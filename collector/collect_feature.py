import os
import json
import time
import psutil
import getpass
from datetime import datetime

DATA_DIR = "/home/eyerin/projects/ai-nids/data/raw"
os.makedirs(DATA_DIR, exist_ok=True)

def collect_features(window_size_sec=60):

    try:
        start_procs = list(psutil.process_iter(['pid', 'name', 'username', 'ppid', 'create_time']))
    except Exception as e:
        print(f"[ERROR] Failed to read start processes: {e}")
        return None

    time.sleep(window_size_sec)

    try:
        end_procs = list(psutil.process_iter(['pid', 'name', 'username', 'ppid', 'create_time']))
    except Exception as e:
        print(f"[ERROR] Failed to read end processes: {e}")
        return None

    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = "unknown"

    start_pids = set(p.info['pid'] for p in start_procs)
    end_pids   = set(p.info['pid'] for p in end_procs)
    spawned_pids = end_pids - start_pids

    shell_names = ("bash", "sh", "zsh")
    shell_spawns = sum(
        1 for p in end_procs
        if p.info['pid'] in spawned_pids and any(s in p.info['name'] for s in shell_names)
    )

    try:
        features = {
            "window_size_sec": window_size_sec,
            "process_spawn_rate": len(spawned_pids),
            "unique_process_count": len(set(p.info['name'] for p in end_procs)),
            "shell_spawn_count": shell_spawns,
            "parent_child_anomaly_score": 0.0,
            "background_process_ratio": sum(
                1 for p in end_procs if p.info.get('username') != current_user
            ) / max(len(end_procs), 1),
            "orphan_process_count": sum(1 for p in end_procs if p.info['ppid'] == 1),
            "long_running_process_count": sum(
                1 for p in end_procs if time.time() - p.info['create_time'] > 3600
            ),
        }
    except Exception as e:
        print(f"[ERROR] Failed to compute features: {e}")
        return None

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    file_path = os.path.join(DATA_DIR, f"host_{timestamp}.json")

    try:
        with open(file_path, "w") as f:
            json.dump(features, f, indent=4)
        print(f"[+] Saved: {file_path}")
    except Exception as e:
        print(f"[ERROR] Failed to write file: {e}")
        return None

    return file_path


if __name__ == "__main__":
    print("[*] Collector started for 300 cycles...")

    for i in range(300):
        print(f"[*] Cycle {i+1}/300...")
        collect_features(60)

    print("[✓] Completed 300 snapshots. Exiting.")

