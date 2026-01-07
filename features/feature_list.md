#FEATURES LIST (AI-Based Host Intrusion Detection System)#
**This focuses on process level behavioral anomalies on the host system.**
**Feature list frozen for v1 phase of the system**	
*Authentication, Command line, file system and resource metrics are excluded in this phase*

###1. window_size_sec
*What- Time window over which events are recorded
*WHy- Normalizes behaviour over fixed intervals
*Implementation- 60 seconds


###2. process_spawn_rate
*WHat- Number of processes spawned per time window
*WHy- Malware often causes abnormal process creation bursts
*Indicator- Sudden spikes are suspicious


###3. unique_process_count
*What- Number of distinct processes executed in a window
*Why- High diversity may indicate automated or malicious execution
*Example- Script based attacks spawn many tools


###4. shell_spawn_count
*What- Number of shell processes formed
*Why- Shells are commonly abused by attackers
*Example- cmd.exe, powershell.exe, bash.exe, 


###5. parent_child_anomaly_score
*What- Score representing how unusual a parent-child relationship is 
*Why- Legitimate process follow stable and predictable spawn pattern
*Based on- Parent child rarity and sensitivity of the child process


###6. background_process_ratio
*What- Ratio of background processes to running process
*Why- Malware often hides as background process
*Indicatior- High ratio=Suspicious


###7. orphan_process_count
*What- Number of processes whose parents have been terminated
*Why-  Orphaned process can indicate injected or malicious injection
*Example- Parent exits, child continues freely


###8. long_running_process_count
*What- Number of processes running longer than a defined time period
*Why- Persistence techniques often rely on long living processes
*Indicator- Unexpected persistence indicate suspicious activity
