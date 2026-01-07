# AI-Based Host Intrusion Detection System (HIDS)

## 📌 Project Overview
This project aims to build a **Host-Based Intrusion Detection System (HIDS)** that monitors system activity and detects suspicious or anomalous behavior on a single machine.

The system is **feature-driven**, with the design focused on extracting meaningful behavioral signals from logs, processes, commands, and resource usage.  
An AI/ML component will be integrated on top of these features at a later stage.

---

## 🎯 Objectives
- Monitor host-level activity in real time or near-real time
- Detect abnormal behavior such as brute-force logins, shell abuse, or suspicious command execution
- Provide an explainable and extensible detection framework
- Serve as a foundation for AI-based anomaly detection

---

## 🧠 Detection Approach
The system follows a **two-layer design**:

1. **Feature Extraction Layer**
   - Aggregates system behavior over fixed time windows
   - Produces structured feature vectors

2. **Detection Layer**
   - Initial version: rule-based anomaly detection
   - Future version: AI/ML-based anomaly detection (handled separately)

---

## 🧩 Feature Set (v1)
The initial version uses a **minimal, high-signal feature set** to avoid noise and overfitting.

Examples include:
- Authentication behavior (failed/successful logins)
- Shell and process spawning behavior
- Command execution characteristics
- System resource usage patterns

📄 The complete and frozen feature list is documented in `features.md`.

---


---

## 🚧 Project Status
**Design Freeze – v1**

- Feature list finalized
- Implementation paused until full team coordination
- Data collection and AI model development will begin in the next phase

---

## 🔮 Future Work
- Implement log and process data collectors
- Complete feature extraction pipeline
- Add rule-based detection engine
- Integrate ML models for anomaly detection
- Evaluate system against simulated attack scenarios

---

## 👥 Team
- Feature design & system architecture: *Current contributor*
- Data collection & AI/ML modeling: *Partner contributor*

---

## ⚠ Disclaimer
This project is developed **strictly for educational and defensive security purposes**.  
No offensive or unauthorized activity is intended or supported.

---

## 📜 License
This project is intended for academic use. Licensing will be defined in future versions.
