# CN_CP


TRACE-NF
Timeline-Based Reconstruction & Attack Classification Engine for Network Forensics

📌 Project Description

TRACE-NF is a forensic network analysis system that combines machine learning-based attack classification with timeline reconstruction to analyze captured network traffic.

The system is designed to:
Classify network traffic into predefined attack types using a trained ML model.
Extract behavior-based features from PCAP files.
Reconstruct the chronological sequence of suspicious activities.
Provide confidence scores for detected attacks.
Generate a detailed, human-readable forensic report.
Verify evidence integrity using SHA-256 hashing.

Unlike traditional intrusion detection systems that only output attack labels, TRACE-NF provides contextual explanation and timeline-based reconstruction of multi-stage attacks.

🎯 Identified Attack Types

The system classifies the following attack categories using machine learning:

Normal Traffic
Port Scanning
Brute Force Attack
Flooding / DoS-like Attack
Additionally, it detects:
Persistence Behavior (rule-based temporal correlation)

🧠 System Workflow
Phase 1 — Model Training

Uses the CICIDS2017 cleaned dataset (CSV format).
Trains a supervised machine learning model.
Saves the trained classifier for runtime use.

Phase 2 — Forensic Analysis
Accepts a PCAP file as input.
Generates SHA-256 hash for evidence integrity.
Extracts flow-level features from packets.
Applies the trained ML model to predict attack types.
Reconstructs attack timeline from packet timestamps.
Generates a structured forensic report (terminal + PDF).

📂 Minimal File Structure
TRACE-NF/
│
├── extract_features.py      # PCAP → feature extraction
├── train_model.py           # Train ML model using CICIDS dataset
├── analyze_pcap.py          # Full forensic analysis pipeline
│
├── data/
│   ├── cicids2017.csv       # Training dataset
│   └── sample.pcap          # PCAP file for analysis
│
├── model/
│   └── attack_model.pkl     # Trained ML model
│
└── output/
    └── forensic_report.pdf  # Generated forensic report

⚙️ Technologies Used
Python
PyShark (PCAP parsing)
Pandas & NumPy
Scikit-learn (Machine Learning)
SHA-256 hashing (evidence verification)
Report generation (terminal + PDF)

📊 Output Features

The generated forensic report includes:
Evidence integrity verification (SHA-256 hash)
Suspicious entity identification
Attack classification with confidence scores
Multi-attack detection
Timeline reconstruction
Attack evolution stages
Behavioral interpretation
Risk assessment
Human-readable summary