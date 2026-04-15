This project is a lightweight anomaly-based Intrusion Detection System (IDS) with a web-based control panel built using Flask. It monitors real-time network traffic using Scapy and detects anomalies using an Isolation Forest machine learning model.

The system is designed for small-scale networks and runs locally with minimal resource usage.

- **ids_main.py**
  - Captures live network traffic
  - Extracts statistical features
  - Trains Isolation Forest model
  - Detects anomalies in real time
  - Writes alerts to `alerts.log`

- **app.py (Flask Control Panel)**
  - Starts and stops IDS process
  - Displays system status
  - Streams alerts from log file
  - Provides web-based monitoring interface

---

## Features

- Real-time network traffic monitoring
- Anomaly detection using Isolation Forest
- Lightweight statistical feature extraction
- Web-based start/stop control panel
- Live alert streaming via browser
- Process isolation (IDS runs independently)
- Automatic log tracking

---

## Requirements

- Python 3.8+
- Linux / Windows (Linux recommended for packet capture)

---

## Installation

```bash
git clone <your-repo-url>
cd <project-folder>

pip install -r requirements.txt

Running the System
1. Start Web Control Panel
python app.py

Then open:

http://localhost:5000
2. Start IDS from Web UI

Click:

▶ Start IDS

The system will:

Launch ids_main.py
Begin traffic monitoring
Write alerts to alerts.log
3. Stop IDS

Click:

■ Stop IDS
Direct IDS Execution (Optional)

You can run IDS without the web panel:

python ids_main.py
Configuration

Edit inside ids_main.py:

WINDOW_SECONDS → feature window size
TRAIN_SECONDS → baseline training time
IF_CONTAMINATION → anomaly sensitivity
INTERFACE → network interface (optional)
Alert Format
[YYYY-MM-DD HH:MM:SS] ALERT: Anomaly detected (score=-0.42) | rate=120 pkt/s ...
Logs
alerts.log → security alerts
ids.log → system logs
Testing

Simulate traffic attacks using tools like:

hping3
nping
attack scripts (port scan, SYN flood)

Example:

python attack_simulator.py
Key Technologies
Scapy (packet capture)
Scikit-learn (Isolation Forest)
Flask (web control panel)
NumPy (feature processing)
Safety Note

This system is for educational and research use only. It should not be deployed in production environments without additional hardening.

Author

Final Year Project – Lightweight IDS for Small-Scale Networks