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

## Features

- Real-time network traffic monitoring
- Anomaly detection using Isolation Forest
- Lightweight statistical feature extraction
- Web-based start/stop control panel
- Live alert streaming via browser
- Process isolation (IDS runs independently)
- Automatic log tracking

This system is for educational and research use only. It should not be deployed in production environments without additional hardening.

- Brandon
