# Ulinzi: Lightweight Anomaly-Based IDS for Small Networks

Ulinzi is a Python-based intrusion detection system that monitors live network traffic, learns a baseline of normal activity, and detects anomalies such as floods and port scans in real time.

---

## Quick Start

```bash
mkdir ~/ids && cd ~/ids

# add ids_main.py and app.py

pip3 install flask

python3 app.py

Open in browser:

http://localhost:5000

Click Start IDS.

Requirements
Kali Linux
Python 3.9+
Flask (pip3 install flask)
Root privileges (for packet capture)
Tools: hping3, nmap
Network Setup

Check interface:

ip link show

Check IP address:

ip addr show | grep "inet " | grep -v 127

If needed, set manually in ids_main.py:

INTERFACE = "ens33"
Operation
1. Baseline Phase (Automatic)
Duration: 60 seconds
Learns normal traffic rates
Do not run attacks during this phase
2. Detection Phase
Starts automatically after baseline
System begins monitoring for anomalies
Attack Simulation

Run from a second terminal using your own IP.

SYN Flood
sudo hping3 -S --flood -p 80 <your-ip>
UDP Flood
sudo hping3 --udp --flood -p 53 <your-ip>
ICMP Flood
sudo hping3 --icmp --flood <your-ip>
Port Scan
sudo nmap -sS -p 1-1000 --min-rate 500 <your-ip>
Volumetric DoS
sudo hping3 --flood <your-ip>
Detection Timing
Requires 2 consecutive windows (~6 seconds)
Dashboard refresh interval: ~5 seconds
Expected alert delay: 6–11 seconds
Logs
Alerts
tail -f ~/ids/alerts.log
Debug / Traffic Stats
tail -f ~/ids/ids.log
Thresholds (Default)
Type	Threshold
SYN flood	500 pkt/s
UDP flood	2000 pkt/s
ICMP flood	200 pkt/s
Total traffic	3000 pkt/s
Port scan	50 ports / 3s
Configuration

Edit in ids_main.py:

BASELINE_SECONDS
THRESHOLD_MULTIPLIER
*_FLOOR values
PORT_SCAN_THRESHOLD
CONFIRM_WINDOWS
COOLDOWN_SECS
Running Without Dashboard
sudo python3 ids_main.py
Stopping
sudo kill $(pgrep -f ids_main.py)
Common Issues
Permission denied
sudo python3 ids_main.py
No packets captured
Wrong interface → set INTERFACE manually
Wrong phase / stuck state
rm ~/ids/alerts.log
Port already in use
PORT=8080 python3 app.py
Notes
Designed for small networks and lab environments
Uses statistical anomaly detection (no machine learning)
Focused on low overhead and simplicity