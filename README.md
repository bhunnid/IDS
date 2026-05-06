# Ulinzi — Lightweight Host Intrusion Detection System (HIDS)

A Python-based HIDS that monitors live host activity, learns a statistical
baseline of normal behaviour, and detects anomalies in real time.

## Monitors

| Layer   | Source                      | Detects                                      |
|---------|-----------------------------|----------------------------------------------|
| Host    | `/var/log/auth.log`         | Brute-force login, privilege escalation      |
| Host    | psutil process list         | Abnormal process spawn rates                 |
| Host    | SHA-256 file hashing        | Unauthorised modification of critical files  |
| Network | AF_PACKET raw socket        | SYN/UDP/ICMP floods, port scanning           |

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
# Terminal 1 — start the web dashboard (no root needed)
python3 app.py

# Terminal 2 — start the HIDS engine (root required for raw socket + auth log)
sudo python3 hids_main.py
```

Or use the dashboard at http://localhost:5000 to start/stop the engine.

## Attack Simulation

```bash
# Brute-force login
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1

# Port scan
sudo nmap -sS -p 1-1000 --min-rate 500 <target-ip>

# SYN flood
sudo hping3 -S --flood -V -p 80 <target-ip>

# UDP flood
sudo hping3 --udp --flood -p 53 <target-ip>

# ICMP flood
sudo hping3 --icmp --flood <target-ip>

# File tamper (restore with: sudo git checkout /etc/hosts)
echo "tampered" | sudo tee -a /etc/hosts
```

## Output

- `alerts.log` — all alerts with timestamps
- `hids.log`   — full operational log (debug + info)
