# Ulinzi HIDS v4
## CNS 3104 Final Year Project · Strathmore University
### Brandon Kiplangat · Reg. No. 193310

> **Lightweight, anomaly-based Host Intrusion Detection System for Kali Linux.**
> Detects 11 attack types in real time. Sends push notifications to your phone via ntfy.sh.

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt --break-system-packages
```

### 2. Run (Python)
```bash
sudo python3 app.py
```
Open **http://localhost:5000** in your browser.
Open **http://\<VM-IP\>:5000** from your phone (same Wi-Fi network).

### 3. Build a standalone executable
```bash
python3 build_exe.py
sudo ./dist/ulinzi
```

---

## Detection Rules

### Host-Level Rules (no network capture needed)
| Rule | Name                  | Trigger                                          |
|------|-----------------------|--------------------------------------------------|
| H1   | Brute-force Login     | Auth failure rate > adaptive threshold           |
| H2   | Privilege Escalation  | sudo/su event rate > adaptive threshold          |
| H3   | Process Anomaly       | New process spawn rate > adaptive threshold      |
| H4   | File Integrity        | SHA-256 change on monitored critical files       |
| H5   | Suspicious Process    | Known malicious process name or reverse shell cmd|

### Network-Level Rules (requires sudo / root)
| Rule | Name            | Trigger                                                    |
|------|-----------------|------------------------------------------------------------|
| N1   | SYN Flood       | SYN rate > threshold AND >60% of TCP are SYN               |
| N2   | UDP Flood       | Inbound UDP rate > threshold                               |
| N3   | ICMP Flood      | Inbound ICMP rate > threshold                              |
| N4   | Port Scan       | Single source IP hits ≥ 20 distinct ports in 1 second      |
| N5   | DNS Tunneling   | Abnormally high DNS query rate from single source          |
| N6   | ARP Spoofing    | Gratuitous ARP reply without prior ARP request             |

---

## Push Notifications (ntfy.sh)

### Phone Setup (2 minutes, free, no account)

1. **Install ntfy app on your phone**
   - Android: [Google Play](https://play.google.com/store/apps/details?id=io.heckel.ntfy) or [F-Droid](https://f-droid.org/packages/io.heckel.ntfy/)
   - iOS: [App Store](https://apps.apple.com/app/ntfy/id1625396347)

2. **Choose a unique topic name** (this is your private channel)
   ```
   Example: ulinzi-brandon-kali-2024
   ```
   Use something random — topic names are public by default on ntfy.sh.

3. **Subscribe in the ntfy app**
   - Open app → tap `+` → type your topic name → Subscribe

4. **Configure Ulinzi**
   - Open the dashboard → **Settings** tab
   - Enter your topic name, enable notifications, click Save
   - OR edit `ulinzi.conf` directly:
   ```json
   {
     "ntfy_enabled": true,
     "ntfy_topic": "ulinzi-brandon-kali-2024",
     "ntfy_min_level": "MEDIUM"
   }
   ```

5. **Test it** — click "Test Notification" in the Settings tab. Your phone should buzz within 2 seconds.

### What notifications look like on your phone

```
🔴 HIGH — Brute-force Login
🔑 failures=47 thr=10 top_src=192.168.1.100(47)
⏱ 14:22:01
```

```
🚨 CRITICAL — File Tampered
📄 path=/etc/passwd prev=3a9f1c... new=b72e8d...
⏱ 14:22:10
```

---

## Building the Executable

```bash
# Install PyInstaller
pip install pyinstaller --break-system-packages

# Build
python3 build_exe.py

# Output
dist/
├── ulinzi          ← Standalone executable (~25 MB)
├── ulinzi.conf     ← Configuration file
└── run.sh          ← Launch script
```

### Run the executable
```bash
cd dist/
sudo ./ulinzi                    # full monitoring, port 5000
sudo ./ulinzi --port 8080        # custom port
```

### Deploy system-wide
```bash
sudo cp dist/ulinzi /usr/local/bin/
sudo cp dist/ulinzi.conf /etc/ulinzi.conf
sudo ulinzi   # run from anywhere
```

---

## Dashboard Features

| Feature              | Description                                          |
|----------------------|------------------------------------------------------|
| Alert feed           | Real-time, filterable by level, auto-refreshes 2s    |
| Severity score       | Every alert scored 1-100 based on rule + level       |
| Stat strip           | Live counts by level + host/network split            |
| Spark chart          | Alert rate over last 30 minutes                      |
| Hourly bar chart     | Stacked alert counts for last 24 hours               |
| Attackers table      | Top source IPs, event counts, attack types           |
| Live traffic bars    | SYN/UDP/ICMP/total packet rates                      |
| Monitor status       | Live status of each detection module                 |
| Settings page        | Configure ntfy in-browser without editing files      |
| Test notification    | One-click ntfy test from the dashboard               |

---

## Configuration Reference (`ulinzi.conf`)

| Parameter              | Default          | Description                                 |
|------------------------|------------------|---------------------------------------------|
| `baseline_seconds`     | `60`             | How long to observe normal behavior         |
| `window_seconds`       | `1`              | Detection window size (1s = fast alerts)    |
| `threshold_multiplier` | `3`              | `threshold = p95_baseline × multiplier`     |
| `confirm_windows`      | `2`              | Windows before flood alert fires            |
| `cooldown_secs`        | `30`             | Minimum seconds between repeat alerts       |
| `file_check_interval`  | `5`              | File integrity check frequency (seconds)    |
| `port_scan_threshold`  | `20`             | Distinct ports per source IP to trigger     |
| `dns_query_floor`      | `50`             | DNS queries/sec to trigger tunnel rule      |
| `ntfy_enabled`         | `false`          | Enable push notifications                   |
| `ntfy_topic`           | (must set)       | Your ntfy topic/channel name                |
| `ntfy_min_level`       | `"MEDIUM"`       | Minimum level to push                       |
| `ntfy_token`           | `""`             | ntfy access token (for private topics)      |
| `monitored_files`      | (see config)     | Files to watch for integrity changes        |

---

## Attack Simulation (from attacker Kali VM)

```bash
export TARGET=192.168.x.x  # IP of the machine running Ulinzi

# H1 — Brute force SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 8 -f

# H2 — Privilege escalation (run ON the target)
for i in $(seq 1 30); do sudo ls /root 2>/dev/null; done

# H3 — Process anomaly (run ON the target)
for i in $(seq 1 50); do (sleep 0.1 &); done

# H4 — File integrity (run ON the target)
echo "1.2.3.4 google.com" | sudo tee -a /etc/hosts
sudo sed -i '/1.2.3.4/d' /etc/hosts  # restore

# N1 — SYN flood
sudo hping3 -S --flood -p 80 $TARGET

# N2 — UDP flood
sudo hping3 --udp --flood -p 53 $TARGET

# N3 — ICMP flood
sudo hping3 --icmp --flood $TARGET

# N4 — Port scan
sudo nmap -sS -p 1-1000 --min-rate 500 $TARGET

# N5 — DNS tunnel simulation
for i in $(seq 1 200); do dig @$TARGET google.com &; done
```

---

## File Structure

```
Ulinzi_v4/
├── app.py              Flask dashboard + REST API + SSE
├── hids_engine.py      Detection engine (all 11 rules)
├── build_exe.py        PyInstaller build script
├── ulinzi.conf         Configuration (JSON)
├── requirements.txt    Python dependencies
├── README.md           This file
│
├── (generated at runtime)
├── alerts.log          Plain-text alert log
├── alerts.jsonl        Structured JSON alert log
├── hids.log            Engine operational log
└── ulinzi.db           SQLite database (alerts + attackers)
```

---

## References
- Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems* (NIST SP 800-94).
- Roesch, M. (1999). *Snort: Lightweight Intrusion Detection for Networks.* USENIX LISA '99.
- Behl, A., & Behl, K. (2017). *Cybersecurity and Cyberwar.* Oxford University Press.
