# Kali Linux IDS — Complete Guide

A rule-based Network Intrusion Detection System built for Kali Linux.
Captures live traffic using raw sockets (no Scapy, no external dependencies),
learns your normal baseline, then alerts only on real attacks.

---

## Files

```
ids_main.py   IDS engine — captures packets, learns baseline, writes alerts
app.py        Flask web dashboard — start/stop IDS, view live alerts
alerts.log    Written by IDS — one alert per line (created automatically)
ids.log       Verbose operational log — per-window stats, debug info
```

Both files go in the same folder.

---

## Requirements

| Item | Notes |
|---|---|
| Kali Linux (any recent version) | VM or bare metal |
| Python 3.9 or newer | `python3 --version` to check |
| Flask | Only external dependency |
| Root / sudo | Raw packet capture needs it |
| hping3, nmap | Pre-installed on Kali |

---

## Installation

```bash
# 1. Create a folder and copy both files into it
mkdir ~/ids
cd ~/ids
# place ids_main.py and app.py here

# 2. Install Flask — the only thing to install
pip3 install flask

# 3. Verify
python3 -c "import flask; print('Flask OK')"
```

---

## Step 1 — Find your network interface

The IDS auto-detects, but confirm the name first:

```bash
ip link show
```

Look for your interface — on Kali VMs it is commonly `ens33`, `eth0`, or `enp0s3`:

```
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

Also get your IP address (needed to target attacks at yourself):

```bash
ip addr show | grep "inet " | grep -v 127
# Example output:  inet 192.168.1.100/24
```

If the IDS picks the wrong interface on startup, open `ids_main.py` and set line 56:

```python
INTERFACE = "ens33"   # replace with your actual interface name
```

---

## Step 2 — Start the web dashboard

Open a terminal and run:

```bash
cd ~/ids
python3 app.py
```

Open your browser:

```
http://localhost:5000
```

The dashboard loads with status **STOPPED**. The dashboard does not need root —
only the IDS engine needs root because it opens a raw socket.

---

## Step 3 — Start the IDS

Click **▶ Start IDS** in the browser.

The dashboard launches `ids_main.py` with `sudo`. The status badge changes to
**BASELINE...** with an amber pulsing dot. A progress bar shows how far through
the 60-second baseline you are.

To watch the IDS output live, open a second terminal:

```bash
tail -f ~/ids/ids.log
```

You will see:

```
2024-11-01 14:30:00  INFO  IDS starting  |  baseline=60s  window=3s ...
2024-11-01 14:30:00  INFO  Hard floors   |  syn=500/s  udp=2000/s  icmp=200/s  total=3000/s
2024-11-01 14:30:00  INFO  Interface selected (bind OK): ens33
2024-11-01 14:30:03  INFO  [BASELINE  57s left]  pkts=  18  total=6.0/s ...
2024-11-01 14:30:06  INFO  [BASELINE  54s left]  pkts=  22  total=7.3/s ...
```

---

## Step 4 — Wait for baseline to complete

**Do not run any attacks yet.** The IDS is learning what your normal traffic looks like.

After 60 seconds the log shows:

```
2024-11-01 14:31:00  INFO  Baseline complete — p99 peaks: total=6.2/s syn=0.1/s udp=2.1/s icmp=0.0/s
2024-11-01 14:31:00  INFO  Detection thresholds: total=3000/s  syn=500/s  udp=2000/s  icmp=200/s
2024-11-01 14:31:00  INFO  Detection ARMED — watching for attacks.
```

The dashboard badge changes to **DETECTING** with a steady green dot and the
progress bar disappears.

Note the thresholds. On an idle VM (~6 pkt/s baseline) the hard floors dominate:

- SYN flood requires sustained **500+ SYN packets/second**
- UDP flood requires **2000+ UDP packets/second**
- ICMP flood requires **200+ ICMP packets/second**
- Volumetric DoS requires **3000+ total packets/second**

These are numbers only hping3 / nmap actually reach. Normal background traffic
(DNS, ARP, mDNS, NTP) at 6 pkt/s never gets close.

---

## Step 5 — Simulate attacks

Open a **second terminal**. Use your own IP as the target.

### SYN Flood

```bash
sudo hping3 -S --flood -V -p 80 <your-ip>
```

Sends thousands of TCP SYN packets per second without completing handshakes.
Stop with `Ctrl+C`.

**Expected alert after ~6 seconds:**
```
[2024-11-01 14:35:06] ALERT: SYN flood | syn=4800/s (thr=500) ratio=96% tcp=14400 syn=13824
```

---

### UDP Flood

```bash
sudo hping3 --udp --flood -p 53 <your-ip>
```

**Expected alert:**
```
[2024-11-01 14:36:06] ALERT: UDP flood | udp=7500/s (thr=2000) pkts=22500
```

---

### ICMP Flood

```bash
sudo hping3 --icmp --flood <your-ip>
```

Or using standard ping:

```bash
sudo ping -f <your-ip>
```

**Expected alert:**
```
[2024-11-01 14:37:06] ALERT: ICMP flood | icmp=4900/s (thr=200) pkts=14700
```

---

### Port Scan

```bash
sudo nmap -sS -p 1-1000 --min-rate 500 <your-ip>
```

Scans 1000 ports rapidly from a single source IP. The IDS triggers when one IP
touches 50 or more distinct destination ports within a single 3-second window.

**Expected alert:**
```
[2024-11-01 14:39:06] ALERT: Port scan | src=192.168.1.50 ports=500 (thr=50)
```

---

### Volumetric DoS

```bash
sudo hping3 --flood <your-ip>
```

**Expected alert:**
```
[2024-11-01 14:41:06] ALERT: Volumetric DoS | rate=3500/s (thr=3000) tcp=10500 udp=0 icmp=0
```

---

### How long until the alert appears?

Each rule requires 2 consecutive 3-second windows before firing, so minimum
detection time from attack start is **6 seconds**. The dashboard polls every
5 seconds, so you may wait up to **~11 seconds** before seeing the card appear.

---

## Step 6 — Review alerts in the dashboard

Go to `http://localhost:5000`.

Alert cards in the right panel are colour-coded:

| Colour | Severity | Alert types |
|---|---|---|
| Red | Critical | SYN flood, UDP flood, ICMP flood, Volumetric DoS |
| Amber | High | Port scan |
| Grey | Info | IDS started, armed, stopped |

Each card shows the alert type, the detail line (measured rate vs threshold),
and the timestamp.

**Filter tabs** above the feed let you focus on Critical, High, or Medium.

**Stat pills** at the top show cumulative counts since the log was last cleared.

**Spark chart** shows alert frequency over the last 2 hours in 5-minute buckets.

**Pause** freezes the feed while you read. **Resume** restarts auto-updates.

**Clear log** archives `alerts.log` to `alerts.log.bak` and starts fresh.

---

## Step 7 — Review alerts in the log file

```bash
# Watch live
tail -f ~/ids/alerts.log

# Attack alerts only (skip lifecycle events)
grep -v "IDS started\|IDS stopped\|DETECTION mode" ~/ids/alerts.log

# Count by type
grep "SYN flood"  ~/ids/alerts.log | wc -l
grep "UDP flood"  ~/ids/alerts.log | wc -l
grep "ICMP flood" ~/ids/alerts.log | wc -l
grep "Port scan"  ~/ids/alerts.log | wc -l
```

Every line follows this format:

```
[YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>
```

Full example session:

```
[2024-11-01 14:30:00] ALERT: IDS started | baseline=60s window=3s multiplier=4x floors: syn=500 udp=2000 icmp=200 total=3000
[2024-11-01 14:31:00] ALERT: IDS entered DETECTION mode | thr_total=3000/s thr_syn=500/s thr_udp=2000/s thr_icmp=200/s
[2024-11-01 14:35:06] ALERT: SYN flood | syn=4800/s (thr=500) ratio=96% tcp=14400 syn=13824
[2024-11-01 14:36:06] ALERT: UDP flood | udp=7500/s (thr=2000) pkts=22500
[2024-11-01 14:37:06] ALERT: ICMP flood | icmp=4900/s (thr=200) pkts=14700
[2024-11-01 14:39:06] ALERT: Port scan | src=192.168.1.50 ports=500 (thr=50)
[2024-11-01 14:50:00] ALERT: IDS stopped | windows=600
```

For per-window rates and debug info:

```bash
tail -f ~/ids/ids.log
```

---

## Stopping

**From the dashboard:** Click **Stop IDS**, then `Ctrl+C` in the `app.py` terminal.

**From the terminal:**

```bash
sudo kill $(pgrep -f ids_main.py)
```

---

## Running the IDS standalone (no dashboard)

```bash
cd ~/ids
sudo python3 ids_main.py
```

Alerts still go to `alerts.log`. All output prints to the terminal.

---

## Tuning

Edit the `CONFIGURATION` section at the top of `ids_main.py`:

| Setting | Default | Effect |
|---|---|---|
| `INTERFACE` | `None` | Force a specific interface. Set if auto-detect is wrong. |
| `BASELINE_SECONDS` | `60` | Seconds of normal traffic to observe. |
| `THRESHOLD_MULTIPLIER` | `4` | Adaptive threshold = p99_peak x this. Hard floors win on idle VMs. |
| `SYN_FLOOR` | `500` | Minimum SYN rate (pkt/s) for a flood alert. |
| `UDP_FLOOR` | `2000` | Minimum UDP rate (pkt/s) for a flood alert. |
| `ICMP_FLOOR` | `200` | Minimum ICMP rate (pkt/s) for a flood alert. |
| `TOTAL_FLOOR` | `3000` | Minimum total pkt/s for a volumetric DoS alert. |
| `PORT_SCAN_THRESHOLD` | `50` | Distinct dst ports from one IP in one 3-second window. |
| `CONFIRM_WINDOWS` | `2` | Consecutive windows required (2 x 3s = 6s sustained). |
| `COOLDOWN_SECS` | `60` | Seconds before the same rule can fire again. |

---

## Troubleshooting

**"Permission denied" when starting IDS**

```bash
# Run directly with sudo
sudo python3 ids_main.py

# Or run the whole dashboard as root
sudo python3 app.py
```

**"Cannot bind to interface" error**

```bash
ip link show   # find the real interface name
# Then set it in ids_main.py:
# INTERFACE = "ens33"
```

**No packets captured (pkts=0)**

```bash
# Check which interface was chosen
grep "Interface selected" ~/ids/ids.log

# Generate some traffic to test
ping -c 10 8.8.8.8

# If still nothing, force the correct interface in ids_main.py
```

**Dashboard shows wrong phase / progress bar disappears immediately**

This happens when `alerts.log` from a previous run already contains
"DETECTION mode". The phase is read from the log, so it jumps straight to
detecting. Clear the old log first:

```bash
rm ~/ids/alerts.log
```

Then restart the IDS from the dashboard.

**Attacks not detected**

Check what thresholds were set:

```bash
grep "Detection thresholds" ~/ids/ids.log
```

The SYN threshold should be 500, UDP should be 2000, ICMP should be 200.
Run the attack for at least 15 seconds and watch `ids.log` to confirm windows
are being processed during the attack.

**Port 5000 already in use**

```bash
PORT=8080 python3 app.py
# Open: http://localhost:8080
```
