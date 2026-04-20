# Kali Linux IDS — Complete Guide

A lightweight, rule-based Network Intrusion Detection System built for Kali Linux.
Captures live traffic using raw sockets (no Scapy), learns your normal network
baseline, and alerts only on real attacks — SYN floods, UDP floods, ICMP floods,
volumetric DoS, and port scans.

---

## Table of Contents

1. [What's Included](#1-whats-included)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Finding Your Network Interface](#4-finding-your-network-interface)
5. [Running the Web Dashboard](#5-running-the-web-dashboard)
6. [Starting the IDS](#6-starting-the-ids)
7. [The Baseline Phase](#7-the-baseline-phase)
8. [The Detection Phase](#8-the-detection-phase)
9. [Simulating Attacks](#9-simulating-attacks)
10. [Reading Alerts in the Dashboard](#10-reading-alerts-in-the-dashboard)
11. [Reading Alerts from the Log File](#11-reading-alerts-from-the-log-file)
12. [Stopping Everything](#12-stopping-everything)
13. [Running the IDS Without the Dashboard](#13-running-the-ids-without-the-dashboard)
14. [Tuning the IDS](#14-tuning-the-ids)
15. [Troubleshooting](#15-troubleshooting)
16. [Alert Reference](#16-alert-reference)
17. [File Reference](#17-file-reference)

---

## 1. What's Included

```
ids_main.py   — The IDS engine. Captures packets, learns baseline, fires alerts.
app.py        — Flask web dashboard. Start/stop the IDS, view live alerts.
```

Both files go in the same folder. The IDS writes two files while running:

```
alerts.log    — Every alert, one line each. This is what the dashboard reads.
ids.log       — Verbose operational log (per-window stats, debug info).
```

---

## 2. Requirements

| Requirement | Notes |
|---|---|
| Kali Linux (any recent version) | VM or bare metal, both work |
| Python 3.9 or newer | Kali 2022+ ships 3.10, Kali 2021 ships 3.9 |
| Flask | Only external dependency — for the web dashboard |
| Root / sudo | Required for raw packet capture |
| hping3, nmap | Pre-installed on Kali — used to simulate attacks |

Check your Python version:

```bash
python3 --version
```

---

## 3. Installation

**Step 1** — Create a working folder and place both files in it:

```bash
mkdir ~/ids
cd ~/ids
# copy ids_main.py and app.py into this folder
```

**Step 2** — Install Flask (the only thing to install):

```bash
pip3 install flask
```

Verify it worked:

```bash
python3 -c "import flask; print('Flask OK:', flask.__version__)"
```

That's it. `ids_main.py` uses only Python's standard library — no Scapy,
no numpy, no scikit-learn.

---

## 4. Finding Your Network Interface

The IDS auto-detects your interface on startup, but you can verify it first.
This is important in VM environments where interfaces are often named
`ens33`, `enp0s3`, or `eth1` rather than the classic `eth0`.

```bash
ip link show
```

Example output:

```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...        ← this is your interface
```

Or on a VMware Kali VM:

```
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> ...       ← this is your interface
```

Also find your IP address (you'll need it to target yourself in attack simulations):

```bash
ip addr show
# Look for: inet 192.168.x.x — that is your IP
```

**If the IDS picks the wrong interface**, open `ids_main.py` and set line 74:

```python
INTERFACE = "ens33"   # replace with your actual interface name
```

---

## 5. Running the Web Dashboard

Open a terminal and run:

```bash
cd ~/ids
python3 app.py
```

You should see:

```
 * Running on http://0.0.0.0:5000
```

Open your browser and go to:

```
http://localhost:5000
```

The dashboard will load. The status badge shows **STOPPED** — the IDS is not
running yet. The dashboard polls the backend every 5 seconds automatically,
so you never need to manually refresh.

> **Note:** The dashboard itself (`app.py`) does not need root. Only the IDS
> engine (`ids_main.py`) needs root because it opens a raw packet socket.

---

## 6. Starting the IDS

In the browser, click the **▶ Start IDS** button.

The dashboard calls the `/start` endpoint, which launches `ids_main.py` as a
subprocess using `sudo python3`. The status badge immediately changes to
**BASELINE…** with an amber pulsing dot.

You can also watch the IDS log in a terminal while it runs:

```bash
tail -f ~/ids/ids.log
```

You will see output like:

```
2024-11-01 14:30:00  INFO  IDS starting | baseline=60s window=3s multiplier=8x ...
2024-11-01 14:30:00  INFO  Interface candidates: ['ens33', 'eth0', 'enp0s3', ...]
2024-11-01 14:30:00  INFO  Interface selected (bind test passed): ens33
2024-11-01 14:30:00  INFO  Sniffer bound to interface: ens33
2024-11-01 14:30:03  INFO  [BASELINE  57s left]  pkts=  42  total=14/s  syn=0/s  udp=4/s  icmp=0/s
2024-11-01 14:30:06  INFO  [BASELINE  54s left]  pkts=  58  total=19/s  syn=1/s  udp=7/s  icmp=0/s
```

---

## 7. The Baseline Phase

**Duration:** 60 seconds (configurable)

During the baseline phase, the IDS is **learning**, not alerting. It observes
your normal network traffic and records the peak packet rates across 3-second
windows, using the 99th percentile to avoid outliers.

**What the baseline measures:**

| Metric | What it tracks |
|---|---|
| `total_rate` | All packets per second |
| `syn_rate` | TCP SYN packets per second |
| `udp_rate` | UDP packets per second |
| `icmp_rate` | ICMP packets per second |

After 60 seconds, the IDS computes detection thresholds:

```
threshold = max(hard_floor, measured_p99_peak × 8)
```

The multiplier of 8 means traffic must be **8 times higher than your own
measured normal peak** before an alert fires. This is why the IDS avoids
false positives from file downloads, video calls, or backup jobs — they
might spike traffic, but never to 8 times the baseline maximum.

**During baseline you will see the dashboard:**
- Status badge: amber **BASELINE…** with pulsing dot
- Progress bar showing how far through the 60 seconds you are
- Live per-window stats updating every 5 seconds

**Do NOT run any attacks during this phase.** If you do, the baseline will
be inflated and the detection thresholds will be set too high, making the IDS
less sensitive.

**Once baseline completes**, the log shows:

```
2024-11-01 14:31:00  INFO  Baseline complete — observed p99: total=22/s syn=1/s udp=8/s icmp=0/s
2024-11-01 14:31:00  INFO  Detection thresholds set: total=5000/s syn=200/s udp=1000/s icmp=50/s
2024-11-01 14:31:00  INFO  Detection ARMED — watching for attacks.
```

The dashboard status badge changes to **DETECTING** with a steady green dot.

---

## 8. The Detection Phase

The IDS evaluates traffic in 3-second windows. Five rules check every window:

### Rule 1 — SYN Flood

Triggers when:
- SYN packet rate exceeds the threshold **AND**
- More than 70% of TCP packets are SYNs (handshakes not completing)

The second condition is what separates a real SYN flood from a normal server
under heavy load. Legitimate servers complete handshakes; flood tools don't.

### Rule 2 — UDP Flood

Triggers when the UDP packet rate exceeds the threshold.
Normal UDP is DNS, NTP, and mDNS — a combined rate well under 50/s on most LANs.
A UDP flood typically hits hundreds or thousands per second.

### Rule 3 — ICMP Flood

Triggers when the ICMP packet rate exceeds the threshold.
Hard floor is 50 ICMP packets/second regardless of baseline — no normal network
activity generates 50 ICMP pkt/s.

### Rule 4 — Volumetric DoS

Triggers when raw total packet rate exceeds the threshold and no
protocol-specific rule (1–3) has already fired. This catches mixed-protocol
floods that don't fit a single protocol category.

### Rule 5 — Port Scan

Triggers when a single source IP touches 50 or more distinct destination ports
within one 3-second window. Legitimate clients connect to a handful of ports;
scanners touch hundreds.

### Alert suppression

Every rule has two additional safeguards:

- **Confirmation gate:** The rule must trigger in 2 consecutive windows
  (6 seconds) before writing an alert. A single-window spike — e.g. a brief
  broadcast storm or a large file download — is suppressed.

- **Cooldown:** Once a rule fires, it cannot fire again for 60 seconds.
  This means one sustained attack produces one alert, not fifty.

---

## 9. Simulating Attacks

All tools below are pre-installed on Kali Linux. Open a **second terminal**
and run the attack while the IDS is in detection mode. You can target your
own machine or another VM on the same network.

First get your IP:

```bash
ip addr show | grep "inet " | grep -v 127 | awk '{print $2}' | cut -d/ -f1
```

---

### Attack 1 — SYN Flood

Simulates a TCP SYN flood. Sends SYN packets at maximum speed without
completing the three-way handshake.

```bash
sudo hping3 -S --flood -V -p 80 <your-ip>
```

| Flag | Meaning |
|---|---|
| `-S` | Set SYN flag |
| `--flood` | Send as fast as possible |
| `-V` | Verbose output |
| `-p 80` | Target port 80 |

**Expected alert (after ~6 seconds):**

```
[2024-11-01 14:35:06] ALERT: SYN flood | syn=850/s (thr=200) ratio=95% tcp=2550 syn=2423
```

Stop with `Ctrl+C`.

---

### Attack 2 — UDP Flood

Floods the target with UDP packets.

```bash
sudo hping3 --udp --flood -p 53 <your-ip>
```

| Flag | Meaning |
|---|---|
| `--udp` | UDP mode |
| `-p 53` | Target port 53 (DNS) |

**Expected alert:**

```
[2024-11-01 14:36:06] ALERT: UDP flood | udp=1400/s (thr=1000) pkts=4200
```

---

### Attack 3 — ICMP Flood (Ping Flood)

Floods with ICMP echo requests.

```bash
sudo hping3 --icmp --flood <your-ip>
```

Or using the standard ping tool:

```bash
sudo ping -f <your-ip>
```

**Expected alert:**

```
[2024-11-01 14:37:06] ALERT: ICMP flood | icmp=320/s (thr=50) pkts=960
```

---

### Attack 4 — Port Scan

Scans the first 1000 ports at a high rate. The `--min-rate 500` flag forces
nmap to send at least 500 packets per second.

```bash
sudo nmap -sS -p 1-1000 --min-rate 500 <your-ip>
```

| Flag | Meaning |
|---|---|
| `-sS` | TCP SYN scan (stealth scan) |
| `-p 1-1000` | Scan ports 1 through 1000 |
| `--min-rate 500` | Send at least 500 packets/second |

**Expected alert:**

```
[2024-11-01 14:39:06] ALERT: Port scan | src=192.168.1.50 ports=500 (thr=50)
```

---

### Attack 5 — Volumetric DoS (Raw Flood)

Floods with raw TCP packets at maximum speed (no SYN/flag specifics).

```bash
sudo hping3 --flood <your-ip>
```

**Expected alert (if not caught by SYN rule first):**

```
[2024-11-01 14:41:06] ALERT: Volumetric DoS | rate=5200/s (thr=5000) tcp=15600 udp=0 icmp=0
```

---

### How long until the alert appears?

Each rule requires 2 consecutive 3-second windows before firing, so minimum
detection time is 6 seconds after the attack starts. The dashboard polls every
5 seconds, so you may wait up to 11 seconds total before seeing the card appear.

---

## 10. Reading Alerts in the Dashboard

Go to `http://localhost:5000`.

### Alert feed (right panel)

Each alert appears as a colour-coded card:

| Colour | Severity | Alert types |
|---|---|---|
| Red | Critical | SYN flood, UDP flood, ICMP flood, Volumetric DoS |
| Amber | High | Port scan |
| Purple | Medium | Statistical anomaly (generic) |
| Grey | Info | IDS started, armed, stopped |

Each card shows:
- **Type label** (e.g. "SYN Flood")
- **Detail line** with the measured rate, threshold, and packet counts
- **Timestamp** (HH:MM:SS)

### Filter tabs

Use the tabs above the feed to focus on specific severity levels:

- **All** — shows everything including info events
- **Critical** — SYN, UDP, ICMP floods and volumetric DoS only
- **High** — port scans only
- **Medium** — generic anomalies only

### Stat pills (top row)

The four pills show cumulative alert counts since the log was last cleared:

```
Critical: 3    High: 1    Medium: 0    Info: 4
```

### Spark chart

The mini bar chart in the top-right shows alert frequency over the last 2 hours
in 5-minute buckets. Bars are colour-graded: blue for low activity, amber for
medium, red for high.

### Pause button

Click **Pause** to freeze the feed while you read a card. The live dot turns
grey while paused. Click **Resume** to resume auto-updates.

### Clear log

Click **⊘ Clear log** to archive the current `alerts.log` to `alerts.log.bak`
and start fresh. Useful between attack simulations.

---

## 11. Reading Alerts from the Log File

The IDS appends every alert to `alerts.log` in the same folder.

**Watch it live:**

```bash
tail -f ~/ids/alerts.log
```

**View all alerts:**

```bash
cat ~/ids/alerts.log
```

**Filter for attack alerts only (exclude info events):**

```bash
grep -v "IDS started\|IDS stopped\|DETECTION mode" ~/ids/alerts.log
```

**Count alerts by type:**

```bash
grep "SYN flood" ~/ids/alerts.log | wc -l
grep "Port scan" ~/ids/alerts.log | wc -l
grep "UDP flood" ~/ids/alerts.log | wc -l
grep "ICMP flood" ~/ids/alerts.log | wc -l
```

### Alert format

Every line in `alerts.log` follows this exact format:

```
[YYYY-MM-DD HH:MM:SS] ALERT: <kind> | <detail>
```

Example lines:

```
[2024-11-01 14:30:00] ALERT: IDS started | baseline=60s window=3s multiplier=8x
[2024-11-01 14:31:00] ALERT: IDS entered DETECTION mode | thr_total=5000/s thr_syn=200/s thr_udp=1000/s thr_icmp=50/s
[2024-11-01 14:35:06] ALERT: SYN flood | syn=850/s (thr=200) ratio=95% tcp=2550 syn=2423
[2024-11-01 14:36:06] ALERT: UDP flood | udp=1400/s (thr=1000) pkts=4200
[2024-11-01 14:37:06] ALERT: ICMP flood | icmp=320/s (thr=50) pkts=960
[2024-11-01 14:39:06] ALERT: Port scan | src=192.168.1.50 ports=500 (thr=50)
[2024-11-01 14:41:06] ALERT: Volumetric DoS | rate=5200/s (thr=5000) tcp=15600 udp=0 icmp=0
[2024-11-01 14:50:00] ALERT: IDS stopped | windows=600
```

### Operational log (ids.log)

For detailed per-window statistics and debug info:

```bash
tail -f ~/ids/ids.log
```

This shows every 3-second window, suspect/clear events, cooldown timers, and
the interface binding process. Useful for diagnosing why an attack was or
wasn't detected.

---

## 12. Stopping Everything

**From the dashboard:** Click **■ Stop IDS**. The status badge returns to STOPPED.

**Stop the dashboard server:** Press `Ctrl+C` in the terminal running `app.py`.

**If the IDS is running standalone:** Press `Ctrl+C` in its terminal, or:

```bash
sudo kill $(pgrep -f ids_main.py)
```

The IDS writes a final "IDS stopped" line to `alerts.log` on clean shutdown.

---

## 13. Running the IDS Without the Dashboard

You can run the IDS directly — no Flask needed. You'll see all output in
the terminal and alerts go straight to `alerts.log`.

```bash
cd ~/ids
sudo python3 ids_main.py
```

Live output during baseline:

```
2024-11-01 14:30:00  INFO  IDS starting  |  baseline=60s  window=3s  multiplier=8x  ...
2024-11-01 14:30:00  INFO  Interface candidates: ['ens33', 'eth0', ...]
2024-11-01 14:30:00  INFO  Interface selected (bind test passed): ens33
2024-11-01 14:30:03  INFO  [BASELINE  57s left]  pkts=  42  total=14/s  syn=0/s ...
```

Live output during detection (quiet — only prints windows and alerts):

```
2024-11-01 14:31:00  INFO  Detection ARMED — watching for attacks.
2024-11-01 14:31:03  INFO  [DETECTING]  pkts=  38  total=12/s  syn=0/s ...
2024-11-01 14:35:03  WARNING  >>> ALERT: SYN flood | syn=850/s (thr=200) ...
```

---

## 14. Tuning the IDS

All settings are at the top of `ids_main.py`. Open it in any text editor:

```bash
nano ~/ids/ids_main.py
```

| Setting | Default | Effect |
|---|---|---|
| `INTERFACE` | `None` | Force a specific interface name. Set if auto-detect picks the wrong one. |
| `BASELINE_SECONDS` | `60` | How long to observe normal traffic. Increase on busier networks. |
| `WINDOW_SECONDS` | `3` | Measurement interval. Smaller = faster detection, more CPU. |
| `THRESHOLD_MULTIPLIER` | `8` | How many × above your measured normal peak triggers an alert. Lower = more sensitive. Minimum recommended: 4. |
| `SYN_FLOOR` | `200` | Minimum SYN rate to alert regardless of baseline (packets/s). |
| `UDP_FLOOR` | `1000` | Minimum UDP rate to alert regardless of baseline. |
| `ICMP_FLOOR` | `50` | Minimum ICMP rate to alert regardless of baseline. |
| `TOTAL_FLOOR` | `5000` | Minimum total rate to alert regardless of baseline. |
| `SYN_RATIO_MIN` | `0.70` | Fraction of TCP that must be SYNs for a SYN flood. |
| `PORT_SCAN_THRESHOLD` | `50` | Distinct ports from one IP in one window to trigger a scan alert. |
| `CONFIRM_WINDOWS` | `2` | Consecutive windows required before alerting. Lower = faster, more false positives. |
| `COOLDOWN_SECS` | `60` | Seconds before the same rule can fire again. |

**For a high-traffic network** (office, server with many connections):
```python
BASELINE_SECONDS     = 120   # longer baseline to cover traffic patterns
THRESHOLD_MULTIPLIER = 10    # higher multiplier needed
CONFIRM_WINDOWS      = 3     # require more sustained attack before alerting
```

**For maximum sensitivity** (quiet lab network):
```python
THRESHOLD_MULTIPLIER = 4
CONFIRM_WINDOWS      = 1     # alert on first trigger
COOLDOWN_SECS        = 30
```

**To pin the interface:**
```python
INTERFACE = "ens33"   # your actual interface from `ip link show`
```

---

## 15. Troubleshooting

### "Permission denied" when starting the IDS

The IDS needs a raw socket, which requires root.

```bash
# Run directly with sudo:
sudo python3 ids_main.py

# If using the web dashboard, it starts the IDS with sudo automatically.
# Make sure the user running app.py can sudo without a password, or run
# app.py as root:
sudo python3 app.py
```

### "Cannot bind to interface" error

The IDS is trying to bind to an interface that doesn't exist.

```bash
# See what interfaces actually exist:
ip link show

# Then either:
# Option A — set it in ids_main.py:
# INTERFACE = "ens33"   (replace with your actual interface)

# Option B — let auto-detect work:
# Make sure you're running as root so the bind test can run
```

### Dashboard shows "Script not found"

Both files must be in the same directory. Check:

```bash
ls ~/ids/
# Should show: ids_main.py  app.py
```

### No packets captured (pkts=0 for many windows)

The IDS is running but capturing no traffic.

```bash
# 1. Confirm you're on the right interface:
cat ~/ids/ids.log | grep "Interface selected"

# 2. Generate traffic to confirm capture works:
ping -c 10 8.8.8.8

# 3. If still zero, check the interface is UP:
ip link show ens33   # replace with your interface

# 4. Try forcing the interface:
# Edit ids_main.py: INTERFACE = "ens33"
```

### Attacks not detected

- Confirm the status badge shows **DETECTING** (not BASELINE)
- Run the attack for at least 10–15 seconds
- Check the threshold that was set:
  ```bash
  grep "Detection thresholds set" ~/ids/ids.log
  ```
  If thresholds are very high (e.g. `total=50000/s`), your baseline captured
  some high-traffic period. Stop the IDS, wait for traffic to settle, and restart.
- Lower `THRESHOLD_MULTIPLIER` to 5 or 4 for more sensitivity.

### Dashboard won't open

```bash
# Check Flask is installed:
python3 -c "import flask; print('OK')"

# Check if port 5000 is already in use:
ss -tlnp | grep 5000

# Use a different port:
PORT=8080 python3 app.py
# Then open: http://localhost:8080
```

### Python version errors

```bash
python3 --version
# Must be 3.9 or higher

# On older Kali, upgrade Python or use:
python3.10 app.py
python3.10 ids_main.py
```

---

## 16. Alert Reference

| Kind | Severity | What it means | Typical detail |
|---|---|---|---|
| `SYN flood` | Critical | TCP SYN flood attack. Thousands of connection attempts not completing. | `syn=850/s (thr=200) ratio=95%` |
| `UDP flood` | Critical | UDP packet flood. Bandwidth exhaustion attack. | `udp=1400/s (thr=1000) pkts=4200` |
| `ICMP flood` | Critical | Ping flood or Smurf attack. | `icmp=320/s (thr=50) pkts=960` |
| `Volumetric DoS` | Critical | Raw packet rate flood not matching a specific protocol. | `rate=5200/s (thr=5000)` |
| `Port scan` | High | Single source IP rapidly scanning many ports. | `src=10.0.0.5 ports=500 (thr=50)` |
| `IDS started` | Info | Lifecycle event. IDS process launched. | `baseline=60s window=3s` |
| `IDS entered DETECTION mode` | Info | Baseline complete. Rules are now armed. | `thr_total=5000/s thr_syn=200/s ...` |
| `IDS stopped` | Info | IDS process cleanly shut down. | `windows=600` |

### Reading the detail field

**SYN flood detail:** `syn=850/s (thr=200) ratio=95% tcp=2550 syn=2423`
- `syn=850/s` — measured SYN rate this window
- `thr=200` — the threshold that was exceeded
- `ratio=95%` — 95% of TCP packets were SYNs (normal is under 10%)
- `tcp=2550 syn=2423` — raw counts in the 3-second window

**Port scan detail:** `src=192.168.1.50 ports=500 (thr=50)`
- `src=192.168.1.50` — the scanning IP address
- `ports=500` — number of distinct destination ports touched in 3 seconds
- `thr=50` — the threshold (50 ports)

**DETECTION mode detail:** `thr_total=5000/s thr_syn=200/s thr_udp=1000/s thr_icmp=50/s`
- These are the computed thresholds for this session, derived from your baseline.
- If these seem too high or too low, adjust `THRESHOLD_MULTIPLIER`.

---

## 17. File Reference

```
~/ids/
├── ids_main.py       IDS engine — edit CONFIGURATION section at top to tune
├── app.py            Web dashboard — runs on port 5000
├── alerts.log        Alert output — written by IDS, read by dashboard
├── alerts.log.bak    Previous alerts — created when you click "Clear log"
└── ids.log           Operational log — per-window stats, debug output
```

### API endpoints (app.py)

| Endpoint | Method | Returns |
|---|---|---|
| `/` | GET | Dashboard HTML page |
| `/start` | POST | Starts IDS subprocess, redirects to dashboard |
| `/stop` | POST | Stops IDS subprocess, redirects to dashboard |
| `/clear` | POST | Archives and clears alerts.log |
| `/status` | GET | JSON: `{ running, phase, uptime, pid, baseline_pct }` |
| `/alerts` | GET | JSON: `{ alerts: [...] }` — structured alert objects |
| `/metrics` | GET | JSON: `{ counts: {...}, spark: [...] }` — stats and chart data |

---

*The IDS uses only Python standard library for packet capture.
No Scapy, no numpy, no ML dependencies. Flask is the only package to install.*
