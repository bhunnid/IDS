# IDS on Kali Linux — Complete Instructions
## From installation to attack simulation to reading alerts

---

## WHAT YOU NEED

- Kali Linux VM (any recent version)
- Python 3.10+ (already on Kali)
- Flask (`pip3 install flask`)
- A second machine or the same machine to simulate attacks from
- Root / sudo access (required for raw packet capture)

---

## STEP 1 — Install the only dependency

```bash
pip3 install flask
```

That is the only thing to install. `ids_main.py` uses Python's built-in
`socket` and `struct` modules — no Scapy, no numpy, no scikit-learn.

---

## STEP 2 — Place both files in the same folder

```
/home/kali/ids/
    ids_main.py
    app.py
```

```bash
mkdir -p ~/ids
# copy ids_main.py and app.py into ~/ids/
cd ~/ids
```

---

## STEP 3 — Start the web dashboard

Open a terminal and run:

```bash
cd ~/ids
python3 app.py
```

Open your browser and go to:

```
http://localhost:5000
```

You will see the IDS Console dashboard. The IDS is NOT running yet —
you will see **STOPPED** in the status badge.

---

## STEP 4 — Start the IDS from the dashboard

1. In the browser, click **▶ Start IDS**
2. The status badge changes to **BASELINE…** with an amber pulsing dot
3. A progress bar shows how far through the 60-second baseline you are
4. The terminal running `app.py` will show nothing (IDS logs go to `ids.log`)

**Important:** During the baseline phase the IDS is learning what your
normal network traffic looks like. Do NOT run any attacks during this time.
Just let normal traffic flow — browse a website, let background apps run.

---

## STEP 5 — Watch the IDS arm itself

After 60 seconds, the dashboard automatically updates:

- Status badge changes to **DETECTING** with a green glowing dot
- The baseline progress bar disappears
- The terminal running `ids_main.py` (visible in `ids.log`) shows the
  computed thresholds, e.g.:
  ```
  Baseline done. Thresholds → total=5000/s  syn=200/s  udp=1000/s  icmp=50/s
  ```

The IDS is now armed. You can see what it detected in `alerts.log`:
```bash
cat ~/ids/alerts.log
```

---

## STEP 6 — Simulate attacks (from Kali, targeting yourself or another VM)

**Find your IP address first:**
```bash
ip addr show
# Look for inet x.x.x.x — that is your IP
# Example: 192.168.1.100
```

All attack tools below are pre-installed on Kali Linux.

---

### Attack 1 — SYN Flood (detects as: SYN flood)

Opens thousands of TCP connections without completing the handshake.

```bash
sudo hping3 -S --flood -V -p 80 192.168.1.100
```

- `-S` = SYN flag only
- `--flood` = send as fast as possible
- `-p 80` = target port 80

**Expected alert after ~6 seconds:**
```
[2024-11-01 14:35:01] ALERT: SYN flood | syn=850/s (threshold=200/s) ratio=95%
```

Stop the attack: `Ctrl+C`

---

### Attack 2 — UDP Flood (detects as: UDP flood)

Floods the target with UDP packets.

```bash
sudo hping3 --udp --flood -p 53 192.168.1.100
```

- `--udp` = UDP mode
- `-p 53` = targeting DNS port

**Expected alert:**
```
[2024-11-01 14:36:10] ALERT: UDP flood | udp=1200/s (threshold=1000/s)
```

---

### Attack 3 — ICMP Flood / Ping Flood (detects as: ICMP flood)

Floods with ICMP echo requests.

```bash
sudo hping3 --icmp --flood 192.168.1.100
```

Or using the standard ping flood:
```bash
sudo ping -f 192.168.1.100
```

**Expected alert:**
```
[2024-11-01 14:37:15] ALERT: ICMP flood | icmp=300/s (threshold=50/s)
```

---

### Attack 4 — Port Scan (detects as: Port scan)

Scans hundreds of ports rapidly from one source IP.

```bash
sudo nmap -sS -p 1-1000 --min-rate 500 192.168.1.100
```

- `-sS` = SYN scan (stealth)
- `--min-rate 500` = at least 500 packets/s

**Expected alert:**
```
[2024-11-01 14:39:25] ALERT: Port scan | src=192.168.1.50 ports=500 (threshold=50)
```

---

### Attack 5 — Volumetric DoS (detects as: Volumetric DoS)

Raw packet flood not matching a specific protocol rule.

```bash
sudo hping3 --flood 192.168.1.100
```

---

## STEP 7 — Watch alerts appear in the dashboard

After starting an attack:

1. Go back to `http://localhost:5000`
2. The dashboard **polls every 5 seconds** automatically — just wait
3. You will see alert cards appear in the right panel:
   - **Red** cards = Critical (SYN flood, UDP flood, ICMP flood, Vol. DoS)
   - **Amber** cards = High (Port scan)
4. The **Critical** and **High** counters in the top row increment
5. The spark chart (top right) shows the alert frequency over time

You can also use the **filter tabs** (Critical / High / Medium) to focus
on specific alert types, and click **Pause** to freeze the feed while reading.

---

## STEP 8 — Read the raw alert log

```bash
tail -f ~/ids/alerts.log
```

Example output after attacks:

```
[2024-11-01 14:30:00] ALERT: IDS started | baseline=60s window=3s multiplier=8x
[2024-11-01 14:31:00] ALERT: IDS entered DETECTION mode | thr_total=5000/s thr_syn=200/s ...
[2024-11-01 14:35:01] ALERT: SYN flood | syn=850/s (threshold=200/s) ratio=95% tcp=2550 syn=2423
[2024-11-01 14:36:10] ALERT: UDP flood | udp=1200/s (threshold=1000/s) pkts=3600
[2024-11-01 14:37:15] ALERT: ICMP flood | icmp=300/s (threshold=50/s) pkts=900
[2024-11-01 14:39:25] ALERT: Port scan | src=192.168.1.50 ports=500 (threshold=50)
```

For the debug log (per-window stats, suspect/clear/cooldown events):
```bash
tail -f ~/ids/ids.log
```

---

## STEP 9 — Clear alerts and re-run

Click **⊘ Clear log** in the dashboard to archive the current log and start fresh.
This saves the old log as `alerts.log.bak`.

Or manually:
```bash
mv ~/ids/alerts.log ~/ids/alerts.log.bak
```

---

## STOPPING EVERYTHING

In the dashboard: click **■ Stop IDS**
Then stop the Flask server: `Ctrl+C` in the terminal running `app.py`

---

## RUNNING IDS DIRECTLY (without the web panel)

If you want to run the IDS standalone and just watch stdout:

```bash
cd ~/ids
sudo python3 ids_main.py
```

You will see live output like:
```
2024-11-01 14:30:00  INFO  IDS starting | baseline=60s window=3s ...
2024-11-01 14:30:03  INFO  [BASELINE  57s left]  pkts=  45  total=15/s  syn=0/s  ...
2024-11-01 14:30:06  INFO  [BASELINE  54s left]  pkts=  62  total=20/s  syn=1/s  ...
...
2024-11-01 14:31:00  INFO  Baseline done. Thresholds → total=5000/s syn=200/s ...
2024-11-01 14:31:00  INFO  Detection ARMED. Monitoring for attacks.
2024-11-01 14:31:03  INFO  [DETECTING]  pkts=  38  total=12/s  syn=0/s  udp=5/s ...
```

When an attack starts:
```
2024-11-01 14:35:01  WARNING  >>> ALERT: SYN flood | syn=850/s (threshold=200/s) ...
```

---

## ADJUSTING SENSITIVITY

Edit `ids_main.py` at the top (CONFIGURATION section):

| Setting | Default | Effect |
|---|---|---|
| `BASELINE_SECONDS` | 60 | How long to learn normal traffic. Increase for busy networks. |
| `THRESHOLD_MULTIPLIER` | 8 | How many × above your normal peak triggers an alert. Lower = more sensitive. |
| `CONFIRM_WINDOWS` | 2 | How many consecutive 3-second windows before alerting. Lower = faster. |
| `COOLDOWN_SECS` | 60 | Seconds before the same rule can fire again. |
| `PORT_SCAN_THRESHOLD` | 50 | Distinct ports from one IP in 3 seconds to trigger a port scan alert. |

---

## TROUBLESHOOTING

**"Permission denied" when starting IDS**
The IDS needs raw socket access. Use sudo in the terminal, or run the whole
panel as root: `sudo python3 app.py`

**"Script not found" in the dashboard**
Both files must be in the same directory. Check with `ls ~/ids/`

**IDS starts but no traffic is captured**
Your interface name may be different. Edit `INTERFACE` at the top of
`ids_main.py`:
```python
INTERFACE = "eth0"   # or "ens33", "wlan0", etc.
```
Find yours with: `ip link show`

**Attacks not detected**
- Make sure the baseline phase is complete (status shows DETECTING, not BASELINE)
- Run the attack for at least 10 seconds (2 windows × 3s + confirmation time)
- Check `ids.log` to see per-window stats and confirm traffic is being captured

**Dashboard shows stale data**
It polls every 5 seconds. Wait a few seconds, or click the browser refresh.
