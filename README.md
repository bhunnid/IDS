# Lightweight Anomaly-Based IDS  *(v2)*

A minimal Python IDS using Scapy + Isolation Forest.
No dashboard, no database, no cloud — just packets and alerts.

---

## What's new in v2

| # | Improvement | Where |
|---|---|---|
| 1 | **Feature normalisation** — StandardScaler removes scale bias | `train.py`, `detect.py` |
| 2 | **Fixed-interval windows** — clock-anchored, no drift | `features.py` |
| 3 | **Alert logging** — every anomaly written to `alerts.log` | `detect.py` |
| 4 | **CPU + memory display** — per-window resource stats | `detect.py` |
| 5 | **Suspicious IP tracking** — top source IPs shown on ALERT | `detect.py` |
| 6 | **Tunable threshold** — `--threshold` flag replaces hard 0.0 | `detect.py`, `run_ids.py` |

---

## Setup

### 1. Install dependencies
```
pip install scapy pandas numpy scikit-learn joblib psutil
```

### 2. Install Npcap (Windows only — required for Scapy raw sockets)
Download: https://npcap.com/#download
Install with default options.

### 3. Run as Administrator
Right-click your terminal → Run as administrator.

---

## Step-by-Step Pipeline

### Step 1 — Capture normal traffic
```
python capture.py --save normal_traffic.csv
```
Let it run for 5-15 minutes during normal activity (browsing, downloads).
Press Ctrl+C when done.

### Step 2 — Extract feature windows
```
python features.py --input normal_traffic.csv --output normal_features.csv
```
Default window = 10 seconds. Use --window 5 for finer granularity.

### Step 3 — Train the model
```
python train.py --input normal_features.csv --model ids_model.pkl
```
Creates two files: ids_model.pkl and scaler.pkl.
The console prints raw feature statistics and flagged training windows.

### Step 4 — Start real-time detection
```
python run_ids.py
```
Or with all options explicit:
```
python run_ids.py --model ids_model.pkl --scaler scaler.pkl --iface "Wi-Fi" --threshold -0.10
```

---

## Console output explained

```
[14:32:05] NORMAL           score=+0.0812  pkts=142  bytes=98432   cpu=1.2%  mem=42.3%
[14:32:15] ALERT: ANOMALY  score=-0.2140  pkts=3201  bytes=4200000  cpu=3.1%  mem=42.5%  top_src=[192.168.1.50(2800), 10.0.0.4(320)]
```

| Field | Meaning |
|---|---|
| score | Isolation Forest decision score. Below threshold = ALERT |
| pkts | Packets seen in this 10-second window |
| bytes | Total bytes in this window |
| cpu / mem | Process resource usage — proves lightweight claim in report |
| top_src | Busiest source IPs in the window (shown on ALERT only) |

---

## Alert log (alerts.log)

Every anomaly is appended to alerts.log:

```
2024-11-12 14:32:15 | ANOMALY | score=-0.2140 | pkts=3201 | bytes=4200000 | top_src_ips=[192.168.1.50(2800pkts)]
```

Use this file for your evaluation section — sort by score to rank severity.

---

## Anomaly threshold tuning

The --threshold flag controls sensitivity. Test all three for your report:

```
python run_ids.py --threshold -0.01   # loose  — catches more, higher false positives
python run_ids.py --threshold -0.10   # default — balanced
python run_ids.py --threshold -0.20   # strict  — only severe anomalies
```

Expected results table for your report:

| Threshold | Normal browsing | Nmap scan | hping3 flood |
|---|---|---|---|
| -0.01 | Some false positives | Detected | Detected |
| -0.10 | Mostly NORMAL | Detected | Detected |
| -0.20 | All NORMAL | May miss slow scan | Detected |

---

## Contamination tuning (train.py)

Controls what fraction of training data is treated as potentially anomalous:

```
python train.py --input normal_features.csv --contamination 0.01  # strict
python train.py --input normal_features.csv --contamination 0.05  # default
python train.py --input normal_features.csv --contamination 0.10  # permissive
```

| Value | Effect |
|---|---|
| 0.01 | Tight boundary — few false positives |
| 0.05 | Balanced default |
| 0.10 | Wider boundary — higher recall, more noise |

---

## Testing with Kali Linux

| Scenario | Command on Kali | Expected IDS result |
|---|---|---|
| Normal browsing | — | Mostly NORMAL |
| Port scan | nmap -sS target_ip | ALERT spikes (TCP count / unique IPs) |
| SYN flood | hping3 -S --flood target_ip | Continuous ALERT (extreme packet count) |
| ICMP flood | hping3 --icmp --flood target_ip | ALERT (icmp_count spike) |

---

## Data Flow

```
capture.py → packet_queue → features.py → detect.py → console + alerts.log
                  |
             CSV (optional)
                  |
           features.py → train.py → ids_model.pkl + scaler.pkl
```

---

## Files

| File | Purpose |
|---|---|
| capture.py | Live packet capture, shared queue + optional CSV export |
| features.py | Fixed-interval time-window feature extraction |
| train.py | Isolation Forest + StandardScaler training |
| detect.py | Real-time inference, logging, IP tracking, resource stats |
| run_ids.py | One-command pipeline launcher |
| ids_model.pkl | (generated) Trained Isolation Forest |
| scaler.pkl | (generated) Fitted StandardScaler |
| alerts.log | (generated) Append-only anomaly event log |
