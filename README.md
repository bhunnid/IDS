# Lightweight Anomaly-Based IDS — v3

A minimal Python IDS: Scapy capture → feature extraction → Isolation Forest → alerts.
No dashboard. No database. No cloud. Runs on Windows with a single terminal.

---

## Architecture

The v3 rebuild fixes three root causes of crashes in v2:

### Problem 1 — Circular imports
`detect.py` imported `from capture import packet_queue`.
`capture.py` owned a module-level Queue.
When `detect.py` also patched `capture.on_packet` at runtime, any
import ordering issue (common on Windows) caused silent failures or
attribute errors.

**Fix:** A new `pipeline.py` owns the Queue and nothing else.
Every module that needs the Queue does `from pipeline import PACKET_QUEUE`.
No module imports another IDS module directly except through `pipeline.py`.

### Problem 2 — Monkey-patching
`detect.py` replaced `capture.on_packet` at runtime to add IP tracking.
This broke CSV writing (the original writer closure was silently abandoned)
and was fragile under any import reordering.

**Fix:** IP tracking now lives inside `features.py`'s `live_windows()` generator.
Every yielded feature dict includes a `top_src_ips` key computed from the
window's own packet buffer. No patching, no shared mutable state.

### Problem 3 — Thread-unsafe shared list
`_recent_packets` was a plain list mutated from the sniff thread and read
from the main thread — a guaranteed race condition.

**Fix:** Removed entirely. The packet buffer inside `live_windows()` is a
local variable — only one thread (the main loop) ever touches it.

### Clean data flow

```
sniff()
  └─ prn=callback            (capture.py — daemon thread)
       └─ PACKET_QUEUE.put() (pipeline.py — thread-safe Queue)
            └─ live_windows() drains queue, builds windows
                 └─ packets_to_features() computes 8 features + top IPs
                      └─ predict() scales + classifies
                           └─ print_window() + log_alert()
```

### Import graph (no cycles)

```
pipeline.py       (no IDS imports)
capture.py    ←── pipeline
features.py   ←── pipeline
train.py      ←── features  (FEATURE_COLS only)
detect.py     ←── capture, features  (NOT pipeline directly)
run_ids.py    ←── detect, capture, features, train  (lazy imports per command)
```

---

## Setup

```
pip install scapy pandas numpy scikit-learn joblib psutil
```

On Windows, also install **Npcap**: https://npcap.com/#download
Run your terminal as **Administrator** (required for raw socket access).

---

## Full Pipeline

### Step 1 — Capture normal traffic
```
python run_ids.py capture --save normal.csv
```
Let it run for 5–15 minutes of normal browsing / downloads.
Press **Ctrl+C** when done.

### Step 2 — Extract feature windows
```
python run_ids.py features --input normal.csv --output normal_features.csv
```

### Step 3 — Train the model
```
python run_ids.py train --input normal_features.csv
```
Produces `ids_model.pkl` and `scaler.pkl`.

### Step 4 — Start live detection
```
python run_ids.py live
```

---

## Individual script usage

Every script also works standalone:

```
# Capture
python capture.py --save data.csv --iface "Wi-Fi"

# Features
python features.py --input data.csv --output features.csv --window 10

# Train
python train.py --input features.csv --contamination 0.05

# Detect (live)
python detect.py --model ids_model.pkl --scaler scaler.pkl

# Detect (replay)
python detect.py --replay features.csv --threshold -0.10
```

---

## Console output

```
[14:32:05] ✓  NORMAL           score=+0.0812  pkts=142  bytes=98432   cpu=1.2%  mem=42.3%
[14:32:15] ⚠  ALERT: ANOMALY  score=-0.2140  pkts=3201  bytes=4200000  cpu=3.1%  mem=42.5%  top_src=[192.168.1.50(2800), 10.0.0.4(320)]
```

| Field | Meaning |
|---|---|
| `score` | Isolation Forest decision score — below threshold triggers ALERT |
| `pkts` | Packets in this 10-second window |
| `bytes` | Total bytes in this window |
| `cpu` / `mem` | Resource usage — evidence for "lightweight" in your report |
| `top_src` | Top source IPs by packet count (ANOMALY windows only) |

---

## alerts.log

Every anomaly is appended to `alerts.log`:

```
2024-11-12 14:32:15 | ANOMALY | score=-0.2140 | pkts=3201 | bytes=4200000 | top_src=[192.168.1.50(2800), 10.0.0.4(320)]
```

---

## Tuning for your report

### Threshold (`--threshold`)
Controls how sensitive detection is without retraining.

```
python run_ids.py live --threshold -0.01    # loose
python run_ids.py live --threshold -0.10    # default
python run_ids.py live --threshold -0.20    # strict
```

### Contamination (`--contamination`)
Controls the model's prior on how much of the training data is anomalous.
Retrain for each value.

```
python run_ids.py train --input features.csv --contamination 0.01
python run_ids.py train --input features.csv --contamination 0.05
python run_ids.py train --input features.csv --contamination 0.10
```

### Report table (fill in from your own runs)

| contamination | threshold | Normal → NORMAL | Nmap → ALERT | hping3 → ALERT |
|---|---|---|---|---|
| 0.01 | -0.10 | | | |
| 0.05 | -0.10 | | | |
| 0.10 | -0.10 | | | |

---

## Testing with Kali

| Scenario | Kali command | Expected |
|---|---|---|
| Normal browsing | — | Mostly NORMAL |
| Port scan | `nmap -sS <target>` | ALERT: high unique_ips, tcp_count |
| SYN flood | `hping3 -S --flood <target>` | Continuous ALERT: extreme packet_count |
| ICMP flood | `hping3 --icmp --flood <target>` | ALERT: icmp_count spike |

For each scenario:
1. Start `python run_ids.py live` on the Windows machine
2. Run the attack from Kali
3. Screenshot the console and note the score values
4. Check `alerts.log` for a full record

---

## Files

| File | Imports from | Purpose |
|---|---|---|
| `pipeline.py` | nothing | Owns `PACKET_QUEUE` — the only shared state |
| `capture.py` | `pipeline` | Scapy sniff → queue + optional CSV |
| `features.py` | `pipeline` | Fixed-window feature extraction + live generator |
| `train.py` | `features` | Fit StandardScaler + IsolationForest, save artefacts |
| `detect.py` | `capture`, `features` | Load artefacts, live detection, logging |
| `run_ids.py` | all (lazy) | Single CLI entry point with subcommands |
