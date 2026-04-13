# Lightweight Anomaly-Based IDS

A production-ready, lightweight IDS for Windows 11 that captures packet metadata with Scapy, extracts flow-style window features, and detects anomalies in real time using `IsolationForest`.

## Architecture

- `pipeline.py`: owns the single shared `PACKET_QUEUE`.
- `capture.py`: captures packets with Scapy and optionally writes packet metadata to CSV.
- `features.py`: builds fixed 10-second feature windows for offline training and live detection.
- `train.py`: trains `StandardScaler` + `IsolationForest` and saves `ids_model.pkl` and `scaler.pkl`.
- `detect.py`: runs live detection or replays a feature CSV and logs anomalies to `alerts.log`.
- `run_ids.py`: single CLI entry point with `capture`, `features`, `train`, `live`, and `replay`.

The pipeline is:

```text
Scapy sniff() -> PACKET_QUEUE -> live_windows()/CSV windows -> scaler -> IsolationForest -> console alerts + alerts.log
```

## Install

```bash
pip install scapy pandas numpy scikit-learn joblib psutil
```

Windows requirements:

- Install Npcap: https://npcap.com/#download
- Run PowerShell or Windows Terminal as Administrator
- Select the correct interface, for example `Wi-Fi` or `Ethernet`

## Usage

List interfaces:

```bash
python run_ids.py capture --list-ifaces
```

Capture normal traffic for training:

```bash
python run_ids.py capture --iface "Wi-Fi" --save normal.csv
```

Extract windowed features:

```bash
python run_ids.py features --input normal.csv --output normal_features.csv --window 10
```

Train the anomaly model:

```bash
python run_ids.py train --input normal_features.csv --contamination 0.05
```

Run live detection:

```bash
python run_ids.py live --iface "Wi-Fi" --threshold -0.10
```

Replay previously extracted features:

```bash
python run_ids.py replay --input normal_features.csv --threshold -0.10
```

## Features

Each window is built from packet metadata only. No payload inspection is used.

- `packet_count`
- `byte_count`
- `avg_packet_size`
- `tcp_count`
- `udp_count`
- `icmp_count`
- `unique_src_ips`
- `top_src_ips`

## Live Output

```text
[14:32:05] NORMAL score=+0.08 pkts=120 bytes=90000 cpu=2% mem=40%
[14:32:15] ALERT  score=-0.21 pkts=3000 bytes=4000000 cpu=3% mem=41% top_src=[192.168.1.50(2800)]
```

Anomalies are appended to `alerts.log` in this format:

```text
2026-04-13 14:32:15 | ANOMALY | score=-0.2140 | pkts=3201 | bytes=4200000 | top_src_ips=[192.168.1.50(2800)]
```

## Testing

Expected lab tests:

- Normal browsing: mostly `NORMAL`
- Nmap scan: spike in `packet_count`, `tcp_count`, and `unique_src_ips`
- SYN flood with `hping3 -S --flood <target>`: repeated `ALERT`
- ICMP flood with `hping3 --icmp --flood <target>`: repeated `ALERT`
