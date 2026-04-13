# Lightweight Anomaly-Based IDS

A lightweight, modular, anomaly-based intrusion detection system for Windows 11. It captures packet metadata with Scapy, builds flow-style time-window features, trains an `IsolationForest`, and performs real-time local anomaly detection without cloud services or payload inspection.

## Architecture

- `pipeline.py`: owns the single shared `PACKET_QUEUE`.
- `capture.py`: captures packet metadata from a selected interface and can save raw packet records to CSV.
- `features.py`: converts packets into fixed time-window features for training and live detection.
- `train.py`: trains `StandardScaler` plus `IsolationForest` and saves `ids_model.pkl` and `scaler.pkl`.
- `detect.py`: runs live detection or replay detection and logs anomalies to `alerts.log`.
- `evaluate.py`: computes formal metrics from labeled feature datasets, including threshold sweeps.
- `run_ids.py`: single CLI entry point for the full workflow.

Pipeline:

```text
Scapy sniff() -> PACKET_QUEUE -> feature windows -> scaler -> IsolationForest -> console alerts + alerts.log
```

## Install

```bash
pip install scapy pandas numpy scikit-learn joblib psutil
```

Windows requirements:

- Install Npcap: https://npcap.com/#download
- Run PowerShell or Windows Terminal as Administrator
- Use `python run_ids.py capture --list-ifaces` to find the capture interface

## Core Commands

List interfaces:

```bash
python run_ids.py capture --list-ifaces
```

Capture normal traffic:

```bash
python run_ids.py capture --iface "\Device\NPF_Loopback" --save normal.csv
```

Extract features:

```bash
python run_ids.py features --input normal.csv --output normal_features.csv --window 10 --local-ip 127.0.0.1
```

Train the model:

```bash
python run_ids.py train --input normal_features.csv --contamination 0.05
```

Run live detection:

```bash
python run_ids.py live --iface "\Device\NPF_Loopback" --threshold -0.10 --window 10 --local-ip 127.0.0.1
```

Replay feature windows:

```bash
python run_ids.py replay --input normal_features.csv --threshold -0.10
```

Evaluate labeled feature data:

```bash
python run_ids.py evaluate --input labeled_features.csv --threshold -0.10 --sweep -0.20 -0.10 -0.05 0.00 --metrics-out metrics.csv --scored-out scored_windows.csv
```

## Current Feature Set

The IDS uses metadata only. No packet payloads are inspected.

- `packet_count`
- `byte_count`
- `avg_packet_size`
- `tcp_count`
- `udp_count`
- `icmp_count`
- `unique_src_ips`
- `unique_dst_ips`
- `unique_host_pairs`
- `unique_service_ports`
- `new_connection_count`
- `avg_connection_duration`
- `max_connection_duration`
- `avg_inter_arrival_ms`
- `max_packets_per_src`
- `avg_packets_per_src`
- `avg_bytes_per_src`
- `inbound_packet_count`
- `outbound_packet_count`
- `inbound_byte_count`
- `outbound_byte_count`
- `top_src_ips`

These cover packet volume, protocol distribution, host communication frequency, per-host activity, connection/session diversity, timing behavior, and directional traffic statistics.

## Evaluation Support

`evaluate.py` supports labeled research testing with:

- accuracy
- precision
- recall
- F1-score
- false positive rate
- false negative rate
- confusion matrix counts
- ROC AUC
- threshold sweeps

Supported label values:

- benign labels: `normal`, `benign`, `0`, `false`
- attack labels: `anomaly`, `attack`, `malicious`, `1`, `true`

## Live Output

```text
[14:32:05] NORMAL score=+0.08 pkts=120 bytes=90000 cpu=2% mem=40%
[14:32:15] ALERT  score=-0.21 pkts=3000 bytes=4000000 cpu=3% mem=41% top_src=[192.168.1.50(2800)]
```

Alert log format:

```text
2026-04-13 14:32:15 | ANOMALY | score=-0.2140 | pkts=3201 | bytes=4200000 | top_src_ips=[192.168.1.50(2800)]
```

## Suggested Academic Workflow

1. Capture normal traffic and extract training features.
2. Train the model on benign windows only.
3. Capture or prepare labeled benign and attack windows.
4. Run `evaluate` with multiple thresholds.
5. Report precision, recall, F1, false positive rate, and ROC AUC.
6. Compare thresholds and discuss tradeoffs.

## Attack Scenarios To Test

- normal browsing traffic
- Nmap port scan
- SYN flood with `hping3 -S --flood <target>`
- ICMP flood with `hping3 --icmp --flood <target>`
- repeated connection attempts for brute-force style behavior
