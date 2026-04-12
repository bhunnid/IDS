# Lightweight IDS for Small Networks and IoT Devices

A simple, fast intrusion detection system for small networks and IoT environments.

## Quick Start

```bash
pip install -r requirements.txt
python simple_ids.py --interface eth0
```

## Usage

```bash
# Live capture
python simple_ids.py --interface eth0

# PCAP analysis  
python simple_ids.py --pcap traffic.pcap

# List interfaces
python simple_ids.py --list-interfaces
```

## Features

- Port scan detection
- SYN/ICMP flood detection
- Data exfiltration monitoring
- Suspicious port access
- IP whitelisting
- Real-time alerts

## Configuration

Edit `config.yaml` to adjust detection thresholds and settings.

## License

MIT License
