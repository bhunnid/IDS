This project is a lightweight anomaly-based Intrusion Detection System (IDS) with a web-based control panel built using Flask. It monitors real-time network traffic and detects anomalies.

The IDS uses a two-layer approach to eliminate false positives while reliably detecting real attacks:

Layer 1 — Adaptive Baseline (3 min learning phase)
The system observes live network traffic for 3 minutes and records the 99th-percentile peak for each rate metric. Detection thresholds are then set at 8× these peaks, ensuring normal traffic spikes can never trigger alerts.

Layer 2 — Signature-Based Attack Rules
Only clear, high-confidence attack patterns are flagged:

SYN Flood: High SYN rate with >70% SYN packets (legitimate traffic completes handshakes)
UDP Flood: UDP traffic exceeds 8× baseline (normal UDP rarely spikes significantly)
ICMP Flood: ICMP rate exceeds 50 packets/sec (far above typical usage)
Volumetric DoS: Total traffic exceeds 8× baseline (only if not already classified above)
Port Scan: Single source hits ≥50 ports within 3 seconds (not typical client behavior)

Result:
The system ignores harmless anomalies and only alerts on clear, attack-level behavior, dramatically reducing false positives.

The system is designed for small networks and runs locally with minimal resource usage.

This system is for educational and research use only. It should not be deployed in production environments without additional hardening.

- Brandon
