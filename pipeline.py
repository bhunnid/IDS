"""
pipeline.py — Shared state module.

This is the ONLY place the packet queue is created.
Every other module imports from here — never from each other.
This eliminates circular imports entirely.

                capture.py
                    │
                    ▼
             pipeline.PACKET_QUEUE   ◄── the queue lives here
                    │
                    ▼
              features.py
                    │
                    ▼
               detect.py

Rule: no module imports another IDS module directly.
      Every module that needs the queue does:
          from pipeline import PACKET_QUEUE
"""

import queue

# ── Shared packet queue ───────────────────────────────────────────────────────
# capture.py puts() dicts here.
# features.py get_nowait()s from here.
# maxsize=0 means unlimited (bounded only by available RAM).
PACKET_QUEUE: queue.Queue = queue.Queue(maxsize=0)

# ── Packet dict schema (documentation only) ──────────────────────────────────
# Every item placed on PACKET_QUEUE must be a dict with these keys:
#   timestamp : float   — time.time() at capture
#   src_ip    : str     — source IP address
#   dst_ip    : str     — destination IP address
#   size      : int     — total packet length in bytes
#   protocol  : str     — "TCP" | "UDP" | "ICMP" | "OTHER"
