"""
capture.py — Live packet capture using Scapy.

Responsibilities:
  - Sniff raw packets on a network interface
  - Parse each packet into a lightweight dict
  - Put the dict onto pipeline.PACKET_QUEUE
  - Optionally write packets to a CSV file for offline training

Architecture notes:
  - Imports ONLY from pipeline (no circular risk)
  - Uses sniff(prn=...) — no monkey-patching, no custom hooks
  - The CSV writer is passed as a closure variable into _make_callback()
    so it is never shared or mutated from outside this module
  - start_capture() is blocking; run it in a daemon Thread from run_ids.py

Usage (standalone — captures and prints raw packets):
    python capture.py
    python capture.py --save training_data.csv
    python capture.py --save training_data.csv --iface "Wi-Fi"

Requirements:
    pip install scapy
    On Windows: install Npcap from https://npcap.com and run as Administrator
"""

import argparse
import csv
import time

from scapy.all import IP, ICMP, TCP, UDP, sniff

from pipeline import PACKET_QUEUE


# ── Packet parsing ────────────────────────────────────────────────────────────

def _protocol(pkt) -> str:
    """Return a string label for the transport-layer protocol."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def parse_packet(pkt) -> dict | None:
    """
    Convert a raw Scapy packet to a plain dict.
    Returns None if the packet has no IP layer (e.g. ARP, STP).
    """
    if not pkt.haslayer(IP):
        return None
    return {
        "timestamp": time.time(),
        "src_ip":    pkt[IP].src,
        "dst_ip":    pkt[IP].dst,
        "size":      len(pkt),
        "protocol":  _protocol(pkt),
    }


# ── Callback factory ──────────────────────────────────────────────────────────

def _make_callback(writer=None, verbose=False):
    """
    Return a prn= callback for sniff().

    Using a factory instead of a module-level function means:
      - writer is captured in the closure — no globals, no monkey-patching
      - verbose flag is local to this call — no side effects on other modules

    Args:
        writer:  csv.DictWriter or None
        verbose: if True, print each packet to console
    """
    def callback(pkt):
        record = parse_packet(pkt)
        if record is None:
            return
        PACKET_QUEUE.put(record)
        if writer:
            writer.writerow(record)
        if verbose:
            print(
                f"[{record['protocol']:5s}] "
                f"{record['src_ip']:>15s} → {record['dst_ip']:<15s}  "
                f"{record['size']} B"
            )
    return callback


# ── Public entry point ────────────────────────────────────────────────────────

def start_capture(iface=None, save_path=None, verbose=False):
    """
    Start live packet capture (blocking).

    Call this from a daemon Thread — it runs until interrupted.

    Args:
        iface:     Interface name string, or None for Scapy's default.
        save_path: Path to write a CSV of captured packets (training data).
        verbose:   Print each captured packet to stdout.
    """
    csv_file = None
    writer   = None

    if save_path:
        csv_file   = open(save_path, "w", newline="", encoding="utf-8")
        fieldnames = ["timestamp", "src_ip", "dst_ip", "size", "protocol"]
        writer     = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        print(f"[capture] Saving to {save_path}")

    callback = _make_callback(writer=writer, verbose=verbose)

    print(f"[capture] Sniffing on {iface or 'default interface'} ...")

    try:
        sniff(
            iface=iface,
            prn=callback,
            store=False,   # do not accumulate packets in Scapy's memory
        )
    finally:
        # Guaranteed to run even if sniff() raises an exception
        if csv_file:
            csv_file.close()
            print(f"[capture] Closed {save_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS packet capture")
    parser.add_argument("--iface",   metavar="NAME", help="Interface name")
    parser.add_argument("--save",    metavar="FILE", help="Save packets to CSV")
    parser.add_argument("--verbose", action="store_true", default=True,
                        help="Print each packet (default: on)")
    args = parser.parse_args()

    try:
        start_capture(iface=args.iface, save_path=args.save, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[capture] Stopped.")
