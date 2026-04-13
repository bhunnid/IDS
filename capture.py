"""Packet capture utilities for the lightweight IDS."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Callable

from scapy.all import ICMP, IP, TCP, UDP, get_if_list, sniff

from pipeline import PACKET_QUEUE

PACKET_FIELDNAMES = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "size",
    "protocol",
]


def list_interfaces() -> list[str]:
    """Return available capture interfaces in stable order."""
    return sorted(dict.fromkeys(get_if_list()))


def _protocol_name(packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def parse_packet(packet) -> dict[str, object] | None:
    """Convert a Scapy packet to a lightweight metadata record."""
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_port = None
    dst_port = None
    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    return {
        "timestamp": float(packet.time),
        "src_ip": str(ip_layer.src),
        "dst_ip": str(ip_layer.dst),
        "src_port": src_port,
        "dst_port": dst_port,
        "size": int(len(packet)),
        "protocol": _protocol_name(packet),
    }


def _build_callback(
    writer: csv.DictWriter | None = None,
    csv_handle=None,
    verbose: bool = False,
) -> Callable:
    def on_packet(packet) -> None:
        record = parse_packet(packet)
        if record is None:
            return

        PACKET_QUEUE.put(record)

        if writer is not None:
            writer.writerow(record)
            if csv_handle is not None:
                csv_handle.flush()

        if verbose:
            print(
                f"[capture] {record['protocol']:<5} "
                f"{record['src_ip']} -> {record['dst_ip']} "
                f"{record['size']}B"
            )

    return on_packet


def start_capture(
    iface: str | None = None,
    save_path: str | None = None,
    verbose: bool = False,
) -> None:
    """Start a blocking Scapy sniff loop and push records into the queue."""
    csv_handle = None
    writer = None

    if save_path:
        output_path = Path(save_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        csv_handle = output_path.open("w", newline="", encoding="utf-8")
        writer = csv.DictWriter(csv_handle, fieldnames=PACKET_FIELDNAMES)
        writer.writeheader()
        csv_handle.flush()
        print(f"[capture] Saving packet metadata to {output_path}")

    if iface:
        print(f"[capture] Sniffing on interface: {iface}")
    else:
        print("[capture] Sniffing on Scapy default interface")

    print("[capture] Windows requires Npcap and an elevated terminal.")

    try:
        sniff(
            iface=iface,
            prn=_build_callback(writer=writer, csv_handle=csv_handle, verbose=verbose),
            store=False,
        )
    finally:
        if csv_handle is not None:
            csv_handle.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture packets for the IDS")
    parser.add_argument("--iface", help="Capture interface name, for example 'Wi-Fi'")
    parser.add_argument("--save", help="Optional CSV path for raw packet metadata")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print one line per captured packet",
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="List available capture interfaces and exit",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.list_ifaces:
        for name in list_interfaces():
            print(name)
        raise SystemExit(0)

    try:
        start_capture(iface=args.iface, save_path=args.save, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[capture] Capture stopped.")
