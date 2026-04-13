from scapy.all import sniff, conf, IP
import time
import pandas as pd

# Shared in-memory packet buffer
packet_queue = []


def process_packet(packet):
    """
    Convert raw Scapy packet → structured dict for feature extraction
    """
    try:
        if IP in packet:
            proto = packet[IP].proto

            # Map protocol numbers to readable labels
            if proto == 6:
                proto_name = "TCP"
            elif proto == 17:
                proto_name = "UDP"
            elif proto == 1:
                proto_name = "ICMP"
            else:
                proto_name = "OTHER"

            packet_queue.append({
                "timestamp": float(packet.time),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": proto_name,
                "size": len(packet)
            })

    except Exception:
        pass


def resolve_iface(iface):
    """
    Accepts:
        - numeric index (e.g. "8")
        - full Npcap interface string
    """
    try:
        # If numeric index → convert properly
        if str(iface).isdigit():
            return conf.ifaces.dev_from_index(int(iface))

        # Already a device string
        return iface

    except Exception:
        print(f"[capture] ERROR: Invalid interface {iface}")
        print("[capture] Run: python -c \"from scapy.all import show_interfaces; show_interfaces()\"")
        exit(1)


def start_capture(iface, duration=60, save=None):
    """
    Captures packets for fixed duration and optionally saves to CSV.
    """
    global packet_queue
    packet_queue = []

    iface = resolve_iface(iface)

    print(f"[capture] Using interface: {iface}")
    print(f"[capture] Capturing for {duration}s...")

    sniff(
        iface=iface,
        prn=process_packet,
        store=False,
        timeout=duration
    )

    print(f"[capture] Captured {len(packet_queue)} packets")

    if save:
        df = pd.DataFrame(packet_queue)

        # Ensure consistent column order (important for features.py)
        df = df[["timestamp", "src_ip", "dst_ip", "protocol", "size"]]

        df.to_csv(save, index=False)
        print(f"[capture] Saved to {save}")


# ─────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Packet capture module for IDS")
    parser.add_argument("--iface", required=True, help="Interface index or full name")
    parser.add_argument("--save", default=None, help="Output CSV file")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration (seconds)")

    args = parser.parse_args()

    start_capture(args.iface, args.duration, args.save)