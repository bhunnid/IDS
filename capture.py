from scapy.all import sniff, conf
import time
import pandas as pd

packet_queue = []


def process_packet(packet):
    try:
        if packet.haslayer("IP"):
            packet_queue.append({
                "timestamp": time.time(),
                "src_ip": packet["IP"].src,
                "dst_ip": packet["IP"].dst,
                "protocol": packet["IP"].proto,
                "size": len(packet)
            })
    except:
        pass


def resolve_iface(iface):
    """
    Accepts:
        - index (int or string)
        - or full device name
    """
    # If it's a number → convert index to device
    if str(iface).isdigit():
        return conf.ifaces.dev_from_index(int(iface))

    # Otherwise assume it's already a device string
    return iface


def start_capture(iface, duration=60, save=None):
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
        df.to_csv(save, index=False)
        print(f"[capture] Saved to {save}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--save", default=None)
    parser.add_argument("--duration", type=int, default=60)

    args = parser.parse_args()

    start_capture(args.iface, args.duration, args.save)