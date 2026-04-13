# capture.py

from scapy.all import sniff
from queue import Queue

packet_queue = Queue()

def process_packet(packet):
    try:
        if packet.haslayer("IP"):
            pkt = {
                "src": packet["IP"].src,
                "dst": packet["IP"].dst,
                "proto": packet["IP"].proto,
                "size": len(packet)
            }
            packet_queue.put(pkt)
    except:
        pass

def start_capture(interface):
    sniff(iface=interface, prn=process_packet, store=False)