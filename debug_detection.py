#!/usr/bin/env python3
"""Debug detection logic to identify issues."""

import time
from simple_config import SimpleConfig
from simple_ids import Flow, Detector

def debug_syn_flood():
    """Debug SYN flood detection."""
    print("=== DEBUGGING SYN FLOOD DETECTION ===")
    
    config = SimpleConfig()
    detector = Detector(config)
    
    # Get thresholds
    syn_threshold = config.get('thresholds.syn_flood_threshold', 5)
    syn_window = config.get('thresholds.syn_flood_window', 5)
    
    print(f"SYN flood threshold: {syn_threshold} packets/{syn_window}s")
    
    # Create SYN packets
    src_ip = "192.168.1.60"
    dst_ip = "192.168.1.10"
    current_time = time.time()
    
    for i in range(10):
        flow = Flow(src_ip, dst_ip, 12345 + i, 80, "TCP")
        flow.add_packet(64, 0x02)  # SYN packet
        
        print(f"Packet {i+1}: SYN count = {flow.syn_count}")
        print(f"Detector SYN tracker size: {len(detector.syn_flood_times.get(src_ip, []))}")
        
        alert = detector.process_packet(flow)
        if alert:
            print(f"ALERT GENERATED: {alert.type}")
        else:
            print("No alert generated")
    
    # Check tracker state
    syn_times = detector.syn_flood_times.get(src_ip, [])
    print(f"Final SYN tracker: {len(syn_times)} entries")
    print(f"SYN rate: {len(syn_times) / syn_window:.1f} packets/sec")
    print(f"Threshold met: {len(syn_times) / syn_window >= syn_threshold}")

def debug_icmp_flood():
    """Debug ICMP flood detection."""
    print("\n=== DEBUGGING ICMP FLOOD DETECTION ===")
    
    config = SimpleConfig()
    detector = Detector(config)
    
    # Get thresholds
    icmp_threshold = config.get('thresholds.icmp_threshold', 3)
    icmp_window = config.get('thresholds.icmp_window', 5)
    
    print(f"ICMP flood threshold: {icmp_threshold} packets/{icmp_window}s")
    
    # Create ICMP packets
    src_ip = "192.168.1.60"
    dst_ip = "192.168.1.10"
    current_time = time.time()
    
    for i in range(5):
        flow = Flow(src_ip, dst_ip, 0, 0, "ICMP")
        flow.add_packet(64, 0)
        
        print(f"Packet {i+1}: ICMP")
        print(f"Detector ICMP tracker size: {len(detector.icmp_flood_times.get(src_ip, []))}")
        
        alert = detector.process_packet(flow)
        if alert:
            print(f"ALERT GENERATED: {alert.type}")
        else:
            print("No alert generated")
    
    # Check tracker state
    icmp_times = detector.icmp_flood_times.get(src_ip, [])
    print(f"Final ICMP tracker: {len(icmp_times)} entries")
    print(f"ICMP rate: {len(icmp_times) / icmp_window:.1f} packets/sec")
    print(f"Threshold met: {len(icmp_times) / icmp_window >= icmp_threshold}")

def debug_data_exfiltration():
    """Debug data exfiltration detection."""
    print("\n=== DEBUGGING DATA EXFILTRATION DETECTION ===")
    
    config = SimpleConfig()
    detector = Detector(config)
    
    # Get threshold
    exfil_threshold = config.get('thresholds.data_exfiltration_bytes', 10000)
    
    print(f"Data exfiltration threshold: {exfil_threshold} bytes")
    
    # Create large flow
    src_ip = "192.168.1.70"
    dst_ip = "192.168.1.10"
    
    flow = Flow(src_ip, dst_ip, 12345, 4444, "TCP")
    
    # Add packets until threshold
    packet_size = 1000
    packets_needed = exfil_threshold // packet_size + 1
    
    for i in range(packets_needed):
        flow.add_packet(packet_size, 0x18)  # ACK packet
        
        print(f"Packet {i+1}: Total bytes = {flow.byte_count}")
        
        alert = detector.process_packet(flow)
        if alert:
            print(f"ALERT GENERATED: {alert.type}")
            print(f"Alert details: {alert.details}")
            break
        else:
            print("No alert generated")
    
    print(f"Final flow bytes: {flow.byte_count}")
    print(f"Threshold met: {flow.byte_count >= exfil_threshold}")

def debug_rate_limiting():
    """Debug rate limiting."""
    print("\n=== DEBUGGING RATE LIMITING ===")
    
    config = SimpleConfig()
    detector = Detector(config)
    
    cooldown = detector.cooldown_seconds
    print(f"Cooldown seconds: {cooldown}")
    
    src_ip = "192.168.1.90"
    current_time = time.time()
    
    # Test multiple alerts
    for i in range(3):
        flow = Flow(src_ip, f"192.168.1.{100+i}", 12345, 80, "TCP")
        flow.add_packet(64, 0x02)  # SYN packet
        
        # Manually trigger suspicious port detection
        alert = detector._check_suspicious_ports(flow)
        
        if detector._check_rate_limit(src_ip, alert.type, current_time + i):
            print(f"Alert {i+1}: ALLOWED")
        else:
            print(f"Alert {i+1}: RATE LIMITED")
    
    # Check alert history
    history_keys = list(detector.alert_history.keys())
    print(f"Alert history: {len(history_keys)} entries")
    for key in history_keys:
        print(f"  {key}: {detector.alert_history[key]}")

if __name__ == "__main__":
    debug_syn_flood()
    debug_icmp_flood()
    debug_data_exfiltration()
    debug_rate_limiting()
