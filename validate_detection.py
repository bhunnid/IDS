#!/usr/bin/env python3
"""Validate IDS detection logic with realistic attack patterns."""

import time
import sys
from simple_config import SimpleConfig
from simple_ids import Flow, Alert, Detector, IDS

def create_port_scan_traffic(detector, src_ip, dst_ip, ports):
    """Create port scan traffic and test detection."""
    print(f"\n=== TESTING PORT SCAN DETECTION ===")
    print(f"Simulating port scan from {src_ip} to {dst_ip}")
    
    current_time = time.time()
    alerts = []
    
    for port in ports:
        flow = Flow(src_ip, dst_ip, 12345, port, "TCP")
        flow.add_packet(64, 0x02)  # SYN packet
        alert = detector.process_packet(flow)
        if alert:
            alerts.append(alert)
            print(f"ALERT: {alert.type} - {alert.severity}")
    
    print(f"Generated {len(alerts)} alerts for port scan")
    return alerts

def create_syn_flood_traffic(detector, src_ip, dst_ip, packet_count):
    """Create SYN flood traffic and test detection."""
    print(f"\n=== TESTING SYN FLOOD DETECTION ===")
    print(f"Simulating SYN flood: {packet_count} packets from {src_ip}")
    
    current_time = time.time()
    alerts = []
    
    for i in range(packet_count):
        flow = Flow(src_ip, dst_ip, 12345 + i, 80, "TCP")
        flow.add_packet(64, 0x02)  # SYN packet
        alert = detector.process_packet(flow)
        if alert:
            alerts.append(alert)
            print(f"ALERT: {alert.type} - {alert.severity}")
    
    print(f"Generated {len(alerts)} alerts for SYN flood")
    return alerts

def create_icmp_flood_traffic(detector, src_ip, dst_ip, packet_count):
    """Create ICMP flood traffic and test detection."""
    print(f"\n=== TESTING ICMP FLOOD DETECTION ===")
    print(f"Simulating ICMP flood: {packet_count} packets from {src_ip}")
    
    current_time = time.time()
    alerts = []
    
    for i in range(packet_count):
        flow = Flow(src_ip, dst_ip, 0, 0, "ICMP")
        flow.add_packet(64, 0)
        alert = detector.process_packet(flow)
        if alert:
            alerts.append(alert)
            print(f"ALERT: {alert.type} - {alert.severity}")
    
    print(f"Generated {len(alerts)} alerts for ICMP flood")
    return alerts

def create_data_exfiltration_traffic(detector, src_ip, dst_ip, byte_count):
    """Create data exfiltration traffic and test detection."""
    print(f"\n=== TESTING DATA EXFILTRATION DETECTION ===")
    print(f"Simulating data exfiltration: {byte_count} bytes from {src_ip}")
    
    current_time = time.time()
    alerts = []
    
    # Create one large flow
    flow = Flow(src_ip, dst_ip, 12345, 4444, "TCP")
    
    # Add packets until we reach the byte count
    packet_size = 1000
    packets_needed = byte_count // packet_size
    
    for i in range(packets_needed):
        flow.add_packet(packet_size, 0x18)  # ACK packet
        alert = detector.process_packet(flow)
        if alert:
            alerts.append(alert)
            print(f"ALERT: {alert.type} - {alert.severity}")
            break  # Stop after first alert
    
    print(f"Generated {len(alerts)} alerts for data exfiltration")
    print(f"Flow bytes: {flow.byte_count}")
    return alerts

def create_suspicious_port_traffic(detector, src_ip, dst_ip, suspicious_ports):
    """Create suspicious port access traffic and test detection."""
    print(f"\n=== TESTING SUSPICIOUS PORT DETECTION ===")
    print(f"Simulating access to suspicious ports from {src_ip}")
    
    current_time = time.time()
    alerts = []
    
    for port in suspicious_ports:
        flow = Flow(src_ip, dst_ip, 12345, port, "TCP")
        flow.add_packet(64, 0x18)  # ACK packet
        alert = detector.process_packet(flow)
        if alert:
            alerts.append(alert)
            print(f"ALERT: {alert.type} - {alert.severity} (port {port})")
    
    print(f"Generated {len(alerts)} alerts for suspicious port access")
    return alerts

def test_rate_limiting(detector, src_ip):
    """Test rate limiting functionality."""
    print(f"\n=== TESTING RATE LIMITING ===")
    print(f"Testing alert cooldown from {src_ip}")
    
    current_time = time.time()
    alerts = []
    
    # Create multiple alerts quickly
    for i in range(5):
        flow = Flow(src_ip, f"192.168.1.{100+i}", 12345, 80, "TCP")
        flow.add_packet(64, 0x02)  # SYN packet
        alert = detector.process_packet(flow)
        if alert:
            alerts.append(alert)
            print(f"Alert {i+1}: {alert.type}")
        time.sleep(0.1)  # Small delay
    
    print(f"Generated {len(alerts)} alerts (should be limited by cooldown)")
    return alerts

def validate_all_rules():
    """Validate all detection rules."""
    print("=== IDS DETECTION VALIDATION ===")
    print("Testing each detection rule with realistic attack patterns...\n")
    
    # Initialize IDS components
    config = SimpleConfig()
    detector = Detector(config)
    
    # Test parameters
    scanner_ip = "192.168.1.50"
    flood_ip = "192.168.1.60"
    exfil_ip = "192.168.1.70"
    suspicious_ip = "192.168.1.80"
    target_ip = "192.168.1.10"
    
    total_alerts = []
    
    # Test 1: Port Scan Detection
    port_scan_alerts = create_port_scan_traffic(
        detector, scanner_ip, target_ip, [22, 23, 80, 443, 3389]
    )
    total_alerts.extend(port_scan_alerts)
    
    # Test 2: SYN Flood Detection  
    syn_flood_alerts = create_syn_flood_traffic(
        detector, flood_ip, target_ip, 10
    )
    total_alerts.extend(syn_flood_alerts)
    
    # Test 3: ICMP Flood Detection
    icmp_flood_alerts = create_icmp_flood_traffic(
        detector, flood_ip, target_ip, 5
    )
    total_alerts.extend(icmp_flood_alerts)
    
    # Test 4: Data Exfiltration Detection
    exfil_alerts = create_data_exfiltration_traffic(
        detector, exfil_ip, target_ip, 15000  # 15KB
    )
    total_alerts.extend(exfil_alerts)
    
    # Test 5: Suspicious Port Detection
    suspicious_alerts = create_suspicious_port_traffic(
        detector, suspicious_ip, target_ip, [23, 1337, 31337]
    )
    total_alerts.extend(suspicious_alerts)
    
    # Test 6: Rate Limiting
    rate_limit_alerts = test_rate_limiting(detector, "192.168.1.90")
    total_alerts.extend(rate_limit_alerts)
    
    # Summary
    print(f"\n=== VALIDATION SUMMARY ===")
    print(f"Total alerts generated: {len(total_alerts)}")
    print(f"Port scan alerts: {len(port_scan_alerts)}")
    print(f"SYN flood alerts: {len(syn_flood_alerts)}")
    print(f"ICMP flood alerts: {len(icmp_flood_alerts)}")
    print(f"Data exfiltration alerts: {len(exfil_alerts)}")
    print(f"Suspicious port alerts: {len(suspicious_alerts)}")
    print(f"Rate limited alerts: {len(rate_limit_alerts)}")
    
    # Show sample alerts
    if total_alerts:
        print(f"\n=== SAMPLE ALERTS ===")
        for i, alert in enumerate(total_alerts[:3]):
            print(f"Alert {i+1}:")
            print(alert.format_output())
    
    # Validation results
    expected_alerts = 6  # Minimum expected alerts
    if len(total_alerts) >= expected_alerts:
        print(f"\nVALIDATION: SUCCESS")
        print(f"Detection logic is working correctly!")
        return True
    else:
        print(f"\nVALIDATION: FAILED")
        print(f"Expected at least {expected_alerts} alerts, got {len(total_alerts)}")
        return False

if __name__ == "__main__":
    success = validate_all_rules()
    sys.exit(0 if success else 1)
