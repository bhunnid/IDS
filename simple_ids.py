#!/usr/bin/env python3
"""Lightweight IDS for small networks and IoT environments."""

import time
import os
import sys
import signal
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available, only PCAP analysis supported")

from simple_config import SimpleConfig

# Alert severity constants
INFO = "INFO"
WARNING = "WARNING" 
CRITICAL = "CRITICAL"

class Flow:
    """Network flow tracking."""
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = time.time()
        self.last_time = self.start_time
        self.syn_count = 0
    
    def add_packet(self, size: int, tcp_flags: int = 0):
        """Add packet to flow."""
        self.packet_count += 1
        self.byte_count += size
        self.last_time = time.time()
        
        if tcp_flags & 0x02:  # SYN flag
            self.syn_count += 1
    
    def get_duration(self) -> float:
        """Get flow duration in seconds."""
        return self.last_time - self.start_time
    
    def get_packet_rate(self) -> float:
        """Get packets per second."""
        duration = self.get_duration()
        return self.packet_count / duration if duration > 0 else 0
    
    def is_expired(self, timeout: int) -> bool:
        """Check if flow is expired."""
        return (time.time() - self.last_time) > timeout
    
    def get_key(self) -> Tuple:
        """Get unique flow key."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

class Alert:
    """Security alert with severity."""
    
    def __init__(self, alert_type: str, src_ip: str, severity: str, details: Dict[str, any]):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.type = alert_type
        self.src_ip = src_ip
        self.severity = severity
        self.details = details
    
    def format_output(self) -> str:
        """Format alert for display."""
        lines = [
            f"[{self.severity}] {self.type}",
            f"Time: {self.timestamp}",
            f"Source IP: {self.src_ip}"
        ]
        
        for key, value in self.details.items():
            lines.append(f"{key.replace('_', ' ').title()}: {value}")
        
        return "\n".join(lines) + "\n" + "-" * 50 + "\n"

class Detector:
    """Signature-based intrusion detection."""
    
    def __init__(self, config: SimpleConfig):
        self.config = config
        self.thresholds = config.get_thresholds()
        self.whitelist = set(config.get_whitelist())
        self.cooldown_seconds = config.get('alerting.cooldown_seconds', 10)
        
        # Attack pattern trackers
        self.port_scans: Dict[str, Set[int]] = defaultdict(set)
        self.port_scan_times: Dict[str, List[float]] = defaultdict(list)
        self.syn_flood_times: Dict[str, List[float]] = defaultdict(list)
        self.icmp_flood_times: Dict[str, List[float]] = defaultdict(list)
        self.connection_times: Dict[str, List[float]] = defaultdict(list)
        self.flow_counts: Dict[str, int] = defaultdict(int)
        
        # Rate limiting
        self.alert_history: Dict[Tuple[str, str], float] = {}
        self.last_cleanup = time.time()
    
    def process_packet(self, flow: Flow) -> Optional[Alert]:
        """Process a flow and check for attacks."""
        current_time = time.time()
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        
        # Skip whitelisted IPs
        if src_ip in self.whitelist or dst_ip in self.whitelist:
            return None
        
        # Periodic cleanup
        if current_time - self.last_cleanup > 30:
            self._cleanup_data(current_time)
            self.last_cleanup = current_time
        
        # Check attack patterns
        checks = [
            self._check_port_scan(src_ip, flow.dst_port, current_time),
            self._check_syn_flood(src_ip, flow.syn_count, current_time),
            self._check_icmp_flood(src_ip, flow.protocol, current_time),
            self._check_data_exfiltration(flow),
            self._check_suspicious_ports(flow),
            self._check_connection_limits(src_ip, current_time),
            self._check_flow_limits(src_ip)
        ]
        
        for alert in checks:
            if alert and self._check_rate_limit(src_ip, alert.type, current_time):
                return alert
        
        return None
    
    def _check_port_scan(self, src_ip: str, dst_port: int, current_time: float) -> Optional[Alert]:
        """Check for port scanning."""
        window = self.thresholds.get('port_scan_window', 10)
        threshold = self.thresholds.get('port_scan_ports', 15)
        
        self.port_scans[src_ip].add(dst_port)
        self.port_scan_times[src_ip].append(current_time)
        
        # Clean old entries
        cutoff_time = current_time - window
        self.port_scan_times[src_ip] = [t for t in self.port_scan_times[src_ip] if t > cutoff_time]
        
        # Check threshold
        if len(self.port_scans[src_ip]) >= threshold and len(self.port_scan_times[src_ip]) >= threshold:
            return Alert("Port Scan Detected", src_ip, WARNING, {
                "ports_scanned": len(self.port_scans[src_ip]),
                "time_window": f"{window}s"
            })
        
        return None
    
    def _check_syn_flood(self, src_ip: str, syn_count: int, current_time: float) -> Optional[Alert]:
        """Check for SYN flood."""
        if syn_count == 0:
            return None
        
        window = self.thresholds.get('syn_flood_window', 5)
        threshold = self.thresholds.get('syn_flood_threshold', 80)
        
        self.syn_flood_times[src_ip].append(current_time)
        
        # Clean old entries
        cutoff_time = current_time - window
        self.syn_flood_times[src_ip] = [t for t in self.syn_flood_times[src_ip] if t > cutoff_time]
        
        # Check threshold - count SYN packets in window
        syn_count_in_window = len(self.syn_flood_times[src_ip])
        if syn_count_in_window >= threshold:
            return Alert("SYN Flood Detected", src_ip, CRITICAL, {
                "syn_packets": syn_count_in_window,
                "time_window": f"{window}s"
            })
        
        return None
    
    def _check_icmp_flood(self, src_ip: str, protocol: str, current_time: float) -> Optional[Alert]:
        """Check for ICMP flood."""
        if protocol != "ICMP":
            return None
        
        window = self.thresholds.get('icmp_window', 5)
        threshold = self.thresholds.get('icmp_threshold', 40)
        
        self.icmp_flood_times[src_ip].append(current_time)
        
        # Clean old entries
        cutoff_time = current_time - window
        self.icmp_flood_times[src_ip] = [t for t in self.icmp_flood_times[src_ip] if t > cutoff_time]
        
        # Check threshold - count ICMP packets in window
        icmp_count_in_window = len(self.icmp_flood_times[src_ip])
        if icmp_count_in_window >= threshold:
            return Alert("ICMP Flood Detected", src_ip, CRITICAL, {
                "icmp_packets": icmp_count_in_window,
                "time_window": f"{window}s"
            })
        
        return None
    
    def _check_data_exfiltration(self, flow: Flow) -> Optional[Alert]:
        """Check for data exfiltration."""
        threshold = self.thresholds.get('data_exfiltration_bytes', 1000000)
        
        if flow.byte_count >= threshold:
            return Alert("Data Exfiltration Detected", flow.src_ip, CRITICAL, {
                "bytes_transferred": f"{flow.byte_count:,}",
                "destination": f"{flow.dst_ip}:{flow.dst_port}"
            })
        
        return None
    
    def _check_suspicious_ports(self, flow: Flow) -> Optional[Alert]:
        """Check for connections to suspicious ports."""
        suspicious_ports = self.thresholds.get('suspicious_ports', [])
        
        if flow.dst_port in suspicious_ports:
            return Alert("Suspicious Port Access", flow.src_ip, INFO, {
                "suspicious_port": flow.dst_port,
                "destination": f"{flow.dst_ip}:{flow.dst_port}"
            })
        
        return None
    
    def _check_connection_limits(self, src_ip: str, current_time: float) -> Optional[Alert]:
        """Check for excessive connections."""
        threshold = self.thresholds.get('max_connections_per_second', 50)
        
        self.connection_times[src_ip].append(current_time)
        
        # Clean old entries (1 second window)
        cutoff_time = current_time - 1
        self.connection_times[src_ip] = [t for t in self.connection_times[src_ip] if t > cutoff_time]
        
        # Check threshold
        if len(self.connection_times[src_ip]) >= threshold:
            return Alert("Excessive Connections", src_ip, WARNING, {
                "connections_per_second": len(self.connection_times[src_ip])
            })
        
        return None
    
    def _check_flow_limits(self, src_ip: str) -> Optional[Alert]:
        """Check for too many flows from one IP."""
        threshold = self.thresholds.get('max_flows_per_ip', 100)
        
        self.flow_counts[src_ip] += 1
        
        if self.flow_counts[src_ip] >= threshold:
            return Alert("Flow Limit Exceeded", src_ip, WARNING, {
                "flow_count": self.flow_counts[src_ip],
                "threshold": threshold
            })
        
        return None
    
    def _cleanup_data(self, current_time: float):
        """Clean up old tracking data."""
        cutoff_time = current_time - 300  # 5 minutes
        
        # Clean port scan data
        for ip in list(self.port_scans.keys()):
            self.port_scan_times[ip] = [t for t in self.port_scan_times[ip] if t > cutoff_time]
            if not self.port_scan_times[ip]:
                del self.port_scan_times[ip]
                del self.port_scans[ip]
        
        # Clean other trackers
        for tracker in [self.syn_flood_times, self.icmp_flood_times, self.connection_times]:
            for ip in list(tracker.keys()):
                tracker[ip] = [t for t in tracker[ip] if t > cutoff_time]
                if not tracker[ip]:
                    del tracker[ip]
        
        # Clean alert history
        expired_keys = [key for key, last_time in self.alert_history.items() 
                       if current_time - last_time > 300]
        for key in expired_keys:
            del self.alert_history[key]
    
    def _check_rate_limit(self, src_ip: str, alert_type: str, current_time: float) -> bool:
        """Check if alert should be rate limited."""
        key = (src_ip, alert_type)
        
        if key in self.alert_history:
            if current_time - self.alert_history[key] < self.cooldown_seconds:
                return False
        
        self.alert_history[key] = current_time
        return True

class IDS:
    """Main intrusion detection system."""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config = SimpleConfig(config_file)
        self.detector = Detector(self.config)
        self.flows: Dict[Tuple, Flow] = {}
        self.running = False
        self.alert_file = None
        self.alert_count = 0
        
        # Flow settings
        flow_config = self.config.get_flow_config()
        self.flow_timeout = flow_config.get('timeout', 60)
        self.max_flows = flow_config.get('max_flows', 5000)
        
        # Setup alert output
        self._setup_alert_file()
    
    def _setup_alert_file(self):
        """Setup alert file output."""
        alerts_file = self.config.get('output.alerts_file', 'results/alerts.log')
        
        # Create results directory
        os.makedirs(os.path.dirname(alerts_file), exist_ok=True)
        
        # Open alert file
        self.alert_file = open(alerts_file, 'a')
        self.alert_file.write(f"\n=== IDS Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
        self.alert_file.flush()
    
    def _process_packet(self, packet):
        """Process a single packet."""
        try:
            # Only process IP packets with TCP/UDP/ICMP
            if not packet.haslayer(IP):
                return
            
            ip = packet[IP]
            src_ip, dst_ip = ip.src, ip.dst
            protocol = "OTHER"
            src_port = dst_port = 0
            tcp_flags = 0
            packet_size = len(packet)
            
            # Parse transport layer
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                protocol = "TCP"
                src_port, dst_port = tcp.sport, tcp.dport
                tcp_flags = tcp.flags
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                protocol = "UDP"
                src_port, dst_port = udp.sport, udp.dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                return  # Skip unsupported protocols
            
            # Get or create flow
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            if flow_key not in self.flows:
                self.flows[flow_key] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Update flow and check for attacks
            flow = self.flows[flow_key]
            flow.add_packet(packet_size, tcp_flags)
            
            alert = self.detector.process_packet(flow)
            if alert:
                self._handle_alert(alert)
            
            self._cleanup_flows()
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _handle_alert(self, alert: Alert):
        """Handle an alert."""
        self.alert_count += 1
        
        # Console output
        if self.config.get('output.console_output', True):
            print(alert.format_output())
        
        # File output
        if self.alert_file:
            self.alert_file.write(alert.format_output())
            self.alert_file.flush()
    
    def _cleanup_flows(self):
        """Clean up expired flows and enforce memory limits."""
        current_time = time.time()
        
        # Remove expired flows
        expired_keys = [key for key, flow in self.flows.items() 
                       if flow.is_expired(self.flow_timeout)]
        for key in expired_keys:
            del self.flows[key]
        
        # Enforce flow limit
        if len(self.flows) > self.max_flows:
            # Remove oldest flows
            sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].start_time)
            flows_to_remove = len(self.flows) - self.max_flows
            
            for i in range(flows_to_remove):
                del self.flows[sorted_flows[i][0]]
    
    def start_live_capture(self, interface: str = None):
        """Start live packet capture."""
        if not SCAPY_AVAILABLE:
            print("Error: Scapy not available for live capture")
            return
        
        interface = interface or self.config.get('capture.interface', 'eth0')
        print(f"Starting IDS on interface: {interface}")
        print("Press Ctrl+C to stop...")
        
        self.running = True
        
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\nStopping IDS...")
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.stop()
    
    def analyze_pcap(self, pcap_file: str):
        """Analyze a PCAP file."""
        if not SCAPY_AVAILABLE:
            print("Error: Scapy not available for PCAP analysis")
            return
        
        print(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_file)
            print(f"Loaded {len(packets)} packets")
            
            for i, packet in enumerate(packets):
                if not self.running:
                    break
                self._process_packet(packet)
                
                if (i + 1) % 1000 == 0:
                    print(f"Processed {i + 1} packets...")
            
            print(f"Analysis complete. Generated {self.alert_count} alerts.")
            
        except Exception as e:
            print(f"Error reading PCAP: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the IDS gracefully."""
        print("\nShutting down IDS...")
        self.running = False
        self.flows.clear()
        
        if self.alert_file:
            try:
                self.alert_file.write(f"\n=== IDS Stopped at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                self.alert_file.write(f"Total alerts generated: {self.alert_count}\n")
                self.alert_file.flush()
                self.alert_file.close()
            except Exception as e:
                print(f"Error closing alert file: {e}")
            finally:
                self.alert_file = None
        
        print(f"IDS stopped gracefully. Total alerts: {self.alert_count}")

def signal_handler(signum, frame):
    """Handle Ctrl+C."""
    print("\nReceived interrupt signal, stopping IDS...")
    if 'ids_instance' in globals():
        ids_instance.stop()
    sys.exit(0)

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Lightweight Intrusion Detection System")
    parser.add_argument("--interface", help="Network interface for live capture")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--config", default="config.yaml", help="Configuration file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces")
    
    args = parser.parse_args()
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create IDS instance
    global ids_instance
    ids_instance = IDS(args.config)
    
    if args.list_interfaces and SCAPY_AVAILABLE:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        return
    
    if args.pcap:
        ids_instance.analyze_pcap(args.pcap)
    elif args.interface or SCAPY_AVAILABLE:
        ids_instance.start_live_capture(args.interface)
    else:
        print("Error: No capture method specified")
        print("Use --interface for live capture or --pcap for file analysis")
        print("Use --list-interfaces to see available interfaces")
        parser.print_help()

if __name__ == "__main__":
    main()
