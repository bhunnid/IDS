#!/usr/bin/env python3
"""
Simple configuration loader for lightweight IDS
"""

import yaml
import os
from typing import Dict, Any, List

class SimpleConfig:
    """Simple configuration manager for IDS"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            print(f"Config file {self.config_file} not found, using defaults")
            return self._get_defaults()
        except yaml.YAMLError as e:
            print(f"Error parsing config: {e}")
            return self._get_defaults()
    
    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'whitelist': [],
            'thresholds': {
                'port_scan_ports': 15,
                'port_scan_window': 10,
                'syn_flood_threshold': 80,
                'syn_flood_window': 5,
                'icmp_threshold': 40,
                'icmp_window': 5,
                'data_exfiltration_bytes': 1000000,
                'suspicious_ports': [23, 8080, 4444, 5555, 1337, 31337],
                'max_connections_per_second': 50,
                'max_flows_per_ip': 100
            },
            'flow': {
                'timeout': 60,
                'max_flows': 5000
            },
            'capture': {
                'interface': 'eth0',
                'promiscuous': True
            },
            'output': {
                'alerts_file': 'results/alerts.log',
                'console_output': True,
                'max_alerts_per_minute': 100
            },
            'alerting': {
                'cooldown_seconds': 10
            },
            'performance': {
                'memory_limit_mb': 512,
                'cleanup_interval': 30
            }
        }
    
    def get(self, key: str, default=None):
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_thresholds(self) -> Dict[str, Any]:
        """Get detection thresholds"""
        return self.get('thresholds', {})
    
    def get_flow_config(self) -> Dict[str, Any]:
        """Get flow configuration"""
        return self.get('flow', {})
    
    def get_capture_config(self) -> Dict[str, Any]:
        """Get capture configuration"""
        return self.get('capture', {})
    
    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration"""
        return self.get('output', {})
    
    def get_whitelist(self) -> List[str]:
        """Get IP whitelist"""
        return self.get('whitelist', [])
    
    def get_alerting_config(self) -> Dict[str, Any]:
        """Get alerting configuration"""
        return self.get('alerting', {})
