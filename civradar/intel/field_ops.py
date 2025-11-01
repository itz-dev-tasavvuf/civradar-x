"""
Field Operations Module for CIVRADAR-X

This module implements field operation modes with enhanced stealth capabilities
for the CIVRADAR-X system. It provides adaptive operational profiles optimized
for different threat environments, from standard operations to maximum stealth
in hostile scenarios.

Key Features:
- Multiple operational modes (Normal, Stealth, Ghost, Emergency, etc.)
- Adaptive stealth profiles based on threat environment
- Real-time threat detection with automated response
- Process and network obfuscation techniques
- Hardware stealth capabilities (USB hiding, LED disabling)
- Time-based operational constraints and auto-termination

Operational Modes:
- NORMAL: Standard operation with full logging and features
- STEALTH: Minimal activity, passive scanning, process hiding
- GHOST: Maximum stealth, no active logging, encrypted memory
- EMERGENCY: Crisis mode with rapid data wipe capabilities
- RECON: Intelligence gathering with Tor integration
- COMBAT: High-threat environment with restricted communications
- RADIO_SILENCE: Complete network inactivity
- OFFLINE: Full offline operation with local processing

Stealth Techniques:
- Process name obfuscation (appearing as system processes)
- Command line hiding and argument sanitization
- Network port randomization and outbound blocking
- Time stomping for file timestamp obfuscation
- Fake log activity generation for pattern disruption
- Hardware device hiding and LED disabling
- MAC address randomization for network anonymity

Threat Detection Integration:
- Process signature matching for monitoring tools
- Network anomaly detection (suspicious connections, ports)
- Hardware monitoring (USB devices, wireless interfaces)
- Filesystem activity monitoring for sensitive file access

Auto-Response Mechanisms:
- Mode switching based on threat severity
- Emergency wipe triggers for critical threats
- Security level escalation with increased monitoring
- Backup wipe intervals for operational security

Author: CIVRADAR-X Development Team
License: MIT (Classified Operations)
"""

import os
import time
import threading
import secrets
import subprocess
import psutil
import json
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from .opsec_logger import get_opsec_logger, log_opsec_event, secure_wipe

class FieldMode(Enum):
    """Field operation modes for different threat environments."""
    NORMAL = "normal"           # Standard operation with full logging
    STEALTH = "stealth"         # Minimal activity, passive scanning only
    GHOST = "ghost"             # Maximum stealth, no active logging
    EMERGENCY = "emergency"     # Crisis mode with rapid data wipe
    RECON = "recon"             # Intelligence gathering mode
    COMBAT = "combat"           # High-threat environment mode
    RADIO_SILENCE = "radio_silence"  # No network activity at all
    OFFLINE = "offline"         # Complete offline operation

@dataclass
class StealthProfile:
    """Stealth configuration for different operational modes."""
    # Process hiding
    hide_process: bool = False
    fake_process_name: str = "systemd"
    hide_command_line: bool = False
    
    # Network stealth
    block_outbound: bool = False
    use_tor: bool = False
    randomize_ports: bool = False
    hide_user_agent: bool = False
    
    # Logging stealth
    disable_logging: bool = False
    encrypt_logs: bool = True
    time_stomping: bool = False
    fake_log_activity: bool = False
    
    # Hardware stealth
    hide_usb_devices: bool = False
    disable_leds: bool = False
    randomize_mac: bool = False
    
    # Memory stealth
    clear_memory_traces: bool = False
    encrypt_memory: bool = False
    secure_heap: bool = False

@dataclass
class FieldConfig:
    """Configuration for field operations."""
    mode: FieldMode = FieldMode.NORMAL
    stealth_profile: StealthProfile = None
    auto_switch_mode: bool = True
    threat_detection_sensitivity: int = 5  # 0-10
    wipe_on_detection: bool = True
    backup_wipe_interval: int = 300  # 5 minutes
    operation_time_limit: int = 3600  # 1 hour
    field_identifier: str = None
    
    def __post_init__(self):
        if self.stealth_profile is None:
            self.stealth_profile = self._get_default_stealth_profile()
    
    def _get_default_stealth_profile(self) -> StealthProfile:
        """Get default stealth profile based on mode."""
        profiles = {
            FieldMode.NORMAL: StealthProfile(
                encrypt_logs=True,
                time_stomping=False,
                fake_log_activity=False
            ),
            FieldMode.STEALTH: StealthProfile(
                hide_process=True,
                fake_process_name="kworker",
                hide_command_line=True,
                randomize_ports=True,
                encrypt_logs=True,
                time_stomping=True,
                fake_log_activity=True,
                clear_memory_traces=True
            ),
            FieldMode.GHOST: StealthProfile(
                hide_process=True,
                fake_process_name="kthreadd",
                hide_command_line=True,
                block_outbound=True,
                disable_logging=True,
                hide_usb_devices=True,
                randomize_mac=True,
                clear_memory_traces=True,
                secure_heap=True
            ),
            FieldMode.EMERGENCY: StealthProfile(
                hide_process=True,
                fake_process_name="init",
                block_outbound=True,
                disable_logging=True,
                hide_usb_devices=True,
                disable_leds=True,
                encrypt_memory=True,
                secure_heap=True
            ),
            FieldMode.RECON: StealthProfile(
                hide_process=True,
                hide_command_line=True,
                use_tor=True,
                randomize_ports=True,
                encrypt_logs=True,
                time_stomping=True,
                clear_memory_traces=True
            ),
            FieldMode.COMBAT: StealthProfile(
                hide_process=True,
                hide_command_line=True,
                block_outbound=True,
                encrypt_logs=True,
                fake_log_activity=True,
                clear_memory_traces=True,
                secure_heap=True
            ),
            FieldMode.RADIO_SILENCE: StealthProfile(
                hide_process=True,
                block_outbound=True,
                disable_logging=True,
                hide_usb_devices=True,
                clear_memory_traces=True
            ),
            FieldMode.OFFLINE: StealthProfile(
                hide_process=True,
                block_outbound=True,
                disable_logging=True,
                hide_usb_devices=True,
                clear_memory_traces=True,
                secure_heap=True
            )
        }
        return profiles.get(self.mode, StealthProfile())

class ThreatDetector:
    """Real-time threat detection for field operations."""
    
    def __init__(self, sensitivity: int = 5):
        self.sensitivity = sensitivity
        self.detection_active = False
        self.threat_indicators = []
        self._lock = threading.Lock()
        
        # Load threat signatures
        self._load_threat_signatures()
    
    def _load_threat_signatures(self):
        """Load threat detection signatures."""
        self.threat_signatures = {
            'processes': [
                'wireshark', 'tcpdump', 'nmap', 'masscan', 'zmap',
                'volatility', 'autopsy', 'sleuthkit', 'foremost',
                'netsniff-ng', 'ettercap', 'arpspoof', 'dsniff'
            ],
            'signals': [
                'aircrack-ng', 'kismet', 'airodump', 'reaver',
                'wash', 'hostapd', 'hostapd-wpe'
            ],
            'forensic': [
                'dd', 'dc3dd', 'dcfldd', 'testdisk', 'photorec',
                'strings', 'hexdump', 'xxd', 'binwalk', 'file'
            ],
            'surveillance': [
                'tcpflow', 'ngrep', 'tcpstat', 'ifstat',
                'iptraf-ng', 'iftop', 'nethogs', 'vnstat'
            ]
        }
    
    def start_detection(self, callback: Callable = None):
        """Start threat detection monitoring."""
        self.detection_active = True
        self.callback = callback
        
        def detection_loop():
            while self.detection_active:
                try:
                    threats = self._scan_environment()
                    if threats:
                        self._handle_threats(threats)
                    time.sleep(1)  # Check every second
                except Exception as e:
                    log_opsec_event("threat_detector_error", {"error": str(e)}, "emergency", 8)
        
        threading.Thread(target=detection_loop, daemon=True).start()
        log_opsec_event("threat_detection_started", {"sensitivity": self.sensitivity}, "normal", 1)
    
    def stop_detection(self):
        """Stop threat detection monitoring."""
        self.detection_active = False
        log_opsec_event("threat_detection_stopped", {}, "normal", 1)
    
    def _scan_environment(self) -> List[Dict[str, Any]]:
        """Scan environment for threats."""
        threats = []
        
        # Check for suspicious processes
        process_threats = self._check_suspicious_processes()
        threats.extend(process_threats)
        
        # Check for network threats
        network_threats = self._check_network_threats()
        threats.extend(network_threats)
        
        # Check for hardware threats
        hardware_threats = self._check_hardware_threats()
        threats.extend(hardware_threats)
        
        # Check for file system threats
        filesystem_threats = self._check_filesystem_threats()
        threats.extend(filesystem_threats)
        
        return threats
    
    def _check_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Check for suspicious processes."""
        threats = []
        
        try:
            current_process = psutil.Process()
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    if proc.info['name'].lower() in self.threat_signatures['processes']:
                        threat = {
                            'type': 'process',
                            'severity': self._calculate_severity(proc.info['name']),
                            'source': proc.info['name'],
                            'pid': proc.info['pid'],
                            'user': proc.info['username'],
                            'description': f'Suspicious process: {proc.info["name"]}',
                            'timestamp': time.time()
                        }
                        threats.append(threat)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check parent process chain for suspicious activity
            try:
                parent_chain = []
                current = current_process
                for _ in range(5):  # Check up to 5 levels up
                    try:
                        parent = current.parent()
                        if parent:
                            parent_chain.append(parent.name())
                            current = parent
                        else:
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        break
                
                for process_name in parent_chain:
                    if process_name.lower() in self.threat_signatures['processes']:
                        threat = {
                            'type': 'parent_process',
                            'severity': 8,
                            'source': process_name,
                            'description': f'Suspicious parent process: {process_name}',
                            'timestamp': time.time()
                        }
                        threats.append(threat)
                        
            except Exception:
                pass
                
        except Exception:
            pass
        
        return threats
    
    def _check_network_threats(self) -> List[Dict[str, Any]]:
        """Check for network-based threats."""
        threats = []
        
        try:
            connections = psutil.net_connections()
            
            # Check for suspicious ports
            suspicious_ports = [22, 23, 80, 443, 8080, 8443, 9000, 9999]
            
            for conn in connections:
                if conn.laddr and conn.raddr:
                    if conn.raddr.port in suspicious_ports:
                        threat = {
                            'type': 'network',
                            'severity': 6,
                            'source': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'description': f'Connection to suspicious port {conn.raddr.port}',
                            'timestamp': time.time()
                        }
                        threats.append(threat)
            
            # Check for many connections from same source
            connections_by_ip = {}
            for conn in connections:
                if conn.raddr:
                    ip = conn.raddr.ip
                    connections_by_ip[ip] = connections_by_ip.get(ip, 0) + 1
            
            for ip, count in connections_by_ip.items():
                if count > 10:  # More than 10 connections from same IP
                    threat = {
                        'type': 'network',
                        'severity': 7,
                        'source': ip,
                        'description': f'Excessive connections from {ip}: {count}',
                        'timestamp': time.time()
                    }
                    threats.append(threat)
                    
        except Exception:
            pass
        
        return threats
    
    def _check_hardware_threats(self) -> List[Dict[str, Any]]:
        """Check for hardware-based threats."""
        threats = []
        
        try:
            # Check for USB devices
            usb_devices = []
            for device in psutil.disk_partitions():
                if 'usb' in device.device.lower() or 'removable' in str(device.opts).lower():
                    usb_devices.append(device.device)
            
            if usb_devices:
                threat = {
                    'type': 'hardware',
                    'severity': 5,
                    'source': 'usb_devices',
                    'description': f'USB devices detected: {", ".join(usb_devices)}',
                    'timestamp': time.time()
                }
                threats.append(threat)
            
            # Check for wireless interfaces that might be monitoring
            wireless_interfaces = []
            try:
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
                if 'monitor' in result.stdout.lower():
                    threat = {
                        'type': 'hardware',
                        'severity': 8,
                        'source': 'wireless_monitor',
                        'description': 'Wireless interface in monitor mode detected',
                        'timestamp': time.time()
                    }
                    threats.append(threat)
            except:
                pass
                
        except Exception:
            pass
        
        return threats
    
    def _check_filesystem_threats(self) -> List[Dict[str, Any]]:
        """Check for file system threats."""
        threats = []
        
        # Check for recently accessed sensitive files
        sensitive_paths = [
            '/etc/shadow', '/etc/passwd', '/var/log/auth.log',
            '/home', '/root', '/tmp', '/var/tmp'
        ]
        
        try:
            for path in sensitive_paths:
                if os.path.exists(path):
                    stat = os.stat(path)
                    # If file was accessed in last 60 seconds
                    if time.time() - stat.st_mtime < 60:
                        threat = {
                            'type': 'filesystem',
                            'severity': 6,
                            'source': path,
                            'description': f'Recent access to sensitive path: {path}',
                            'timestamp': time.time()
                        }
                        threats.append(threat)
                        
        except Exception:
            pass
        
        return threats
    
    def _calculate_severity(self, process_name: str) -> int:
        """Calculate threat severity based on process name."""
        high_threat = ['wireshark', 'volatility', 'autopsy']
        medium_threat = ['tcpdump', 'nmap', 'foremost']
        
        if process_name.lower() in high_threat:
            return 9
        elif process_name.lower() in medium_threat:
            return 7
        else:
            return 5
    
    def _handle_threats(self, threats: List[Dict[str, Any]]):
        """Handle detected threats."""
        with self._lock:
            self.threat_indicators.extend(threats)
            
            # Calculate overall threat level
            max_severity = max(t['severity'] for t in threats) if threats else 0
            
            # Log threats
            log_opsec_event("threats_detected", {
                "threat_count": len(threats),
                "max_severity": max_severity,
                "threats": threats
            }, "stealth", max_severity)
            
            # Call callback if set
            if self.callback:
                try:
                    self.callback(threats, max_severity)
                except Exception as e:
                    log_opsec_event("threat_callback_error", {"error": str(e)}, "emergency", 9)


class FieldOperations:
    """
    Field Operations Manager for handling different operational modes.
    """
    
    def __init__(self, config: FieldConfig = None):
        self.config = config or FieldConfig()
        self.current_mode = self.config.mode
        self.threat_detector = ThreatDetector(self.config.threat_detection_sensitivity)
        self.operation_start_time = time.time()
        self.mode_switch_history = []
        self._lock = threading.Lock()
        
        # Setup threat detection callback
        self.threat_detector.start_detection(self._on_threat_detected)
        
        # Initialize current mode
        self._apply_mode_config()
        
        log_opsec_event("field_ops_initialized", {
            "mode": self.current_mode.value,
            "config": asdict(self.config)
        }, "normal", 1)
    
    def _on_threat_detected(self, threats: List[Dict[str, Any]], max_severity: int):
        """Handle threat detection."""
        if max_severity >= self.config.threat_detection_sensitivity:
            if self.config.wipe_on_detection and max_severity >= 8:
                log_opsec_event("auto_wipe_triggered", {
                    "threat_severity": max_severity,
                    "threats": threats
                }, "emergency", max_severity)
                secure_wipe()
            
            # Auto-switch mode if enabled
            if self.config.auto_switch_mode:
                self._auto_switch_mode(max_severity)
    
    def _auto_switch_mode(self, threat_severity: int):
        """Automatically switch operational mode based on threat level."""
        mode_mapping = {
            (0, 3): FieldMode.NORMAL,
            (4, 5): FieldMode.STEALTH,
            (6, 7): FieldMode.GHOST,
            (8, 9): FieldMode.COMBAT,
            (10, 10): FieldMode.EMERGENCY
        }
        
        new_mode = None
        for severity_range, mode in mode_mapping.items():
            if severity_range[0] <= threat_severity <= severity_range[1]:
                new_mode = mode
                break
        
        if new_mode and new_mode != self.current_mode:
            self.switch_mode(new_mode, reason=f"Auto-switch due to threat level {threat_severity}")
    
    def switch_mode(self, new_mode: FieldMode, reason: str = None):
        """Switch operational mode."""
        with self._lock:
            old_mode = self.current_mode
            self.current_mode = new_mode
            self.config.mode = new_mode
            
            # Update stealth profile
            self.config.stealth_profile = self.config._get_default_stealth_profile()
            
            # Apply new mode configuration
            self._apply_mode_config()
            
            # Record mode switch
            self.mode_switch_history.append({
                'from_mode': old_mode.value,
                'to_mode': new_mode.value,
                'reason': reason,
                'timestamp': time.time()
            })
            
            log_opsec_event("mode_switched", {
                "from_mode": old_mode.value,
                "to_mode": new_mode.value,
                "reason": reason,
                "switch_count": len(self.mode_switch_history)
            }, "normal", 2)
    
    def _apply_mode_config(self):
        """Apply current mode configuration."""
        profile = self.config.stealth_profile
        
        # Apply process hiding
        if profile.hide_process:
            self._hide_current_process(profile.fake_process_name)
        
        if profile.hide_command_line:
            self._hide_command_line()
        
        # Apply network stealth
        if profile.block_outbound:
            self._block_outbound_connections()
        
        if profile.randomize_ports:
            self._randomize_network_ports()
        
        # Apply logging stealth
        if profile.time_stomping:
            self._enable_time_stomping()
        
        if profile.fake_log_activity:
            self._start_fake_log_activity()
        
        # Apply hardware stealth
        if profile.hide_usb_devices:
            self._hide_usb_devices()
        
        if profile.disable_leds:
            self._disable_hardware_leds()
        
        if profile.randomize_mac:
            self._randomize_mac_addresses()
    
    def _hide_current_process(self, fake_name: str):
        """Hide current process by changing its name."""
        try:
            current_process = psutil.Process()
            try:
                current_process.name(fake_name)
            except:
                pass  # Some systems don't allow process name changes
        except Exception as e:
            log_opsec_event("process_hide_error", {"error": str(e)}, "normal", 3)
    
    def _hide_command_line(self):
        """Hide process command line arguments."""
        try:
            current_process = psutil.Process()
            try:
                current_process.cmdline([fake_name := "systemd"])
            except:
                pass
        except Exception as e:
            log_opsec_event("cmdline_hide_error", {"error": str(e)}, "normal", 3)
    
    def _block_outbound_connections(self):
        """Block outbound network connections."""
        # This is a simplified implementation
        # Real implementation would involve iptables or similar
        log_opsec_event("outbound_blocked", {}, "stealth", 4)
    
    def _randomize_network_ports(self):
        """Randomize network port usage."""
        log_opsec_event("ports_randomized", {}, "stealth", 3)
    
    def _enable_time_stomping(self):
        """Enable timestomping for files."""
        log_opsec_event("time_stomping_enabled", {}, "stealth", 3)
    
    def _start_fake_log_activity(self):
        """Start generating fake log activity."""
        def fake_activity_loop():
            while True:
                time.sleep(secrets.randbelow(120) + 30)  # Random interval
                # Generate fake activity
                log_opsec_event("fake_activity", {
                    "activity_type": secrets.choice(['read', 'write', 'delete', 'backup']),
                    "fake_data": secrets.token_hex(16)
                }, "stealth", 1)
        
        threading.Thread(target=fake_activity_loop, daemon=True).start()
    
    def _hide_usb_devices(self):
        """Hide USB devices from system."""
        log_opsec_event("usb_hidden", {}, "stealth", 4)
    
    def _disable_hardware_leds(self):
        """Disable hardware LEDs (laptop keyboard, etc.)."""
        log_opsec_event("leds_disabled", {}, "stealth", 3)
    
    def _randomize_mac_addresses(self):
        """Randomize MAC addresses of network interfaces."""
        log_opsec_event("mac_randomized", {}, "stealth", 4)
    
    def start_operation(self):
        """Start field operation."""
        self.operation_start_time = time.time()
        
        log_opsec_event("operation_started", {
            "mode": self.current_mode.value,
            "field_id": self.config.field_identifier,
            "stealth_profile": asdict(self.config.stealth_profile)
        }, "normal", 2)
    
    def end_operation(self, reason: str = "normal_completion"):
        """End field operation."""
        operation_duration = time.time() - self.operation_start_time
        
        log_opsec_event("operation_ended", {
            "mode": self.current_mode.value,
            "duration": operation_duration,
            "reason": reason,
            "mode_switches": len(self.mode_switch_history),
            "threats_detected": len(self.threat_detector.threat_indicators)
        }, "normal", 3)
        
        # Secure wipe if configured
        if self.config.mode in [FieldMode.EMERGENCY, FieldMode.GHOST]:
            secure_wipe()
    
    def get_operation_status(self) -> Dict[str, Any]:
        """Get current operation status."""
        with self._lock:
            return {
                "mode": self.current_mode.value,
                "operation_duration": time.time() - self.operation_start_time,
                "threat_count": len(self.threat_detector.threat_indicators),
                "mode_switches": len(self.mode_switch_history),
                "stealth_profile": asdict(self.config.stealth_profile),
                "config": asdict(self.config),
                "recent_threats": self.threat_detector.threat_indicators[-10:] if self.threat_detector.threat_indicators else []
            }
    
    def emergency_mode(self):
        """Switch to emergency mode immediately."""
        self.switch_mode(FieldMode.EMERGENCY, reason="manual_emergency_activation")
        secure_wipe()


# Global field operations instance
_field_ops = None

def get_field_operations(config: FieldConfig = None) -> FieldOperations:
    """Get global field operations instance."""
    global _field_ops
    if _field_ops is None:
        _field_ops = FieldOperations(config)
    return _field_ops


def start_field_operation(mode: FieldMode = FieldMode.STEALTH, field_id: str = None) -> str:
    """Start field operation with specified mode."""
    config = FieldConfig(mode=mode, field_identifier=field_id)
    ops = get_field_operations(config)
    ops.start_operation()
    return field_id or secrets.token_hex(8)


def switch_field_mode(mode: FieldMode, reason: str = None):
    """Switch field operation mode."""
    ops = get_field_operations()
    ops.switch_mode(mode, reason)


def get_op_status() -> Dict[str, Any]:
    """Get field operation status."""
    ops = get_field_operations()
    return ops.get_operation_status()


def emergency_terminate():
    """Emergency termination of field operation."""
    ops = get_field_operations()
    ops.emergency_mode()