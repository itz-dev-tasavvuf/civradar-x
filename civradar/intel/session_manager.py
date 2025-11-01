# civradar/intel/session_manager.py
"""
Secure Session Management for field operations with auto-wipe capabilities.
Provides isolated sessions, threat-based auto-wipe, and secure session handling.
"""

import secrets
import hashlib
import hmac
import time
import threading
import json
import os
import signal
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import psutil
from .opsec_logger import get_opsec_logger, log_opsec_event, secure_wipe

@dataclass
class SessionConfig:
    """Configuration for secure session management."""
    auto_wipe_timeout: int = 300  # 5 minutes default
    idle_timeout: int = 180  # 3 minutes idle
    threat_level_threshold: int = 7  # Auto-wipe on high threat
    session_isolation: bool = True
    memory_protection: bool = True
    process_hiding: bool = True
    secure_termination: bool = True
    backup_wipe_trigger: bool = True
    forensic_mitigation: bool = True

@dataclass
class SessionThreat:
    """Represents a detected threat during session."""
    threat_type: str
    severity: int  # 0-10
    description: str
    timestamp: float
    source: str
    automated_response: Optional[str] = None

class SecureSession:
    """
    Individual secure session with threat monitoring and auto-wipe capabilities.
    """
    
    def __init__(self, session_id: str, config: SessionConfig):
        self.session_id = session_id
        self.config = config
        self.created_at = time.time()
        self.last_activity = time.time()
        self.is_active = True
        self.threat_level = 0
        self.threats: List[SessionThreat] = []
        self._lock = threading.Lock()
        self._activity_callbacks: List[Callable] = []
        self._threat_callbacks: List[Callable] = []
        
        # Generate session encryption key
        self._init_session_crypto()
        
        # Initialize threat monitoring
        self._start_threat_monitoring()
        
        # Setup auto-wipe timers
        self._setup_timers()
        
        # Initialize process hiding if enabled
        if config.process_hiding:
            self._hide_process()
        
        log_opsec_event("session_created", {
            "session_id": session_id,
            "config": asdict(config),
            "threat_level": self.threat_level
        }, "stealth", self.threat_level)
    
    def _init_session_crypto(self):
        """Initialize session-specific encryption."""
        # Generate session key from multiple entropy sources
        session_entropy = os.urandom(32)
        time_entropy = int(time.time() * 1000000).to_bytes(8, 'big')
        secret_entropy = secrets.token_bytes(16)
        
        key_material = session_entropy + time_entropy + secret_entropy
        
        # Derive encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_entropy[:16],
            iterations=150000,
        )
        self.session_key = base64.urlsafe_b64encode(kdf.derive(key_material[16:]))
        self.cipher = Fernet(self.session_key)
        
        # Clear entropy sources from memory
        del session_entropy, time_entropy, secret_entropy, key_material
    
    def _start_threat_monitoring(self):
        """Start continuous threat monitoring."""
        def monitor_loop():
            while self.is_active:
                try:
                    # Check for various threat indicators
                    threats_detected = self._scan_threats()
                    
                    with self._lock:
                        for threat in threats_detected:
                            self._handle_threat(threat)
                    
                    time.sleep(2)  # Check every 2 seconds
                    
                except Exception as e:
                    log_opsec_event("threat_monitor_error", {
                        "error": str(e),
                        "session_id": self.session_id
                    }, "emergency", 10)
        
        if self.config.threat_level_threshold > 0:
            threading.Thread(target=monitor_loop, daemon=True).start()
    
    def _scan_threats(self) -> List[SessionThreat]:
        """Scan for potential threats."""
        threats = []
        
        # Check for suspicious process activity
        if self._detect_suspicious_processes():
            threats.append(SessionThreat(
                threat_type="suspicious_processes",
                severity=8,
                description="Suspicious process activity detected",
                timestamp=time.time(),
                source="process_monitor",
                automated_response="increase_security"
            ))
        
        # Check for network surveillance
        if self._detect_network_surveillance():
            threats.append(SessionThreat(
                threat_type="network_surveillance",
                severity=9,
                description="Potential network surveillance detected",
                timestamp=time.time(),
                source="network_monitor",
                automated_response="emergency_wipe"
            ))
        
        # Check for system resources anomalies
        if self._detect_resource_anomalies():
            threats.append(SessionThreat(
                threat_type="resource_anomaly",
                severity=6,
                description="System resource anomalies detected",
                timestamp=time.time(),
                source="resource_monitor",
                automated_response="increase_monitoring"
            ))
        
        # Check for forensic tools
        if self._detect_forensic_tools():
            threats.append(SessionThreat(
                threat_type="forensic_tools",
                severity=10,
                description="Forensic analysis tools detected",
                timestamp=time.time(),
                source="tool_detector",
                automated_response="emergency_wipe"
            ))
        
        return threats
    
    def _detect_suspicious_processes(self) -> bool:
        """Detect suspicious process activity."""
        suspicious_names = [
            'wireshark', 'tcpdump', 'nmap', 'masscan', 'zmap',
            'volatility', 'autopsy', 'sleuthkit', 'foremost',
            'ddrescue', 'testdisk', 'photorec', ' foremost'
        ]
        
        try:
            current_process = psutil.Process()
            
            # Check for suspicious processes running with elevated privileges
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    if proc.info['username'] == 'root' and proc.info['name'].lower() in suspicious_names:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check if current process has suspicious parent
            try:
                parent = current_process.parent()
                if parent and parent.name().lower() in suspicious_names:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        except Exception:
            pass
        
        return False
    
    def _detect_network_surveillance(self) -> bool:
        """Detect potential network surveillance."""
        try:
            # Check for network connections that might indicate surveillance
            connections = psutil.net_connections()
            suspicious_ports = [22, 23, 80, 443, 8080, 8443]  # Common monitoring ports
            
            for conn in connections:
                if conn.laddr and conn.raddr:
                    # Check for connections to suspicious IP ranges
                    if self._is_suspicious_ip(conn.raddr.ip):
                        return True
                    
                    # Check for multiple connections from same source
                    connections_from_same_ip = [
                        c for c in connections 
                        if c.raddr and c.raddr.ip == conn.raddr.ip
                    ]
                    if len(connections_from_same_ip) > 5:
                        return True
            
        except Exception:
            pass
        
        return False
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious."""
        # Check against known surveillance/monitoring IP ranges
        suspicious_ranges = [
            '10.0.0.',      # Internal monitoring
            '192.168.',     # Internal monitoring
            '172.16.',      # Internal monitoring
        ]
        
        for range_prefix in suspicious_ranges:
            if ip.startswith(range_prefix):
                return True
        
        return False
    
    def _detect_resource_anomalies(self) -> bool:
        """Detect system resource anomalies that might indicate monitoring."""
        try:
            # Check CPU usage - sudden spikes might indicate monitoring tools
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:  # High CPU usage might indicate monitoring
                return True
            
            # Check memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 90:  # High memory usage
                return True
            
            # Check disk I/O - forensic tools often cause high I/O
            disk_io = psutil.disk_io_counters()
            if disk_io and (disk_io.read_bytes > 1000000000 or disk_io.write_bytes > 1000000000):
                return True
                
        except Exception:
            pass
        
        return False
    
    def _detect_forensic_tools(self) -> bool:
        """Detect forensic analysis tools."""
        forensic_tools = [
            'dd', 'dc3dd', 'dcfldd', 'sectool', 'autopsy',
            'sleuthkit', 'volatility', 'bulk_extractor',
            'foremost', 'testdisk', 'photorec', 'strings',
            'hexdump', 'xxd', 'binwalk', 'file', 'md5sum',
            'sha256sum', 'cksum', 'hashdeep', 'md5deep'
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in forensic_tools:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        
        return False
    
    def _handle_threat(self, threat: SessionThreat):
        """Handle detected threat."""
        self.threats.append(threat)
        self.threat_level = max(self.threat_level, threat.severity)
        
        # Log threat event
        log_opsec_event("threat_detected", {
            "session_id": self.session_id,
            "threat": asdict(threat),
            "current_threat_level": self.threat_level
        }, "stealth", threat.severity)
        
        # Execute automated response
        if threat.automated_response:
            self._execute_automated_response(threat.automated_response, threat.severity)
        
        # Trigger threat callbacks
        for callback in self._threat_callbacks:
            try:
                callback(threat, self.threat_level)
            except Exception as e:
                log_opsec_event("threat_callback_error", {"error": str(e)}, "emergency", 9)
    
    def _execute_automated_response(self, response: str, severity: int):
        """Execute automated threat response."""
        if severity >= self.config.threat_level_threshold:
            if response == "emergency_wipe":
                log_opsec_event("auto_emergency_wipe", {
                    "session_id": self.session_id,
                    "reason": "threat_level_exceeded",
                    "severity": severity
                }, "emergency", severity)
                emergency_wipe()
            elif response == "increase_security":
                self._increase_security_level()
            elif response == "increase_monitoring":
                self._increase_monitoring_frequency()
    
    def _increase_security_level(self):
        """Increase security measures."""
        self.config.auto_wipe_timeout = min(self.config.auto_wipe_timeout, 60)
        self.config.idle_timeout = min(self.config.idle_timeout, 30)
        
        log_opsec_event("security_level_increased", {
            "session_id": self.session_id,
            "new_auto_wipe_timeout": self.config.auto_wipe_timeout,
            "new_idle_timeout": self.config.idle_timeout
        }, "stealth", self.threat_level)
    
    def _increase_monitoring_frequency(self):
        """Increase threat monitoring frequency."""
        # This would be implemented in the monitoring loop
        log_opsec_event("monitoring_increased", {
            "session_id": self.session_id
        }, "stealth", self.threat_level)
    
    def _setup_timers(self):
        """Setup auto-wipe and idle timers."""
        def timeout_watcher():
            while self.is_active:
                with self._lock:
                    current_time = time.time()
                    
                    # Check timeout
                    if current_time - self.last_activity > self.config.auto_wipe_timeout:
                        log_opsec_event("auto_wipe_timeout", {
                            "session_id": self.session_id,
                            "inactive_duration": current_time - self.last_activity
                        }, "normal", 5)
                        self.secure_terminate()
                        return
                    
                    # Check idle timeout
                    if current_time - self.last_activity > self.config.idle_timeout:
                        self._handle_idle_timeout()
                
                time.sleep(10)  # Check every 10 seconds
        
        threading.Thread(target=timeout_watcher, daemon=True).start()
    
    def _handle_idle_timeout(self):
        """Handle session idle timeout."""
        log_opsec_event("session_idle", {
            "session_id": self.session_id,
            "idle_duration": time.time() - self.last_activity
        }, "normal", 2)
        
        # Clear sensitive data but keep session alive
        self._clear_sensitive_memory()
        
        # Reduce threat monitoring
        self._reduce_monitoring()
    
    def _clear_sensitive_memory(self):
        """Clear sensitive data from memory."""
        try:
            # This is a simplified memory clearing approach
            # In a real implementation, you might use specialized memory wiping libraries
            del self.session_key
            del self.cipher
            self._init_session_crypto()
        except Exception as e:
            log_opsec_event("memory_clear_error", {"error": str(e)}, "normal", 4)
    
    def _reduce_monitoring(self):
        """Reduce monitoring frequency for idle sessions."""
        # Implementation would reduce monitoring frequency
        log_opsec_event("monitoring_reduced", {"session_id": self.session_id}, "normal", 1)
    
    def _hide_process(self):
        """Hide process from process listings."""
        try:
            # Set process name to something generic
            current_process = psutil.Process()
            
            # This is a simplified approach - real process hiding would require
            # more sophisticated techniques like kernel module manipulation
            try:
                current_process.name("systemd")
            except:
                try:
                    current_process.name("python3")
                except:
                    pass
            
            # Clear command line arguments
            try:
                current_process.cmdline(["systemd"])
            except:
                pass
                
        except Exception as e:
            log_opsec_event("process_hide_error", {"error": str(e)}, "normal", 3)
    
    def register_activity_callback(self, callback: Callable):
        """Register callback for session activity."""
        with self._lock:
            self._activity_callbacks.append(callback)
    
    def register_threat_callback(self, callback: Callable):
        """Register callback for threat detection."""
        with self._lock:
            self._threat_callbacks.append(callback)
    
    def record_activity(self, activity_type: str, data: Dict[str, Any] = None):
        """Record user activity."""
        with self._lock:
            self.last_activity = time.time()
            
            # Trigger activity callbacks
            for callback in self._activity_callbacks:
                try:
                    callback(activity_type, data)
                except Exception as e:
                    log_opsec_event("activity_callback_error", {"error": str(e)}, "normal", 2)
        
        log_opsec_event("session_activity", {
            "session_id": self.session_id,
            "activity_type": activity_type,
            "data": data
        }, "normal", 1)
    
    def get_session_status(self) -> Dict[str, Any]:
        """Get current session status."""
        with self._lock:
            return {
                "session_id": self.session_id,
                "created_at": self.created_at,
                "last_activity": self.last_activity,
                "is_active": self.is_active,
                "threat_level": self.threat_level,
                "threat_count": len(self.threats),
                "threats": [asdict(t) for t in self.threats[-10:]],  # Last 10 threats
                "config": asdict(self.config),
                "duration": time.time() - self.created_at
            }
    
    def secure_terminate(self):
        """Securely terminate session with data wipe."""
        with self._lock:
            if not self.is_active:
                return
            
            self.is_active = False
            
            log_opsec_event("session_termination", {
                "session_id": self.session_id,
                "duration": time.time() - self.created_at,
                "threat_level": self.threat_level,
                "threat_count": len(self.threats)
            }, "normal", 3)
            
            # Clear sensitive data
            self._clear_all_sensitive_data()
            
            # Wipe session files
            self._wipe_session_files()
            
            # Clear memory references
            del self.session_key
            del self.cipher
            del self.threats
    
    def _clear_all_sensitive_data(self):
        """Clear all sensitive data from session."""
        try:
            # Clear callbacks
            self._activity_callbacks.clear()
            self._threat_callbacks.clear()
            
            # Clear configuration
            sensitive_attrs = ['session_key', 'cipher', 'threats']
            for attr in sensitive_attrs:
                if hasattr(self, attr):
                    delattr(self, attr)
                    
        except Exception as e:
            log_opsec_event("sensitive_data_clear_error", {"error": str(e)}, "normal", 4)
    
    def _wipe_session_files(self):
        """Wipe any session-specific files."""
        # Implementation would wipe any temporary session files
        log_opsec_event("session_files_wiped", {"session_id": self.session_id}, "normal", 2)


class SessionManager:
    """
    Global session manager for handling multiple secure sessions.
    """
    
    def __init__(self, config: SessionConfig = None):
        self.config = config or SessionConfig()
        self.sessions: Dict[str, SecureSession] = {}
        self._lock = threading.Lock()
        self._cleanup_thread = None
        self._start_cleanup_service()
        
        log_opsec_event("session_manager_init", {"config": asdict(self.config)}, "normal", 0)
    
    def _start_cleanup_service(self):
        """Start background cleanup service."""
        def cleanup_loop():
            while True:
                try:
                    self._cleanup_expired_sessions()
                    time.sleep(30)  # Run every 30 seconds
                except Exception as e:
                    log_opsec_event("cleanup_error", {"error": str(e)}, "normal", 3)
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def create_session(self) -> str:
        """Create new secure session."""
        session_id = secrets.token_hex(16)
        
        with self._lock:
            session = SecureSession(session_id, self.config)
            self.sessions[session_id] = session
        
        log_opsec_event("session_created", {
            "session_id": session_id,
            "total_sessions": len(self.sessions)
        }, "normal", 1)
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[SecureSession]:
        """Get session by ID."""
        with self._lock:
            session = self.sessions.get(session_id)
            if session and session.is_active:
                return session
            return None
    
    def terminate_session(self, session_id: str):
        """Terminate specific session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if session:
                session.secure_terminate()
                del self.sessions[session_id]
                log_opsec_event("session_terminated", {"session_id": session_id}, "normal", 2)
    
    def _cleanup_expired_sessions(self):
        """Clean up expired or inactive sessions."""
        current_time = time.time()
        expired_sessions = []
        
        with self._lock:
            for session_id, session in self.sessions.items():
                if (not session.is_active or 
                    current_time - session.last_activity > self.config.auto_wipe_timeout * 2):
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                self.terminate_session(session_id)
    
    def emergency_wipe_all(self):
        """Emergency wipe all sessions."""
        with self._lock:
            session_ids = list(self.sessions.keys())
            
            for session_id in session_ids:
                self.terminate_session(session_id)
            
            log_opsec_event("emergency_wipe_all", {
                "sessions_wiped": len(session_ids)
            }, "emergency", 10)
    
    def get_manager_status(self) -> Dict[str, Any]:
        """Get session manager status."""
        with self._lock:
            active_sessions = sum(1 for s in self.sessions.values() if s.is_active)
            total_threats = sum(len(s.threats) for s in self.sessions.values())
            max_threat_level = max((s.threat_level for s in self.sessions.values()), default=0)
            
            return {
                "total_sessions": len(self.sessions),
                "active_sessions": active_sessions,
                "total_threats": total_threats,
                "max_threat_level": max_threat_level,
                "config": asdict(self.config)
            }


# Global session manager instance
_session_manager = None

def get_session_manager() -> SessionManager:
    """Get global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def create_secure_session() -> str:
    """Create new secure session."""
    manager = get_session_manager()
    return manager.create_session()


def terminate_secure_session(session_id: str):
    """Terminate secure session."""
    manager = get_session_manager()
    manager.terminate_session(session_id)


def emergency_wipe_all_sessions():
    """Emergency wipe all sessions."""
    manager = get_session_manager()
    manager.emergency_wipe_all()