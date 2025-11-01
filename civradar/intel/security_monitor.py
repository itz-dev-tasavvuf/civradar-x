# civradar/intel/security_monitor.py
"""
Security Monitoring and Alerting System.
Provides comprehensive security breach detection and alerting for field operations.
"""

import os
import time
import json
import smtplib
import threading
import subprocess
import hashlib
import secrets
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import psutil
import socket

from .opsec_logger import get_opsec_logger, log_opsec_event

class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

class AlertCategory(Enum):
    """Alert categories."""
    SECURITY_BREACH = "security_breach"
    THREAT_DETECTION = "threat_detection"
    SYSTEM_COMPROMISE = "system_compromise"
    NETWORK_ANOMALY = "network_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    CONFIGURATION_CHANGE = "configuration_change"
    WIPE_OPERATION = "wipe_operation"
    ENCRYPTION_FAILURE = "encryption_failure"

@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_id: str
    category: AlertCategory
    severity: AlertSeverity
    title: str
    description: str
    timestamp: float
    source_ip: str
    process_info: Dict[str, Any]
    system_state: Dict[str, Any]
    recommended_action: str
    auto_response: bool = False
    escalation_level: int = 0
    resolved: bool = False

@dataclass
class AlertConfig:
    """Configuration for security monitoring."""
    enabled: bool = True
    monitoring_interval: int = 30  # seconds
    alert_retention_days: int = 30
    max_alerts_per_hour: int = 100
    auto_escalation: bool = True
    escalation_timeout: int = 300  # 5 minutes
    
    # Notification settings
    email_notifications: bool = False
    email_smtp_server: str = "localhost"
    email_smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_from: str = ""
    email_to: List[str] = None
    
    # Local alerting
    local_alerts: bool = True
    alert_log_file: str = "/var/log/civradar-x/security_alerts.log"
    alert_sound: bool = False
    
    # Automated responses
    auto_wipe_on_critical: bool = True
    auto_switch_to_stealth: bool = True
    auto_terminate_sessions: bool = False

class SecurityMonitor:
    """
    Comprehensive security monitoring system.
    """
    
    def __init__(self, config: AlertConfig = None):
        self.config = config or AlertConfig()
        self.active_alerts: Dict[str, SecurityAlert] = {}
        self.alert_history: List[SecurityAlert] = []
        self.monitoring_active = False
        self._lock = threading.Lock()
        
        # Load alert signatures and patterns
        self._load_threat_signatures()
        self._load_behavioral_baselines()
        
        # Initialize monitoring components
        self._init_process_monitor()
        self._init_network_monitor()
        self._init_system_monitor()
        self._init_behavioral_monitor()
        
        log_opsec_event("security_monitor_initialized", {
            "config": asdict(self.config),
            "monitoring_interval": self.config.monitoring_interval
        }, "normal", 2)
    
    def _load_threat_signatures(self):
        """Load threat detection signatures."""
        self.threat_signatures = {
            "suspicious_processes": [
                "wireshark", "tcpdump", "nmap", "masscan", "zmap",
                "volatility", "autopsy", "sleuthkit", "foremost",
                "netsniff-ng", "ettercap", "arpspoof", "dsniff",
                "aircrack-ng", "airodump-ng", "reaver", "wash"
            ],
            "suspicious_network_activity": [
                {"pattern": "大量连接", "threshold": 50},
                {"pattern": "端口扫描", "threshold": 100},
                {"pattern": "异常DNS查询", "threshold": 30}
            ],
            "file_system_threats": [
                "/etc/shadow", "/etc/passwd", "/var/log/auth.log",
                "/root", "/home/*/.ssh"
            ],
            "memory_threats": [
                {"pattern": "调试器", "indicators": ["ptrace", "strace"]},
                {"pattern": "内存分析", "indicators": ["gdb", "lldb"]}
            ]
        }
    
    def _load_behavioral_baselines(self):
        """Load behavioral baselines for anomaly detection."""
        self.behavioral_baselines = {
            "cpu_usage": {"mean": 20, "std": 10},
            "memory_usage": {"mean": 40, "std": 15},
            "network_connections": {"mean": 15, "std": 10},
            "process_count": {"mean": 150, "std": 30},
            "file_access_rate": {"mean": 10, "std": 5}
        }
    
    def _init_process_monitor(self):
        """Initialize process monitoring."""
        self.process_baseline = {}
        self.suspicious_processes_detected = []
    
    def _init_network_monitor(self):
        """Initialize network monitoring."""
        self.network_baseline = {}
        self.network_anomalies = []
    
    def _init_system_monitor(self):
        """Initialize system monitoring."""
        self.system_baseline = {}
        self.system_anomalies = []
    
    def _init_behavioral_monitor(self):
        """Initialize behavioral monitoring."""
        self.behavioral_samples = []
        self.anomaly_threshold = 2.5  # Standard deviations
    
    def start_monitoring(self):
        """Start security monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        
        # Start monitoring threads
        self._start_monitoring_threads()
        
        log_opsec_event("security_monitoring_started", {
            "interval": self.config.monitoring_interval
        }, "normal", 3)
    
    def stop_monitoring(self):
        """Stop security monitoring."""
        self.monitoring_active = False
        
        log_opsec_event("security_monitoring_stopped", {}, "normal", 2)
    
    def _start_monitoring_threads(self):
        """Start all monitoring threads."""
        monitoring_threads = [
            ("process_monitor", self._process_monitor_loop),
            ("network_monitor", self._network_monitor_loop),
            ("system_monitor", self._system_monitor_loop),
            ("behavioral_monitor", self._behavioral_monitor_loop),
            ("alert_processor", self._alert_processor_loop)
        ]
        
        for thread_name, thread_func in monitoring_threads:
            threading.Thread(target=thread_func, name=thread_name, daemon=True).start()
    
    def _process_monitor_loop(self):
        """Monitor for suspicious processes."""
        while self.monitoring_active:
            try:
                self._scan_processes()
                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                log_opsec_event("process_monitor_error", {"error": str(e)}, "normal", 4)
    
    def _network_monitor_loop(self):
        """Monitor network activity."""
        while self.monitoring_active:
            try:
                self._scan_network_activity()
                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                log_opsec_event("network_monitor_error", {"error": str(e)}, "normal", 4)
    
    def _system_monitor_loop(self):
        """Monitor system state."""
        while self.monitoring_active:
            try:
                self._scan_system_state()
                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                log_opsec_event("system_monitor_error", {"error": str(e)}, "normal", 4)
    
    def _behavioral_monitor_loop(self):
        """Monitor behavioral anomalies."""
        while self.monitoring_active:
            try:
                self._scan_behavioral_anomalies()
                time.sleep(self.config.monitoring_interval)
            except Exception as e:
                log_opsec_event("behavioral_monitor_error", {"error": str(e)}, "normal", 4)
    
    def _alert_processor_loop(self):
        """Process and dispatch alerts."""
        while self.monitoring_active:
            try:
                self._process_pending_alerts()
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                log_opsec_event("alert_processor_error", {"error": str(e)}, "normal", 4)
    
    def _scan_processes(self):
        """Scan for suspicious processes."""
        current_processes = set()
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    proc_info = proc.info
                    current_processes.add(proc_info['pid'])
                    
                    # Check against suspicious process signatures
                    if proc_info['name'].lower() in self.threat_signatures["suspicious_processes"]:
                        self._create_alert(
                            AlertCategory.SECURITY_BREACH,
                            AlertSeverity.HIGH,
                            "Suspicious Process Detected",
                            f"Suspicious process detected: {proc_info['name']} (PID: {proc_info['pid']})",
                            {"process": proc_info}
                        )
                    
                    # Check for processes running as root that shouldn't be
                    if proc_info['username'] == 'root':
                        proc_name = proc_info['name'].lower()
                        if any(suspicious in proc_name for suspicious in ['browser', 'editor', 'viewer']):
                            self._create_alert(
                                AlertCategory.SYSTEM_COMPROMISE,
                                AlertSeverity.MEDIUM,
                                "Root Process Anomaly",
                                f"Process {proc_info['name']} running as root: {proc_info['pid']}",
                                {"process": proc_info}
                            )
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Update baseline if this is early in monitoring
            if len(self.process_baseline) < 100:  # After collecting some samples
                self.process_baseline['active_processes'] = current_processes
                
        except Exception as e:
            log_opsec_event("process_scan_error", {"error": str(e)}, "normal", 3)
    
    def _scan_network_activity(self):
        """Scan for suspicious network activity."""
        try:
            connections = psutil.net_connections()
            connection_count = len(connections)
            
            # Check for excessive connections
            if connection_count > 100:
                self._create_alert(
                    AlertCategory.NETWORK_ANOMALY,
                    AlertSeverity.MEDIUM,
                    "Excessive Network Connections",
                    f"High number of network connections detected: {connection_count}",
                    {"connection_count": connection_count, "connections": len(connections)}
                )
            
            # Check for suspicious ports
            suspicious_ports = [22, 23, 25, 110, 143, 993, 995]  # Common monitoring ports
            for conn in connections:
                if conn.laddr and conn.raddr:
                    if conn.raddr.port in suspicious_ports:
                        self._create_alert(
                            AlertCategory.NETWORK_ANOMALY,
                            AlertSeverity.MEDIUM,
                            "Suspicious Network Port",
                            f"Connection to suspicious port {conn.raddr.port}: {conn.raddr.ip}",
                            {"connection": str(conn)}
                        )
            
            # Check for many connections from same IP
            connections_by_ip = {}
            for conn in connections:
                if conn.raddr:
                    ip = conn.raddr.ip
                    connections_by_ip[ip] = connections_by_ip.get(ip, 0) + 1
            
            for ip, count in connections_by_ip.items():
                if count > 20:  # Many connections from same IP
                    self._create_alert(
                        AlertCategory.NETWORK_ANOMALY,
                        AlertSeverity.HIGH,
                        "Potential Network Surveillance",
                        f"Multiple connections from single IP: {ip} ({count} connections)",
                        {"suspicious_ip": ip, "connection_count": count}
                    )
            
        except Exception as e:
            log_opsec_event("network_scan_error", {"error": str(e)}, "normal", 3)
    
    def _scan_system_state(self):
        """Scan system state for anomalies."""
        try:
            # CPU usage anomaly
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                self._create_alert(
                    AlertCategory.SYSTEM_COMPROMISE,
                    AlertSeverity.MEDIUM,
                    "High CPU Usage",
                    f"System CPU usage: {cpu_percent}%",
                    {"cpu_percent": cpu_percent}
                )
            
            # Memory usage anomaly
            memory = psutil.virtual_memory()
            if memory.percent > 95:
                self._create_alert(
                    AlertCategory.SYSTEM_COMPROMISE,
                    AlertSeverity.HIGH,
                    "High Memory Usage",
                    f"System memory usage: {memory.percent}%",
                    {"memory_percent": memory.percent, "available_gb": memory.available / (1024**3)}
                )
            
            # Disk usage anomaly
            disk_usage = psutil.disk_usage('/')
            if (disk_usage.used / disk_usage.total) > 0.95:
                self._create_alert(
                    AlertCategory.SYSTEM_COMPROMISE,
                    AlertSeverity.MEDIUM,
                    "High Disk Usage",
                    f"Disk usage: {(disk_usage.used / disk_usage.total) * 100:.1f}%",
                    {"disk_usage_percent": (disk_usage.used / disk_usage.total) * 100}
                )
            
            # Check for new files in sensitive directories
            sensitive_dirs = ['/etc', '/var/log', '/tmp', '/var/tmp']
            for dir_path in sensitive_dirs:
                try:
                    files = list(Path(dir_path).glob('*'))
                    recent_files = [f for f in files if time.time() - f.stat().st_mtime < 300]  # Last 5 minutes
                    if len(recent_files) > 10:  # Too many new files
                        self._create_alert(
                            AlertCategory.FILE_SYSTEM_THREATS,
                            AlertSeverity.LOW,
                            "Unusual File Activity",
                            f"Many new files in {dir_path}: {len(recent_files)}",
                            {"directory": dir_path, "recent_files": len(recent_files)}
                        )
                except (PermissionError, FileNotFoundError):
                    continue
            
        except Exception as e:
            log_opsec_event("system_scan_error", {"error": str(e)}, "normal", 3)
    
    def _scan_behavioral_anomalies(self):
        """Scan for behavioral anomalies."""
        try:
            # Collect current metrics
            current_metrics = {
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "network_connections": len(psutil.net_connections()),
                "process_count": len(psutil.pids())
            }
            
            self.behavioral_samples.append({
                "timestamp": time.time(),
                "metrics": current_metrics
            })
            
            # Keep only recent samples (last 100)
            if len(self.behavioral_samples) > 100:
                self.behavioral_samples = self.behavioral_samples[-100:]
            
            # Check for anomalies if we have enough samples
            if len(self.behavioral_samples) >= 10:
                self._detect_behavioral_anomalies(current_metrics)
            
        except Exception as e:
            log_opsec_event("behavioral_scan_error", {"error": str(e)}, "normal", 3)
    
    def _detect_behavioral_anomalies(self, current_metrics: Dict[str, float]):
        """Detect behavioral anomalies using statistical analysis."""
        import statistics
        
        for metric_name, current_value in current_metrics.items():
            # Get historical values for this metric
            historical_values = [sample["metrics"][metric_name] for sample in self.behavioral_samples]
            
            if len(historical_values) >= 10:
                mean = statistics.mean(historical_values)
                stdev = statistics.stdev(historical_values) if len(historical_values) > 1 else 1
                
                # Check for anomaly (beyond threshold standard deviations)
                z_score = abs(current_value - mean) / stdev if stdev > 0 else 0
                
                if z_score > self.anomaly_threshold:
                    severity = AlertSeverity.HIGH if z_score > 3.0 else AlertSeverity.MEDIUM
                    
                    self._create_alert(
                        AlertCategory.BEHAVIORAL_ANOMALY,
                        severity,
                        "Behavioral Anomaly Detected",
                        f"Anomaly in {metric_name}: current={current_value:.2f}, baseline={mean:.2f} (z-score: {z_score:.2f})",
                        {
                            "metric": metric_name,
                            "current_value": current_value,
                            "baseline_mean": mean,
                            "baseline_std": stdev,
                            "z_score": z_score
                        }
                    )
    
    def _create_alert(self, category: AlertCategory, severity: AlertSeverity,
                     title: str, description: str, additional_data: Dict[str, Any] = None):
        """Create security alert."""
        if not self.config.enabled:
            return
        
        # Check rate limiting
        if self._is_rate_limited():
            return
        
        alert_id = secrets.token_hex(16)
        source_ip = self._get_source_ip()
        
        # Get current process and system information
        try:
            current_proc = psutil.Process()
            process_info = {
                "pid": current_proc.pid,
                "name": current_proc.name(),
                "cmdline": current_proc.cmdline()
            }
        except:
            process_info = {}
        
        system_state = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_connections": len(psutil.net_connections())
        }
        
        alert = SecurityAlert(
            alert_id=alert_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            timestamp=time.time(),
            source_ip=source_ip,
            process_info=process_info,
            system_state=system_state,
            recommended_action=self._get_recommended_action(category, severity),
            auto_response=self._should_auto_respond(severity)
        )
        
        # Store alert
        with self._lock:
            self.active_alerts[alert_id] = alert
            self.alert_history.append(alert)
            
            # Trim old alerts
            cutoff_time = time.time() - (self.config.alert_retention_days * 24 * 3600)
            self.alert_history = [a for a in self.alert_history if a.timestamp > cutoff_time]
        
        # Log alert
        log_opsec_event("security_alert_created", {
            "alert_id": alert_id[:8] + "...",  # Partial ID for security
            "category": category.value,
            "severity": severity.value,
            "title": title
        }, "normal", severity.value)
        
        # Dispatch alert
        self._dispatch_alert(alert)
        
        # Execute automated response if configured
        if alert.auto_response:
            self._execute_auto_response(alert)
    
    def _get_source_ip(self) -> str:
        """Get source IP address."""
        try:
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except:
            return "127.0.0.1"
    
    def _get_recommended_action(self, category: AlertCategory, severity: AlertSeverity) -> str:
        """Get recommended action for alert."""
        actions = {
            (AlertCategory.SECURITY_BREACH, AlertSeverity.CRITICAL): "Immediate system lockdown and data wipe",
            (AlertCategory.THREAT_DETECTION, AlertSeverity.HIGH): "Activate stealth mode and enhance monitoring",
            (AlertCategory.SYSTEM_COMPROMISE, AlertSeverity.MEDIUM): "Review system integrity and logs",
            (AlertCategory.NETWORK_ANOMALY, AlertSeverity.LOW): "Monitor network activity closely",
            (AlertCategory.BEHAVIORAL_ANOMALY, AlertSeverity.MEDIUM): "Investigate unusual system behavior"
        }
        
        return actions.get((category, severity), "Monitor and assess situation")
    
    def _should_auto_respond(self, severity: AlertSeverity) -> bool:
        """Determine if automated response should be triggered."""
        return severity in [AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]
    
    def _is_rate_limited(self) -> bool:
        """Check if alerts are rate limited."""
        current_time = time.time()
        one_hour_ago = current_time - 3600
        
        # Count alerts in last hour
        recent_alerts = [
            alert for alert in self.alert_history 
            if alert.timestamp > one_hour_ago
        ]
        
        return len(recent_alerts) >= self.config.max_alerts_per_hour
    
    def _dispatch_alert(self, alert: SecurityAlert):
        """Dispatch alert to configured notification channels."""
        # Local logging
        if self.config.local_alerts:
            self._log_alert_locally(alert)
        
        # Email notification
        if self.config.email_notifications:
            threading.Thread(target=self._send_email_alert, args=(alert,), daemon=True).start()
        
        # Sound alert
        if self.config.alert_sound:
            self._play_alert_sound(alert)
    
    def _log_alert_locally(self, alert: SecurityAlert):
        """Log alert to local file."""
        try:
            log_entry = {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp,
                "category": alert.category.value,
                "severity": alert.severity.value,
                "title": alert.title,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "recommended_action": alert.recommended_action
            }
            
            log_line = json.dumps(log_entry, indent=2)
            
            # Append to log file
            with open(self.config.alert_log_file, 'a') as f:
                f.write(log_line + '\n')
                
        except Exception as e:
            log_opsec_event("alert_log_error", {"error": str(e)}, "normal", 4)
    
    def _send_email_alert(self, alert: SecurityAlert):
        """Send alert via email."""
        if not all([self.config.email_from, self.config.email_to, self.config.email_smtp_server]):
            return
        
        try:
            msg = MimeMultipart()
            msg['From'] = self.config.email_from
            msg['To'] = ', '.join(self.config.email_to)
            msg['Subject'] = f"[CIVRADAR-X] {alert.severity.value.upper()}: {alert.title}"
            
            body = f"""
            Security Alert from CIVRADAR-X
            
            Alert ID: {alert.alert_id}
            Category: {alert.category.value}
            Severity: {alert.severity.value}
            Title: {alert.title}
            Description: {alert.description}
            
            Source IP: {alert.source_ip}
            Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp))}
            
            Recommended Action: {alert.recommended_action}
            
            System State:
            - CPU Usage: {alert.system_state.get('cpu_percent', 'N/A')}%
            - Memory Usage: {alert.system_state.get('memory_percent', 'N/A')}%
            - Disk Usage: {alert.system_state.get('disk_usage', 'N/A')}%
            - Network Connections: {alert.system_state.get('network_connections', 'N/A')}
            
            This is an automated security alert from CIVRADAR-X field operations system.
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.config.email_smtp_server, self.config.email_smtp_port)
            server.starttls()
            if self.config.email_username and self.config.email_password:
                server.login(self.config.email_username, self.config.email_password)
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            log_opsec_event("email_alert_error", {"error": str(e)}, "normal", 5)
    
    def _play_alert_sound(self, alert: SecurityAlert):
        """Play alert sound based on severity."""
        try:
            if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]:
                # Critical alert - multiple beeps
                for _ in range(3):
                    os.system('echo -e "\a"')  # Bell character
                    time.sleep(0.5)
            elif alert.severity == AlertSeverity.HIGH:
                # High severity - double beep
                for _ in range(2):
                    os.system('echo -e "\a"')
                    time.sleep(0.3)
            else:
                # Lower severity - single beep
                os.system('echo -e "\a"')
                
        except Exception:
            pass  # Ignore sound errors
    
    def _execute_auto_response(self, alert: SecurityAlert):
        """Execute automated response to alert."""
        try:
            if alert.severity == AlertSeverity.EMERGENCY:
                # Emergency response
                log_opsec_event("auto_emergency_response", {
                    "alert_id": alert.alert_id,
                    "action": "emergency_wipe_all"
                }, "emergency", 10)
                
                # Import emergency wipe function
                from .secure_wiper import emergency_wipe_all
                emergency_wipe_all()
                
            elif alert.severity == AlertSeverity.CRITICAL:
                # Critical response
                log_opsec_event("auto_critical_response", {
                    "alert_id": alert.alert_id,
                    "action": "switch_to_stealth"
                }, "emergency", 9)
                
                # Switch to stealth mode
                from .field_ops import switch_field_mode, FieldMode
                switch_field_mode(FieldMode.GHOST, "auto_critical_response")
                
        except Exception as e:
            log_opsec_event("auto_response_error", {
                "alert_id": alert.alert_id,
                "error": str(e)
            }, "normal", 7)
    
    def _process_pending_alerts(self):
        """Process pending alerts (escalation, etc.)."""
        current_time = time.time()
        
        with self._lock:
            for alert_id, alert in list(self.active_alerts.items()):
                # Check for escalation
                if (self.config.auto_escalation and 
                    not alert.resolved and 
                    current_time - alert.timestamp > self.config.escalation_timeout):
                    
                    self._escalate_alert(alert)
                    
                    # Mark as resolved to avoid repeated escalation
                    alert.resolved = True
        
        # Clean up old active alerts
        cutoff_time = current_time - 3600  # 1 hour
        old_alerts = [
            alert_id for alert_id, alert in self.active_alerts.items()
            if alert.timestamp < cutoff_time
        ]
        
        for alert_id in old_alerts:
            del self.active_alerts[alert_id]
    
    def _escalate_alert(self, alert: SecurityAlert):
        """Escalate alert to higher level."""
        alert.escalation_level += 1
        
        log_opsec_event("alert_escalated", {
            "alert_id": alert.alert_id,
            "escalation_level": alert.escalation_level,
            "original_severity": alert.severity.value
        }, "normal", 6)
        
        # Increase severity if not already at emergency
        if alert.severity != AlertSeverity.EMERGENCY:
            severity_map = {
                AlertSeverity.LOW: AlertSeverity.MEDIUM,
                AlertSeverity.MEDIUM: AlertSeverity.HIGH,
                AlertSeverity.HIGH: AlertSeverity.CRITICAL,
                AlertSeverity.CRITICAL: AlertSeverity.EMERGENCY
            }
            
            new_severity = severity_map.get(alert.severity, AlertSeverity.EMERGENCY)
            alert.severity = new_severity
            
            # Re-dispatch with new severity
            self._dispatch_alert(alert)
    
    def resolve_alert(self, alert_id: str):
        """Mark alert as resolved."""
        with self._lock:
            if alert_id in self.active_alerts:
                self.active_alerts[alert_id].resolved = True
        
        log_opsec_event("alert_resolved", {"alert_id": alert_id}, "normal", 3)
    
    def get_alerts(self, category: AlertCategory = None, 
                   severity: AlertSeverity = None, 
                   unresolved_only: bool = False) -> List[SecurityAlert]:
        """Get alerts based on criteria."""
        with self._lock:
            alerts = list(self.active_alerts.values())
            
            if category:
                alerts = [a for a in alerts if a.category == category]
            
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            if unresolved_only:
                alerts = [a for a in alerts if not a.resolved]
            
            return sorted(alerts, key=lambda x: x.timestamp, reverse=True)
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics."""
        with self._lock:
            total_alerts = len(self.alert_history)
            active_alerts = len([a for a in self.active_alerts.values() if not a.resolved])
            
            # Count by severity
            severity_counts = {}
            for severity in AlertSeverity:
                severity_counts[severity.value] = len([
                    a for a in self.alert_history if a.severity == severity
                ])
            
            # Count by category
            category_counts = {}
            for category in AlertCategory:
                category_counts[category.value] = len([
                    a for a in self.alert_history if a.category == category
                ])
            
            return {
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "monitoring_active": self.monitoring_active,
                "severity_distribution": severity_counts,
                "category_distribution": category_counts,
                "config": asdict(self.config)
            }


# Global security monitor instance
_security_monitor = None

def get_security_monitor(config: AlertConfig = None) -> SecurityMonitor:
    """Get global security monitor instance."""
    global _security_monitor
    if _security_monitor is None:
        _security_monitor = SecurityMonitor(config)
    return _security_monitor


def start_security_monitoring(config: AlertConfig = None):
    """Start security monitoring."""
    monitor = get_security_monitor(config)
    monitor.start_monitoring()
    return monitor


def get_security_alerts(category: AlertCategory = None, 
                       severity: AlertSeverity = None) -> List[SecurityAlert]:
    """Get security alerts."""
    monitor = get_security_monitor()
    return monitor.get_alerts(category, severity)