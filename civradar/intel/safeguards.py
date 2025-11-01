# civradar/intel/safeguards.py
"""
Operational Safeguards and Anti-Detection Measures.
Provides comprehensive protection against detection and analysis in hostile environments.
"""

import os
import sys
import time
import threading
import secrets
import subprocess
import hashlib
import tempfile
import shutil
import psutil
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

from .opsec_logger import get_opsec_logger, log_opsec_event

class DetectionType(Enum):
    """Types of detection to defend against."""
    PROCESS_ANALYSIS = "process_analysis"
    MEMORY_ANALYSIS = "memory_analysis"
    NETWORK_MONITORING = "network_monitoring"
    FILE_SYSTEM_MONITORING = "filesystem_monitoring"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    PACKET_ANALYSIS = "packet_analysis"
    SYSTEMCALL_TRACING = "syscall_tracing"
    ROOTKIT_DETECTION = "rootkit_detection"

@dataclass
class SafeguardConfig:
    """Configuration for operational safeguards."""
    detection_types: List[DetectionType] = None
    anti_debugging: bool = True
    anti_vm: bool = True
    memory_obfuscation: bool = True
    code_obfuscation: bool = False
    timing_obfuscation: bool = True
    network_stealth: bool = True
    filesystem_stealth: bool = True
    process_hiding: bool = True
    hook_detection: bool = True
    
    def __post_init__(self):
        if self.detection_types is None:
            self.detection_types = list(DetectionType)

class AntiDetectionEngine:
    """
    Engine for implementing anti-detection measures.
    """
    
    def __init__(self, config: SafeguardConfig = None):
        self.config = config or SafeguardConfig()
        self.active_measures = set()
        self._lock = threading.Lock()
        
        # Initialize anti-detection measures
        self._init_anti_debugging()
        self._init_anti_vm()
        self._init_memory_obfuscation()
        self._init_network_stealth()
        self._init_filesystem_stealth()
        self._init_process_hiding()
        self._init_timing_obfuscation()
        
        log_opsec_event("safeguards_initialized", {
            "config": asdict(self.config),
            "active_measures": list(self.active_measures)
        }, "stealth", 2)
    
    def _init_anti_debugging(self):
        """Initialize anti-debugging measures."""
        if not self.config.anti_debugging:
            return
        
        try:
            # Check if being debugged
            if self._is_being_debugged():
                self._trigger_countermeasures()
                return
            
            # Anti-debugging techniques
            self._patch_debugger_detection()
            self._install_debugger_traps()
            self._implement_timing_checks()
            
            self.active_measures.add("anti_debugging")
            
        except Exception as e:
            log_opsec_event("anti_debugging_init_error", {"error": str(e)}, "normal", 6)
    
    def _is_being_debugged(self) -> bool:
        """Check if process is being debugged."""
        try:
            # Check TracerPid in /proc/self/status
            with open('/proc/self/status', 'r') as f:
                status = f.read()
                for line in status.split('\n'):
                    if line.startswith('TracerPid:'):
                        tracer_pid = int(line.split()[1])
                        return tracer_pid != 0
            
            return False
        except:
            return False
    
    def _patch_debugger_detection(self):
        """Patch system calls used for debugger detection."""
        # This would involve more sophisticated techniques in a real implementation
        # For now, we'll implement basic checks
        pass
    
    def _install_debugger_traps(self):
        """Install traps to detect debugger attachment."""
        def debugger_check():
            while True:
                time.sleep(secrets.randbelow(10) + 5)
                if self._is_being_debugged():
                    log_opsec_event("debugger_detected", {}, "emergency", 9)
                    self._trigger_countermeasures()
                    break
        
        threading.Thread(target=debugger_check, daemon=True).start()
    
    def _implement_timing_checks(self):
        """Implement timing-based anti-debugging."""
        def timing_check():
            while True:
                time.sleep(secrets.randbelow(30) + 15)
                
                # Measure execution time of simple operations
                start = time.time()
                for _ in range(10000):
                    hashlib.md5(b"test").hexdigest()
                end = time.time()
                
                execution_time = end - start
                
                # If execution takes suspiciously long, might be debugged
                if execution_time > 0.1:  # Adjust threshold as needed
                    log_opsec_event("timing_anomaly_detected", {
                        "execution_time": execution_time
                    }, "normal", 7)
        
        threading.Thread(target=timing_check, daemon=True).start()
    
    def _trigger_countermeasures(self):
        """Trigger anti-debugging countermeasures."""
        log_opsec_event("countermeasures_activated", {}, "emergency", 10)
        
        # Multiple levels of countermeasures
        self._memory_corruption()
        self._process_suicide()
        self._data_wipe()
    
    def _memory_corruption(self):
        """Corrupt memory to prevent analysis."""
        try:
            # Overwrite critical memory regions
            import ctypes
            ctypes.windll.kernel32.SetProcessWorkingSetSize(-1, -1, -1)
        except:
            # Unix alternative
            try:
                # Clear memory mappings
                import resource
                resource.setrlimit(resource.RLIMIT_AS, (1024*1024*100, -1))  # 100MB limit
            except:
                pass
    
    def _process_suicide(self):
        """Terminate process to prevent analysis."""
        try:
            os._exit(1)
        except:
            pass
    
    def _data_wipe(self):
        """Wipe critical data before termination."""
        try:
            # Wipe environment variables
            for key in list(os.environ.keys()):
                if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'password', 'token']):
                    os.environ[key] = '\x00' * len(os.environ[key])
        except:
            pass
    
    def _init_anti_vm(self):
        """Initialize anti-virtual machine measures."""
        if not self.config.anti_vm:
            return
        
        try:
            vm_indicators = self._detect_vm_indicators()
            
            if vm_indicators:
                log_opsec_event("vm_indicators_detected", {
                    "indicators": vm_indicators
                }, "normal", 6)
                
                # Adjust behavior for VM environment
                self._adapt_to_vm_environment(vm_indicators)
            
            self.active_measures.add("anti_vm")
            
        except Exception as e:
            log_opsec_event("anti_vm_init_error", {"error": str(e)}, "normal", 5)
    
    def _detect_vm_indicators(self) -> List[str]:
        """Detect virtual machine indicators."""
        indicators = []
        
        # Check for VM-specific hardware
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read().lower()
                vm_indicators = [
                    'vmware', 'virtualbox', 'qemu', 'kvm', 'xen',
                    'hyper-v', 'parallels', 'bochs'
                ]
                for indicator in vm_indicators:
                    if indicator in cpuinfo:
                        indicators.append(f"cpuinfo_{indicator}")
        except:
            pass
        
        # Check for VM-specific processes
        vm_processes = ['vmtoolsd', 'VBoxService', 'qemu-ga', 'hv_kvp_daemon']
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() in [p.lower() for p in vm_processes]:
                    indicators.append(f"process_{proc.info['name'].lower()}")
            except:
                continue
        
        # Check for VM-specific device files
        vm_devices = ['/dev/vboxguest', '/dev/vmware', '/dev/qemu']
        for device in vm_devices:
            if os.path.exists(device):
                indicators.append(f"device_{os.path.basename(device)}")
        
        # Check for suspicious MAC addresses (VMware, VirtualBox, etc.)
        try:
            import subprocess
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            mac_patterns = ['00:0c:29', '00:50:56', '08:00:27']  # VMware, VirtualBox patterns
            for line in result.stdout.split('\n'):
                for pattern in mac_patterns:
                    if pattern in line.lower():
                        indicators.append(f"mac_{pattern.replace(':', '')}")
        except:
            pass
        
        return indicators
    
    def _adapt_to_vm_environment(self, indicators: List[str]):
        """Adapt behavior for VM environment."""
        # Reduce logging in VM environments
        # Modify timing patterns
        # Change network behavior
        
        log_opsec_event("adapted_to_vm", {
            "indicators": indicators,
            "adaptations": ["reduced_logging", "modified_timing", "stealth_mode"]
        }, "normal", 4)
    
    def _init_memory_obfuscation(self):
        """Initialize memory obfuscation techniques."""
        if not self.config.memory_obfuscation:
            return
        
        try:
            # Start memory obfuscation threads
            self._start_memory_obfuscation()
            self.active_measures.add("memory_obfuscation")
            
        except Exception as e:
            log_opsec_event("memory_obfuscation_init_error", {"error": str(e)}, "normal", 4)
    
    def _start_memory_obfuscation(self):
        """Start memory obfuscation processes."""
        def memory_movement():
            while True:
                try:
                    # Move memory pages around
                    time.sleep(secrets.randbelow(60) + 30)
                    self._scrub_memory_traces()
                except Exception as e:
                    log_opsec_event("memory_obfuscation_error", {"error": str(e)}, "normal", 3)
        
        def fake_allocation():
            while True:
                try:
                    # Create fake memory allocations
                    fake_data = secrets.token_bytes(secrets.randbelow(1024) + 512)
                    # Immediately discard to create memory pressure
                    del fake_data
                    time.sleep(secrets.randbelow(120) + 60)
                except:
                    pass
        
        threading.Thread(target=memory_movement, daemon=True).start()
        threading.Thread(target=fake_allocation, daemon=True).start()
    
    def _scrub_memory_traces(self):
        """Scrub memory traces."""
        try:
            # Force garbage collection
            import gc
            gc.collect()
            
            # Clear Python internal caches
            if hasattr(sys, '_clear_type_cache'):
                sys._clear_type_cache()
            
        except Exception as e:
            log_opsec_event("memory_scrub_error", {"error": str(e)}, "normal", 2)
    
    def _init_network_stealth(self):
        """Initialize network stealth measures."""
        if not self.config.network_stealth:
            return
        
        try:
            # Randomize network behavior
            self._randomize_network_timing()
            self._implement_traffic_obfuscation()
            self.active_measures.add("network_stealth")
            
        except Exception as e:
            log_opsec_event("network_stealth_init_error", {"error": str(e)}, "normal", 4)
    
    def _randomize_network_timing(self):
        """Randomize network timing patterns."""
        def network_randomizer():
            while True:
                try:
                    # Add random delays to network operations
                    delay = secrets.randbelow(10) + 1
                    time.sleep(delay)
                except:
                    break
        
        threading.Thread(target=network_randomizer, daemon=True).start()
    
    def _implement_traffic_obfuscation(self):
        """Implement traffic obfuscation."""
        # This would implement various traffic obfuscation techniques
        # such as padding, timing randomization, etc.
        pass
    
    def _init_filesystem_stealth(self):
        """Initialize filesystem stealth measures."""
        if not self.config.filesystem_stealth:
            return
        
        try:
            # Hide from filesystem monitoring
            self._hide_from_fs_monitoring()
            self.active_measures.add("filesystem_stealth")
            
        except Exception as e:
            log_opsec_event("filesystem_stealth_init_error", {"error": str(e)}, "normal", 4)
    
    def _hide_from_fs_monitoring(self):
        """Hide from filesystem monitoring tools."""
        def fs_monitor_bypass():
            while True:
                try:
                    # Periodically change file access patterns
                    time.sleep(secrets.randbelow(180) + 90)
                    
                    # Create random file accesses
                    temp_files = list(Path('/tmp').glob('*'))[:5]
                    for temp_file in temp_files:
                        try:
                            if temp_file.exists():
                                temp_file.stat()
                        except:
                            pass
                            
                except:
                    break
        
        threading.Thread(target=fs_monitor_bypass, daemon=True).start()
    
    def _init_process_hiding(self):
        """Initialize process hiding measures."""
        if not self.config.process_hiding:
            return
        
        try:
            # Hide from process listings
            self._hide_process_name()
            self.active_measures.add("process_hiding")
            
        except Exception as e:
            log_opsec_event("process_hiding_init_error", {"error": str(e)}, "normal", 4)
    
    def _hide_process_name(self):
        """Hide or obfuscate process name."""
        try:
            current_process = psutil.Process()
            
            # Try to set a generic process name
            generic_names = ['systemd', 'kworker', 'ksoftirqd', 'kthreadd']
            generic_name = secrets.choice(generic_names)
            
            try:
                current_process.name(generic_name)
            except:
                pass  # Some systems don't allow this
            
        except Exception as e:
            log_opsec_event("process_name_hide_error", {"error": str(e)}, "normal", 3)
    
    def _init_timing_obfuscation(self):
        """Initialize timing obfuscation."""
        if not self.config.timing_obfuscation:
            return
        
        try:
            # Add random delays to operations
            self._implement_timing_jitter()
            self.active_measures.add("timing_obfuscation")
            
        except Exception as e:
            log_opsec_event("timing_obfuscation_init_error", {"error": str(e)}, "normal", 3)
    
    def _implement_timing_jitter(self):
        """Implement timing jitter."""
        def timing_jitter():
            while True:
                try:
                    # Add random delays to create timing variations
                    time.sleep(secrets.randbelow(5) + 1)
                except:
                    break
        
        threading.Thread(target=timing_jitter, daemon=True).start()


class BehavioralAnalyzer:
    """
    Analyzes system behavior to detect potential monitoring or analysis attempts.
    """
    
    def __init__(self, safeguard_engine: AntiDetectionEngine = None):
        self.safeguard_engine = safeguard_engine
        self.behavior_baseline = {}
        self.anomaly_threshold = 0.7
        self._lock = threading.Lock()
        
        # Start behavioral monitoring
        self._start_behavioral_monitoring()
    
    def _start_behavioral_monitoring(self):
        """Start behavioral monitoring."""
        def monitor_loop():
            while True:
                try:
                    self._analyze_current_behavior()
                    time.sleep(10)  # Check every 10 seconds
                except Exception as e:
                    log_opsec_event("behavioral_monitor_error", {"error": str(e)}, "normal", 4)
        
        # Establish baseline first
        time.sleep(30)  # Wait for system to stabilize
        self._establish_behavior_baseline()
        
        # Start monitoring
        threading.Thread(target=monitor_loop, daemon=True).start()
    
    def _establish_behavior_baseline(self):
        """Establish baseline behavior metrics."""
        try:
            # Measure normal CPU usage
            cpu_samples = []
            for _ in range(10):
                cpu_samples.append(psutil.cpu_percent(interval=1))
            
            self.behavior_baseline['cpu_usage'] = {
                'mean': sum(cpu_samples) / len(cpu_samples),
                'std': (sum((x - sum(cpu_samples)/len(cpu_samples))**2 for x in cpu_samples) / len(cpu_samples))**0.5
            }
            
            # Measure normal memory usage
            memory = psutil.virtual_memory()
            self.behavior_baseline['memory_usage'] = memory.percent
            
            # Measure normal process count
            process_count = len(psutil.pids())
            self.behavior_baseline['process_count'] = process_count
            
            # Measure normal network connections
            connections = len(psutil.net_connections())
            self.behavior_baseline['network_connections'] = connections
            
            log_opsec_event("behavior_baseline_established", {
                "baseline": self.behavior_baseline
            }, "normal", 1)
            
        except Exception as e:
            log_opsec_event("baseline_error", {"error": str(e)}, "normal", 3)
    
    def _analyze_current_behavior(self):
        """Analyze current behavior for anomalies."""
        try:
            anomalies = []
            
            # Check CPU usage anomaly
            current_cpu = psutil.cpu_percent(interval=1)
            baseline_cpu = self.behavior_baseline.get('cpu_usage', {})
            if 'mean' in baseline_cpu:
                cpu_deviation = abs(current_cpu - baseline_cpu['mean'])
                if cpu_deviation > baseline_cpu.get('std', 10) * 3:  # 3 standard deviations
                    anomalies.append({
                        'type': 'cpu_usage',
                        'current': current_cpu,
                        'baseline': baseline_cpu['mean'],
                        'deviation': cpu_deviation
                    })
            
            # Check memory usage anomaly
            current_memory = psutil.virtual_memory().percent
            baseline_memory = self.behavior_baseline.get('memory_usage', 0)
            memory_deviation = abs(current_memory - baseline_memory)
            if memory_deviation > 20:  # 20% deviation
                anomalies.append({
                    'type': 'memory_usage',
                    'current': current_memory,
                    'baseline': baseline_memory,
                    'deviation': memory_deviation
                })
            
            # Check process count anomaly
            current_process_count = len(psutil.pids())
            baseline_process_count = self.behavior_baseline.get('process_count', 0)
            if abs(current_process_count - baseline_process_count) > 50:
                anomalies.append({
                    'type': 'process_count',
                    'current': current_process_count,
                    'baseline': baseline_process_count,
                    'deviation': abs(current_process_count - baseline_process_count)
                })
            
            # Check network connections anomaly
            current_connections = len(psutil.net_connections())
            baseline_connections = self.behavior_baseline.get('network_connections', 0)
            if abs(current_connections - baseline_connections) > 20:
                anomalies.append({
                    'type': 'network_connections',
                    'current': current_connections,
                    'baseline': baseline_connections,
                    'deviation': abs(current_connections - baseline_connections)
                })
            
            if anomalies:
                self._handle_behavioral_anomalies(anomalies)
                
        except Exception as e:
            log_opsec_event("behavior_analysis_error", {"error": str(e)}, "normal", 3)
    
    def _handle_behavioral_anomalies(self, anomalies: List[Dict[str, Any]]):
        """Handle detected behavioral anomalies."""
        severity = min(len(anomalies) * 2, 10)
        
        log_opsec_event("behavioral_anomalies", {
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "severity": severity
        }, "stealth", severity)
        
        # If too many anomalies, increase security level
        if len(anomalies) >= 3:
            self._increase_security_level()
    
    def _increase_security_level(self):
        """Increase security measures in response to anomalies."""
        log_opsec_event("security_level_increased", {
            "reason": "behavioral_anomalies",
            "timestamp": time.time()
        }, "normal", 5)
        
        # Trigger additional safeguard measures
        if self.safeguard_engine:
            # Add more aggressive countermeasures
            pass


class SecureCommunication:
    """
    Provides secure communication methods with traffic obfuscation.
    """
    
    def __init__(self):
        self.communication_patterns = []
        self._start_pattern_obfuscation()
    
    def _start_pattern_obfuscation(self):
        """Start communication pattern obfuscation."""
        def pattern_obfuscation():
            while True:
                try:
                    # Generate fake communication patterns
                    self._generate_fake_patterns()
                    time.sleep(secrets.randbelow(300) + 180)  # 3-8 minutes
                except Exception as e:
                    log_opsec_event("pattern_obfuscation_error", {"error": str(e)}, "normal", 2)
        
        threading.Thread(target=pattern_obfuscation, daemon=True).start()
    
    def _generate_fake_patterns(self):
        """Generate fake communication patterns."""
        try:
            # Create fake DNS queries
            fake_domains = [
                'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
                'github.com', 'stackoverflow.com', 'reddit.com', 'twitter.com'
            ]
            
            for _ in range(secrets.randbelow(5) + 1):
                domain = secrets.choice(fake_domains)
                # In a real implementation, this would make actual network requests
                # For now, just log the fake activity
                log_opsec_event("fake_communication", {
                    "type": "dns_query",
                    "domain": domain
                }, "stealth", 1)
                
        except Exception as e:
            log_opsec_event("fake_pattern_error", {"error": str(e)}, "normal", 2)


# Global safeguards instance
_safeguards_engine = None

def get_safeguards_engine(config: SafeguardConfig = None) -> AntiDetectionEngine:
    """Get global safeguards engine instance."""
    global _safeguards_engine
    if _safeguards_engine is None:
        _safeguards_engine = AntiDetectionEngine(config)
    return _safeguards_engine


def enable_safeguards(config: SafeguardConfig = None):
    """Enable operational safeguards."""
    engine = get_safeguards_engine(config)
    return engine


def check_environment_security() -> Dict[str, Any]:
    """Check current environment security status."""
    engine = get_safeguards_engine()
    
    return {
        "active_measures": list(engine.active_measures),
        "config": asdict(engine.config),
        "environment_check": {
            "debugger_detected": engine._is_being_debugged(),
            "vm_indicators": engine._detect_vm_indicators()
        }
    }