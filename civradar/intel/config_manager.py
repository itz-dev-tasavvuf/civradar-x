# civradar/intel/config_manager.py
"""
Field-Ready Configuration Management.
Provides secure, dynamic configuration handling for field operations.
"""

import os
import json
import time
import secrets
import hashlib
import threading
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .opsec_logger import get_opsec_logger, log_opsec_event

class ConfigLevel(Enum):
    """Configuration levels based on security requirements."""
    MINIMAL = "minimal"     # Basic functionality
    STANDARD = "standard"   # Balanced security/functionality
    HIGH = "high"          # Enhanced security
    EXTREME = "extreme"    # Maximum security
    EMERGENCY = "emergency" # Crisis mode

class FieldScenario(Enum):
    """Field operation scenarios."""
    NORMAL = "normal"           # Standard operations
    STEALTH = "stealth"         # Low-visibility operations
    COMBAT = "combat"          # High-threat environments
    EMERGENCY = "emergency"    # Crisis situations
    OFFLINE = "offline"        # No network connectivity
    URBAN = "urban"           # Urban environments
    RURAL = "rural"           # Rural/remote environments
    MOBILE = "mobile"         # Mobile operations

@dataclass
class SecurityConfig:
    """Security-related configuration."""
    encryption_enabled: bool = True
    auto_wipe_enabled: bool = True
    secure_deletion: bool = True
    time_stomping: bool = False
    process_hiding: bool = False
    network_stealth: bool = False
    memory_protection: bool = False
    forensic_protection: bool = False
    threat_detection: bool = True
    emergency_wipe_threshold: int = 8

@dataclass
class OperationalConfig:
    """Operational configuration."""
    scan_interval: int = 10
    data_retention_hours: int = 24
    max_file_size_mb: int = 100
    compression_enabled: bool = True
    backup_enabled: bool = False
    logging_level: str = "normal"
    ui_stealth_mode: bool = False
    gps_enabled: bool = True
    data_fusion: bool = True

@dataclass
class NetworkConfig:
    """Network configuration."""
    listen_host: str = "127.0.0.1"
    listen_port: int = 5000
    use_tor: bool = False
    proxy_enabled: bool = False
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 9050
    allowed_outbound: List[str] = None
    blocked_ports: List[int] = None
    port_randomization: bool = False
    
    def __post_init__(self):
        if self.allowed_outbound is None:
            self.allowed_outbound = ["53", "80", "443", "9050"]
        if self.blocked_ports is None:
            self.blocked_ports = [21, 22, 23, 25, 110, 143, 993, 995]

@dataclass
class FieldConfig:
    """Complete field-ready configuration."""
    security: SecurityConfig = None
    operational: OperationalConfig = None
    network: NetworkConfig = None
    config_level: ConfigLevel = ConfigLevel.STANDARD
    field_scenario: FieldScenario = FieldScenario.NORMAL
    field_identifier: str = None
    version: str = "1.0"
    created_at: float = None
    checksum: str = None
    
    def __post_init__(self):
        if self.security is None:
            self.security = SecurityConfig()
        if self.operational is None:
            self.operational = OperationalConfig()
        if self.network is None:
            self.network = NetworkConfig()
        if self.field_identifier is None:
            self.field_identifier = secrets.token_hex(8)
        if self.created_at is None:
            self.created_at = time.time()
        self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """Calculate configuration checksum for integrity verification."""
        config_dict = asdict(self)
        config_dict.pop('checksum', None)  # Remove checksum from calculation
        
        config_json = json.dumps(config_dict, sort_keys=True).encode()
        return hashlib.sha256(config_json).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify configuration integrity."""
        return self.checksum == self._calculate_checksum()

class ConfigManager:
    """
    Secure configuration manager for field operations.
    """
    
    def __init__(self, config_dir: str = None, master_password: str = None):
        self.config_dir = Path(config_dir or "/etc/civradar-x")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.master_password = master_password
        self.current_config: Optional[FieldConfig] = None
        self.config_history: List[FieldConfig] = []
        self._lock = threading.Lock()
        
        # Initialize encryption
        self._init_encryption()
        
        # Load configuration
        self.load_configuration()
        
        log_opsec_event("config_manager_initialized", {
            "config_dir": str(self.config_dir),
            "has_password": bool(master_password)
        }, "normal", 2)
    
    def _init_encryption(self):
        """Initialize encryption for configuration storage."""
        if self.master_password:
            # Use provided password
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            self.cipher = Fernet(key)
            self.encryption_salt = salt
        else:
            # Generate ephemeral key
            key = Fernet.generate_key()
            self.cipher = Fernet(key)
            self.encryption_salt = secrets.token_bytes(16)
    
    def create_configuration(self, config_level: ConfigLevel, 
                           field_scenario: FieldScenario,
                           custom_settings: Dict[str, Any] = None) -> FieldConfig:
        """
        Create new configuration for specific level and scenario.
        
        Args:
            config_level: Security level for configuration
            field_scenario: Field operation scenario
            custom_settings: Custom configuration overrides
            
        Returns:
            FieldConfig object with appropriate settings
        """
        with self._lock:
            # Create base configuration
            config = FieldConfig(
                config_level=config_level,
                field_scenario=field_scenario
            )
            
            # Apply level-specific settings
            self._apply_config_level(config, config_level)
            
            # Apply scenario-specific settings
            self._apply_field_scenario(config, field_scenario)
            
            # Apply custom settings
            if custom_settings:
                self._apply_custom_settings(config, custom_settings)
            
            # Validate configuration
            if not self._validate_config(config):
                raise ValueError("Configuration validation failed")
            
            # Store in history
            self.config_history.append(config)
            
            log_opsec_event("config_created", {
                "config_level": config_level.value,
                "field_scenario": field_scenario.value,
                "config_id": config.field_identifier
            }, "normal", 3)
            
            return config
    
    def _apply_config_level(self, config: FieldConfig, level: ConfigLevel):
        """Apply security level specific settings."""
        level_configs = {
            ConfigLevel.MINIMAL: SecurityConfig(
                encryption_enabled=True,
                auto_wipe_enabled=False,
                secure_deletion=False,
                process_hiding=False,
                network_stealth=False,
                threat_detection=False
            ),
            ConfigLevel.STANDARD: SecurityConfig(
                encryption_enabled=True,
                auto_wipe_enabled=True,
                secure_deletion=True,
                process_hiding=True,
                network_stealth=True,
                threat_detection=True,
                emergency_wipe_threshold=7
            ),
            ConfigLevel.HIGH: SecurityConfig(
                encryption_enabled=True,
                auto_wipe_enabled=True,
                secure_deletion=True,
                process_hiding=True,
                network_stealth=True,
                memory_protection=True,
                forensic_protection=True,
                threat_detection=True,
                emergency_wipe_threshold=6
            ),
            ConfigLevel.EXTREME: SecurityConfig(
                encryption_enabled=True,
                auto_wipe_enabled=True,
                secure_deletion=True,
                process_hiding=True,
                network_stealth=True,
                memory_protection=True,
                forensic_protection=True,
                time_stomping=True,
                threat_detection=True,
                emergency_wipe_threshold=5
            ),
            ConfigLevel.EMERGENCY: SecurityConfig(
                encryption_enabled=True,
                auto_wipe_enabled=True,
                secure_deletion=True,
                process_hiding=True,
                network_stealth=True,
                memory_protection=True,
                forensic_protection=True,
                time_stomping=True,
                threat_detection=True,
                emergency_wipe_threshold=3
            )
        }
        
        config.security = level_configs.get(level, config.security)
    
    def _apply_field_scenario(self, config: FieldConfig, scenario: FieldScenario):
        """Apply field scenario specific settings."""
        scenario_configs = {
            FieldScenario.NORMAL: {
                "operational": {
                    "scan_interval": 10,
                    "logging_level": "normal",
                    "ui_stealth_mode": False
                },
                "network": {
                    "listen_host": "127.0.0.1",
                    "listen_port": 5000
                }
            },
            FieldScenario.STEALTH: {
                "operational": {
                    "scan_interval": 30,
                    "logging_level": "minimal",
                    "ui_stealth_mode": True
                },
                "network": {
                    "listen_host": "127.0.0.1",
                    "listen_port": 5000,
                    "port_randomization": True
                }
            },
            FieldScenario.COMBAT: {
                "operational": {
                    "scan_interval": 60,
                    "logging_level": "minimal",
                    "data_retention_hours": 1
                },
                "security": {
                    "emergency_wipe_threshold": 5
                },
                "network": {
                    "allowed_outbound": ["53"],  # DNS only
                    "blocked_ports": [21, 22, 23, 25, 80, 443, 993, 995]
                }
            },
            FieldScenario.EMERGENCY: {
                "operational": {
                    "scan_interval": 120,
                    "logging_level": "none",
                    "data_retention_hours": 0
                },
                "security": {
                    "emergency_wipe_threshold": 3
                }
            },
            FieldScenario.OFFLINE: {
                "network": {
                    "use_tor": False,
                    "proxy_enabled": False
                },
                "operational": {
                    "backup_enabled": False
                }
            }
        }
        
        scenario_config = scenario_configs.get(scenario, {})
        
        # Apply scenario settings
        for section, settings in scenario_config.items():
            if hasattr(config, section):
                section_obj = getattr(config, section)
                for key, value in settings.items():
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)
    
    def _apply_custom_settings(self, config: FieldConfig, custom_settings: Dict[str, Any]):
        """Apply custom configuration settings."""
        for path, value in custom_settings.items():
            # Parse path like "security.encryption_enabled"
            parts = path.split('.')
            obj = config
            
            # Navigate to the parent object
            for part in parts[:-1]:
                if hasattr(obj, part):
                    obj = getattr(obj, part)
                else:
                    break
            
            # Set the final value
            final_part = parts[-1]
            if hasattr(obj, final_part):
                setattr(obj, final_part, value)
    
    def _validate_config(self, config: FieldConfig) -> bool:
        """Validate configuration."""
        try:
            # Check required fields
            if not config.field_identifier:
                return False
            
            # Check security settings
            if config.security.encryption_enabled and not self.cipher:
                return False
            
            # Check operational settings
            if config.operational.scan_interval < 1:
                return False
            
            # Check network settings
            if config.network.listen_port < 1 or config.network.listen_port > 65535:
                return False
            
            # Verify checksum
            if not config.verify_integrity():
                return False
            
            return True
            
        except Exception:
            return False
    
    def save_configuration(self, config: FieldConfig, encrypt: bool = True):
        """Save configuration to disk."""
        with self._lock:
            try:
                config_file = self.config_dir / f"config_{config.field_identifier}.json"
                
                # Convert to dictionary
                config_dict = asdict(config)
                
                # Encrypt if requested
                if encrypt and self.cipher:
                    config_json = json.dumps(config_dict).encode()
                    encrypted_data = self.cipher.encrypt(config_json)
                    
                    with open(config_file, 'wb') as f:
                        f.write(encrypted_data)
                else:
                    with open(config_file, 'w') as f:
                        json.dump(config_dict, f, indent=2)
                
                # Update current config
                self.current_config = config
                
                log_opsec_event("config_saved", {
                    "config_id": config.field_identifier,
                    "encrypted": encrypt,
                    "file_path": str(config_file)
                }, "normal", 2)
                
            except Exception as e:
                log_opsec_event("config_save_error", {
                    "error": str(e),
                    "config_id": config.field_identifier
                }, "normal", 5)
                raise
    
    def load_configuration(self, config_id: str = None) -> Optional[FieldConfig]:
        """Load configuration from disk."""
        with self._lock:
            try:
                if config_id:
                    # Load specific configuration
                    config_file = self.config_dir / f"config_{config_id}.json"
                else:
                    # Load most recent configuration
                    config_files = list(self.config_dir.glob("config_*.json"))
                    if not config_files:
                        return None
                    
                    # Sort by modification time, newest first
                    config_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                    config_file = config_files[0]
                
                if not config_file.exists():
                    return None
                
                # Read and decrypt if necessary
                with open(config_file, 'rb') as f:
                    data = f.read()
                
                if self.cipher:
                    try:
                        # Try to decrypt
                        decrypted_data = self.cipher.decrypt(data)
                        config_dict = json.loads(decrypted_data.decode())
                    except:
                        # If decryption fails, treat as plain text
                        config_dict = json.loads(data.decode())
                else:
                    config_dict = json.loads(data.decode())
                
                # Reconstruct config object
                config = FieldConfig(**config_dict)
                
                # Verify integrity
                if config.verify_integrity():
                    self.current_config = config
                    log_opsec_event("config_loaded", {
                        "config_id": config.field_identifier,
                        "config_level": config.config_level.value
                    }, "normal", 2)
                    return config
                else:
                    log_opsec_event("config_integrity_failed", {
                        "config_id": config.field_identifier
                    }, "normal", 6)
                    return None
                
            except Exception as e:
                log_opsec_event("config_load_error", {
                    "error": str(e),
                    "config_id": config_id
                }, "normal", 5)
                return None
    
    def update_configuration(self, updates: Dict[str, Any]) -> bool:
        """Update current configuration."""
        if not self.current_config:
            return False
        
        try:
            with self._lock:
                # Apply updates
                self._apply_custom_settings(self.current_config, updates)
                
                # Recalculate checksum
                self.current_config.checksum = self.current_config._calculate_checksum()
                
                # Save updated configuration
                self.save_configuration(self.current_config)
                
                log_opsec_event("config_updated", {
                    "config_id": self.current_config.field_identifier,
                    "updates": list(updates.keys())
                }, "normal", 2)
                
                return True
                
        except Exception as e:
            log_opsec_event("config_update_error", {
                "error": str(e)
            }, "normal", 5)
            return False
    
    def switch_config_level(self, new_level: ConfigLevel) -> bool:
        """Switch configuration security level."""
        if not self.current_config:
            return False
        
        try:
            # Create new config with new level
            new_config = self.create_configuration(
                new_level,
                self.current_config.field_scenario,
                asdict(self.current_config)
            )
            
            # Preserve field identifier and timestamp
            new_config.field_identifier = self.current_config.field_identifier
            new_config.created_at = self.current_config.created_at
            
            # Save new configuration
            self.save_configuration(new_config)
            
            log_opsec_event("config_level_switched", {
                "old_level": self.current_config.config_level.value,
                "new_level": new_level.value,
                "config_id": new_config.field_identifier
            }, "normal", 3)
            
            return True
            
        except Exception as e:
            log_opsec_event("config_level_switch_error", {
                "error": str(e),
                "target_level": new_level.value
            }, "normal", 6)
            return False
    
    def switch_field_scenario(self, new_scenario: FieldScenario) -> bool:
        """Switch field scenario."""
        if not self.current_config:
            return False
        
        try:
            # Create new config with new scenario
            new_config = self.create_configuration(
                self.current_config.config_level,
                new_scenario,
                asdict(self.current_config)
            )
            
            # Preserve field identifier and timestamp
            new_config.field_identifier = self.current_config.field_identifier
            new_config.created_at = self.current_config.created_at
            
            # Save new configuration
            self.save_configuration(new_config)
            
            log_opsec_event("config_scenario_switched", {
                "old_scenario": self.current_config.field_scenario.value,
                "new_scenario": new_scenario.value,
                "config_id": new_config.field_identifier
            }, "normal", 3)
            
            return True
            
        except Exception as e:
            log_opsec_event("config_scenario_switch_error", {
                "error": str(e),
                "target_scenario": new_scenario.value
            }, "normal", 6)
            return False
    
    def emergency_config_reset(self):
        """Reset to emergency configuration."""
        emergency_config = self.create_configuration(
            ConfigLevel.EMERGENCY,
            FieldScenario.EMERGENCY
        )
        
        self.save_configuration(emergency_config)
        
        log_opsec_event("emergency_config_reset", {
            "config_id": emergency_config.field_identifier
        }, "emergency", 8)
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary."""
        if not self.current_config:
            return {"error": "No configuration loaded"}
        
        return {
            "config_id": self.current_config.field_identifier,
            "config_level": self.current_config.config_level.value,
            "field_scenario": self.current_config.field_scenario.value,
            "security_features": {
                "encryption": self.current_config.security.encryption_enabled,
                "auto_wipe": self.current_config.security.auto_wipe_enabled,
                "process_hiding": self.current_config.security.process_hiding,
                "network_stealth": self.current_config.security.network_stealth,
                "threat_detection": self.current_config.security.threat_detection
            },
            "operational_settings": {
                "scan_interval": self.current_config.operational.scan_interval,
                "retention_hours": self.current_config.operational.data_retention_hours,
                "logging_level": self.current_config.operational.logging_level
            },
            "network_settings": {
                "listen_host": self.current_config.network.listen_host,
                "listen_port": self.current_config.network.listen_port,
                "use_tor": self.current_config.network.use_tor
            },
            "created_at": self.current_config.created_at,
            "history_count": len(self.config_history)
        }
    
    def list_configurations(self) -> List[Dict[str, Any]]:
        """List all available configurations."""
        configs = []
        
        for config_file in self.config_dir.glob("config_*.json"):
            try:
                # Try to load basic info without full decryption
                with open(config_file, 'rb') as f:
                    data = f.read()
                
                config_info = {
                    "file_name": config_file.name,
                    "file_size": config_file.stat().st_size,
                    "modified_time": config_file.stat().st_mtime
                }
                
                # Try to extract basic info
                try:
                    if self.cipher:
                        decrypted_data = self.cipher.decrypt(data)
                        config_dict = json.loads(decrypted_data.decode())
                    else:
                        config_dict = json.loads(data.decode())
                    
                    config_info.update({
                        "config_id": config_dict.get('field_identifier'),
                        "config_level": config_dict.get('config_level'),
                        "field_scenario": config_dict.get('field_scenario'),
                        "created_at": config_dict.get('created_at')
                    })
                except:
                    config_info["encrypted"] = True
                
                configs.append(config_info)
                
            except Exception as e:
                log_opsec_event("config_list_error", {
                    "file": str(config_file),
                    "error": str(e)
                }, "normal", 3)
        
        # Sort by modification time
        configs.sort(key=lambda x: x.get("modified_time", 0), reverse=True)
        
        return configs
    
    def delete_configuration(self, config_id: str) -> bool:
        """Delete configuration."""
        try:
            config_file = self.config_dir / f"config_{config_id}.json"
            
            if config_file.exists():
                # Secure deletion
                self._secure_delete_file(config_file)
                
                log_opsec_event("config_deleted", {
                    "config_id": config_id
                }, "normal", 4)
                
                return True
            
            return False
            
        except Exception as e:
            log_opsec_event("config_delete_error", {
                "config_id": config_id,
                "error": str(e)
            }, "normal", 5)
            return False
    
    def _secure_delete_file(self, file_path: Path):
        """Securely delete configuration file."""
        file_size = file_path.stat().st_size
        
        # Multiple overwrite passes
        with open(file_path, 'r+b') as f:
            for _ in range(3):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        file_path.unlink()


# Global configuration manager instance
_config_manager = None

def get_config_manager(config_dir: str = None, master_password: str = None) -> ConfigManager:
    """Get global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_dir, master_password)
    return _config_manager


def create_field_config(level: ConfigLevel, scenario: FieldScenario, 
                       custom_settings: Dict[str, Any] = None) -> FieldConfig:
    """Create new field configuration."""
    manager = get_config_manager()
    return manager.create_configuration(level, scenario, custom_settings)


def switch_security_level(level: ConfigLevel) -> bool:
    """Switch security level."""
    manager = get_config_manager()
    return manager.switch_config_level(level)


def get_current_config() -> Optional[FieldConfig]:
    """Get current configuration."""
    manager = get_config_manager()
    return manager.current_config


def emergency_reset():
    """Emergency configuration reset."""
    manager = get_config_manager()
    manager.emergency_config_reset()