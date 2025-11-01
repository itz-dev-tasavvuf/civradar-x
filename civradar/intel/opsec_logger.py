# civradar/intel/opsec_logger.py
"""
Operational Security (OPSEC) Logger with encrypted storage and anti-forensics capabilities.
Designed for field operations in hostile environments with secure deletion and tamper protection.
"""

import sqlite3
import os
import json
import time
import secrets
import hashlib
import hmac
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import threading
import logging
from typing import Dict, List, Optional, Any

class OPSECLogger:
    """
    Encrypted logging system with anti-forensics features for field operations.
    Provides tamper protection, secure deletion, and operation mode masking.
    """
    
    def __init__(self, base_path: str = "/tmp/.civradar_opsec", security_level: str = "high"):
        """
        Initialize OPSEC Logger.
        
        Args:
            base_path: Base directory for encrypted storage
            security_level: 'minimal', 'standard', 'high', 'extreme'
        """
        self.base_path = Path(base_path)
        self.security_level = security_level
        self.session_id = secrets.token_hex(16)
        self._lock = threading.Lock()
        
        # Randomize base path for OPSEC
        if security_level in ['high', 'extreme']:
            self.base_path = self.base_path / f".system_{secrets.token_hex(8)}"
        
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._init_encryption()
        self._init_database()
        
        # OPSEC configuration
        self.opsec_config = {
            'minimal': {
                'encrypt_logs': True,
                'secure_delete': False,
                'time_stomping': False,
                'random_filenames': False,
                'memory_protection': False
            },
            'standard': {
                'encrypt_logs': True,
                'secure_delete': True,
                'time_stomping': True,
                'random_filenames': True,
                'memory_protection': True
            },
            'high': {
                'encrypt_logs': True,
                'secure_delete': True,
                'time_stomping': True,
                'random_filenames': True,
                'memory_protection': True,
                'fake_activity': True,
                'decoy_files': True
            },
            'extreme': {
                'encrypt_logs': True,
                'secure_delete': True,
                'time_stomping': True,
                'random_filenames': True,
                'memory_protection': True,
                'fake_activity': True,
                'decoy_files': True,
                'network_camouflage': True,
                'stealth_processes': True
            }
        }
        
        # Initialize anti-forensics features
        self._setup_anti_forensics()
        
        # Logging setup
        self.logger = logging.getLogger(f"opsec.{self.session_id}")
        self.logger.setLevel(logging.INFO)
        
    def _init_encryption(self):
        """Initialize encryption with session-derived key."""
        # Generate session key from random data + system entropy
        random_salt = secrets.token_bytes(32)
        system_entropy = os.urandom(32)
        key_material = random_salt + system_entropy
        
        # Derive encryption key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_material[:16],
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(key_material[16:]))
        
        self.cipher = Fernet(key)
        self.encryption_key = key
        
        # Store key securely (in memory only for high/extreme levels)
        if self.security_level in ['high', 'extreme']:
            # Immediately delete key material from memory
            del key_material, random_salt, system_entropy
        
    def _init_database(self):
        """Initialize encrypted SQLite database."""
        self.db_path = self.base_path / f"data_{secrets.token_hex(8)}.db"
        
        # Time stomping - set random creation/modification times
        if self.opsec_config[self.security_level]['time_stomping']:
            self._apply_time_stomping(self.db_path)
        
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS opsec_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                event_type TEXT,
                timestamp REAL,
                encrypted_data BLOB,
                mac_hash TEXT,
                operation_mode TEXT,
                threat_level INTEGER,
                metadata TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_start REAL,
                last_activity REAL,
                operations_count INTEGER,
                threat_detections INTEGER,
                security_events TEXT
            )
        """)
        
        # Insert session start
        session_start = time.time()
        conn.execute("""
            INSERT INTO session_tracking 
            (session_start, last_activity, operations_count, threat_detections, security_events)
            VALUES (?, ?, 0, 0, ?)
        """, (session_start, session_start, json.dumps([])))
        
        conn.commit()
        conn.close()
        
    def _apply_time_stomping(self, file_path: Path):
        """Apply timestomping to hide file creation patterns."""
        # Generate random timestamps within last year
        now = time.time()
        random_time = now - (secrets.randbelow(365 * 24 * 3600))
        
        # Set random access and modification times
        os.utime(file_path, (random_time, random_time))
        
    def _setup_anti_forensics(self):
        """Setup anti-forensic measures."""
        config = self.opsec_config[self.security_level]
        
        if config['decoy_files']:
            self._create_decoy_files()
        
        if config['fake_activity']:
            self._start_fake_activity()
            
        if config['random_filenames']:
            self._init_random_naming()
    
    def _create_decoy_files(self):
        """Create decoy files to confuse forensic analysis."""
        decoy_types = [
            ('system_cache', '.cache'),
            ('user_data', '.data'),
            ('temp_files', '.tmp'),
            ('config_backup', '.conf'),
            ('log_archive', '.log')
        ]
        
        for file_type, ext in decoy_types:
            for i in range(secrets.randbelow(5) + 1):
                decoy_path = self.base_path / f"{file_type}_{secrets.token_hex(8)}{ext}"
                # Create realistic but fake content
                fake_content = secrets.token_bytes(secrets.randbelow(1024) + 256)
                decoy_path.write_bytes(fake_content)
                
                if self.opsec_config[self.security_level]['time_stomping']:
                    self._apply_time_stomping(decoy_path)
    
    def _start_fake_activity(self):
        """Generate fake activity to mask real operations."""
        def fake_activity_loop():
            while True:
                time.sleep(secrets.randbelow(300) + 60)  # Random intervals
                # Simulate fake file operations
                fake_path = self.base_path / f"fake_{secrets.token_hex(8)}.tmp"
                fake_content = secrets.token_bytes(secrets.randbelow(512) + 64)
                fake_path.write_bytes(fake_content)
                
                # Clean up fake files immediately
                self._secure_delete(fake_path)
        
        if self.security_level in ['high', 'extreme']:
            threading.Thread(target=fake_activity_loop, daemon=True).start()
    
    def _init_random_naming(self):
        """Initialize random filename generation."""
        self.name_cache = {}
        
    def _get_random_filename(self, prefix: str, ext: str) -> str:
        """Generate cryptographically random filename."""
        if self.security_level == 'minimal':
            return f"{prefix}_{int(time.time())}.{ext}"
        else:
            return f"{prefix}_{secrets.token_hex(16)}.{ext}"
    
    def _secure_delete(self, file_path: Path):
        """Securely delete file with overwriting."""
        if not file_path.exists():
            return
            
        config = self.opsec_config[self.security_level]
        if not config['secure_delete']:
            file_path.unlink()
            return
        
        # Multiple pass overwriting for high security
        file_size = file_path.stat().st_size
        
        passes = {
            'standard': 1,
            'high': 3,
            'extreme': 7
        }.get(self.security_level, 1)
        
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        file_path.unlink()
        
        # For extreme security, also overwrite directory entry
        if self.security_level == 'extreme':
            parent_dir = file_path.parent
            dir_name = file_path.name
            
            # This is a simplified approach - real implementation would require
            # more sophisticated file system manipulation
            temp_file = parent_dir / f"tmp_{secrets.token_hex(8)}"
            temp_file.write_bytes(b'\x00' * 512)
            self._secure_delete(temp_file)
    
    def _calculate_mac(self, data: bytes) -> str:
        """Calculate HMAC for tamper detection."""
        return hmac.new(
            self.encryption_key,
            data,
            hashlib.sha256
        ).hexdigest()
    
    def log_operation(self, event_type: str, data: Dict[str, Any], 
                     operation_mode: str = "normal", threat_level: int = 0):
        """
        Log operation with encryption and anti-forensics.
        
        Args:
            event_type: Type of operation (scan, export, threat, etc.)
            data: Data to log (will be encrypted)
            operation_mode: Operation mode (stealth, normal, emergency)
            threat_level: 0-10 threat assessment
        """
        with self._lock:
            try:
                # Prepare log entry
                log_entry = {
                    'event_type': event_type,
                    'data': data,
                    'timestamp': datetime.utcnow().isoformat(),
                    'operation_mode': operation_mode,
                    'threat_level': threat_level,
                    'session_id': self.session_id,
                    'system_info': {
                        'security_level': self.security_level,
                        'anti_forensics': self.opsec_config[self.security_level]
                    }
                }
                
                # Serialize and encrypt
                json_data = json.dumps(log_entry).encode('utf-8')
                encrypted_data = self.cipher.encrypt(json_data)
                
                # Calculate MAC for tamper detection
                mac_hash = self._calculate_mac(encrypted_data)
                
                # Store in database
                conn = sqlite3.connect(str(self.db_path))
                
                # Update session tracking
                conn.execute("""
                    UPDATE session_tracking 
                    SET last_activity = ?, operations_count = operations_count + 1,
                        threat_detections = threat_detections + ?,
                        security_events = ?
                    WHERE id = 1
                """, (
                    time.time(),
                    threat_level,
                    json.dumps(self._get_recent_security_events(conn))
                ))
                
                # Insert encrypted log entry
                conn.execute("""
                    INSERT INTO opsec_events 
                    (session_id, event_type, timestamp, encrypted_data, mac_hash, 
                     operation_mode, threat_level, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.session_id,
                    event_type,
                    time.time(),
                    encrypted_data,
                    mac_hash,
                    operation_mode,
                    threat_level,
                    json.dumps({'threat_level': threat_level})
                ))
                
                conn.commit()
                conn.close()
                
                # Apply time stomping to database file
                if self.opsec_config[self.security_level]['time_stomping']:
                    self._apply_time_stomping(self.db_path)
                
            except Exception as e:
                self.logger.error(f"Failed to log operation: {e}")
    
    def _get_recent_security_events(self, conn) -> List[str]:
        """Get recent security events for context."""
        cursor = conn.execute("""
            SELECT security_events FROM session_tracking WHERE id = 1
        """)
        result = cursor.fetchone()
        if result:
            try:
                return json.loads(result[0])
            except:
                return []
        return []
    
    def retrieve_logs(self, session_id: Optional[str] = None, 
                     event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve and decrypt log entries.
        
        Args:
            session_id: Specific session to retrieve (None for all)
            event_type: Filter by event type (None for all)
            
        Returns:
            List of decrypted log entries
        """
        with self._lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                
                # Build query
                query = "SELECT encrypted_data, mac_hash FROM opsec_events WHERE 1=1"
                params = []
                
                if session_id:
                    query += " AND session_id = ?"
                    params.append(session_id)
                
                if event_type:
                    query += " AND event_type = ?"
                    params.append(event_type)
                
                query += " ORDER BY timestamp DESC"
                
                cursor = conn.execute(query, params)
                results = []
                
                for encrypted_data, mac_hash in cursor.fetchall():
                    # Verify MAC
                    if not hmac.compare_digest(mac_hash, self._calculate_mac(encrypted_data)):
                        self.logger.warning("MAC verification failed - possible tampering")
                        continue
                    
                    try:
                        # Decrypt data
                        decrypted_data = self.cipher.decrypt(encrypted_data)
                        log_entry = json.loads(decrypted_data.decode('utf-8'))
                        results.append(log_entry)
                    except Exception as e:
                        self.logger.error(f"Failed to decrypt log entry: {e}")
                        continue
                
                conn.close()
                return results
                
            except Exception as e:
                self.logger.error(f"Failed to retrieve logs: {e}")
                return []
    
    def secure_wipe_all(self):
        """Securely wipe all session data and temporary files."""
        with self._lock:
            try:
                # Wipe database
                if self.db_path.exists():
                    self._secure_delete(self.db_path)
                
                # Wipe all files in base directory
                for file_path in self.base_path.glob('*'):
                    self._secure_delete(file_path)
                
                # Wipe base directory if empty
                try:
                    self.base_path.rmdir()
                except OSError:
                    # Directory not empty, leave it
                    pass
                
                # Clear memory
                del self.cipher
                del self.encryption_key
                
                self.logger.info("All OPSEC data securely wiped")
                
            except Exception as e:
                self.logger.error(f"Failed to wipe OPSEC data: {e}")
    
    def emergency_wipe(self):
        """Emergency wipe - overwrites everything and creates decoy activity."""
        # Set to extreme security for emergency
        original_level = self.security_level
        self.security_level = 'extreme'
        
        try:
            # Rapid overwrite of database
            if self.db_path.exists():
                with open(self.db_path, 'r+b') as f:
                    for _ in range(10):  # 10 rapid overwrites
                        f.seek(0)
                        f.write(secrets.token_bytes(f.seek(0, 2)))
                        f.flush()
            
            # Create massive decoy activity
            for _ in range(50):
                decoy_path = self.base_path / f"emergency_{secrets.token_hex(8)}.tmp"
                decoy_path.write_bytes(secrets.token_bytes(1024))
                self._secure_delete(decoy_path)
            
            # Final wipe
            self.secure_wipe_all()
            
            self.logger.critical("Emergency wipe completed")
            
        finally:
            self.security_level = original_level
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get current session statistics."""
        with self._lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.execute("""
                    SELECT session_start, last_activity, operations_count, 
                           threat_detections, security_events
                    FROM session_tracking WHERE id = 1
                """)
                
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    session_start, last_activity, ops_count, threats, events = result
                    return {
                        'session_id': self.session_id,
                        'session_duration': time.time() - session_start,
                        'last_activity': last_activity,
                        'operations_count': ops_count,
                        'threat_detections': threats,
                        'security_events': json.loads(events) if events else [],
                        'security_level': self.security_level,
                        'anti_forensics_enabled': self.opsec_config[self.security_level]
                    }
                
                return {}
                
            except Exception as e:
                self.logger.error(f"Failed to get session stats: {e}")
                return {}


# Global OPSEC logger instance
_opsec_logger = None

def get_opsec_logger(security_level: str = "high") -> OPSECLogger:
    """Get or create global OPSEC logger instance."""
    global _opsec_logger
    if _opsec_logger is None:
        _opsec_logger = OPSECLogger(security_level=security_level)
    return _opsec_logger


def log_opsec_event(event_type: str, data: Dict[str, Any], 
                   operation_mode: str = "normal", threat_level: int = 0):
    """Convenience function to log OPSEC events."""
    logger = get_opsec_logger()
    logger.log_operation(event_type, data, operation_mode, threat_level)


def secure_wipe():
    """Convenience function to securely wipe all data."""
    logger = get_opsec_logger()
    logger.secure_wipe_all()


def emergency_wipe():
    """Convenience function for emergency wipe."""
    logger = get_opsec_logger()
    logger.emergency_wipe()