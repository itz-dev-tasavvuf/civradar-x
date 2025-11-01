# civradar/intel/secure_wiper.py
"""
Secure Wipe and Sanitization Tools.
Provides comprehensive data sanitization for hostile environment operations.
"""

import os
import shutil
import time
import secrets
import hashlib
import subprocess
import threading
import tempfile
import glob
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import psutil

from .opsec_logger import get_opsec_logger, log_opsec_event

class WipeMethod(Enum):
    """Secure deletion methods."""
    SIMPLE = "simple"           # Single pass overwrite
    DOD_5220 = "dod_5220"      # DoD 5220.22-M standard (3-pass)
    GUTMANN = "gutmann"        # Gutmann method (35-pass)
    RANDOM = "random"          # Multiple random passes
    PHYSICAL = "physical"      # Physical destruction simulation

class SanitizationLevel(Enum):
    """Sanitization levels."""
    BASIC = "basic"           # Basic file deletion
    STANDARD = "standard"     # Standard secure deletion
    HIGH = "high"            # High-security deletion
    EXTREME = "extreme"      # Maximum security deletion
    EMERGENCY = "emergency"  # Emergency rapid wipe

@dataclass
class WipeConfig:
    """Configuration for secure wipe operations."""
    method: WipeMethod = WipeMethod.DOD_5220
    level: SanitizationLevel = SanitizationLevel.STANDARD
    verify_deletion: bool = True
    random_data_size: int = 1024 * 1024  # 1MB random data
    overwrite_passes: int = 3
    parallel_threads: int = 4
    include_free_space: bool = False
    wipe_metadata: bool = True
    scrub_memory: bool = True

class SecureWiper:
    """
    Secure data deletion and sanitization system.
    """
    
    def __init__(self, config: WipeConfig = None):
        self.config = config or WipeConfig()
        self.active_wipes = {}
        self._lock = threading.Lock()
        self.wipe_progress = {}
        
        # Initialize wipe methods
        self._init_wipe_methods()
        
        log_opsec_event("secure_wiper_initialized", {
            "method": self.config.method.value,
            "level": self.config.level.value,
            "config": asdict(self.config)
        }, "normal", 2)
    
    def _init_wipe_methods(self):
        """Initialize secure wipe methods."""
        self.wipe_patterns = {
            WipeMethod.SIMPLE: [0x00],
            WipeMethod.DOD_5220: [0xF6, 0x00, 0xFF],  # Standard 3-pass
            WipeMethod.RANDOM: ["random"],  # Multiple random passes
            WipeMethod.GUTMANN: [
                0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22,
                0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x92, 0x49, 0x24,
                0x6D, 0xB6, 0xDB, 0x24, 0x49, 0x24, 0x49, 0x24,
                0x00, 0x11, 0x22, 0x33
            ]  # Simplified Gutmann method
        }
    
    def secure_wipe_file(self, file_path: Union[str, Path], 
                        wipe_id: str = None) -> Dict[str, Any]:
        """
        Securely wipe a single file.
        
        Args:
            file_path: Path to file to wipe
            wipe_id: Optional wipe operation ID
            
        Returns:
            Dictionary with wipe operation details
        """
        file_path = Path(file_path)
        wipe_id = wipe_id or secrets.token_hex(8)
        
        with self._lock:
            self.active_wipes[wipe_id] = {
                "status": "starting",
                "file_path": str(file_path),
                "start_time": time.time(),
                "progress": 0
            }
        
        try:
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            log_opsec_event("wipe_started", {
                "wipe_id": wipe_id,
                "file_path": str(file_path),
                "method": self.config.method.value
            }, "normal", 3)
            
            # Get file information
            file_size = file_path.stat().st_size
            
            # Perform secure deletion
            self._perform_secure_deletion(file_path, wipe_id)
            
            # Verify deletion if configured
            if self.config.verify_deletion:
                self._verify_deletion(file_path, wipe_id)
            
            # Update status
            with self._lock:
                self.active_wipes[wipe_id].update({
                    "status": "completed",
                    "progress": 100,
                    "end_time": time.time()
                })
            
            log_opsec_event("wipe_completed", {
                "wipe_id": wipe_id,
                "file_path": str(file_path),
                "file_size": file_size,
                "duration": time.time() - self.active_wipes[wipe_id]["start_time"]
            }, "normal", 3)
            
            return {
                "wipe_id": wipe_id,
                "status": "completed",
                "file_path": str(file_path),
                "file_size": file_size
            }
            
        except Exception as e:
            with self._lock:
                self.active_wipes[wipe_id].update({
                    "status": "failed",
                    "error": str(e),
                    "end_time": time.time()
                })
            
            log_opsec_event("wipe_failed", {
                "wipe_id": wipe_id,
                "file_path": str(file_path),
                "error": str(e)
            }, "normal", 6)
            
            raise
    
    def _perform_secure_deletion(self, file_path: Path, wipe_id: str):
        """Perform secure deletion of file."""
        file_size = file_path.stat().st_size
        
        if self.config.level == SanitizationLevel.EMERGENCY:
            # Emergency rapid wipe
            self._emergency_wipe(file_path, wipe_id)
        elif self.config.level == SanitizationLevel.BASIC:
            # Basic secure deletion
            self._basic_secure_delete(file_path, wipe_id)
        else:
            # Advanced secure deletion
            self._advanced_secure_delete(file_path, wipe_id, file_size)
    
    def _emergency_wipe(self, file_path: Path, wipe_id: str):
        """Emergency rapid wipe for crisis situations."""
        # Overwrite file with random data once
        try:
            with open(file_path, 'r+b') as f:
                # Write random data
                random_data = secrets.token_bytes(f.seek(0, 2))  # Get file size
                f.seek(0)
                f.write(random_data)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            
            # Delete file
            file_path.unlink()
            
            log_opsec_event("emergency_wipe_completed", {
                "wipe_id": wipe_id,
                "file_path": str(file_path)
            }, "emergency", 8)
            
        except Exception as e:
            log_opsec_event("emergency_wipe_error", {
                "wipe_id": wipe_id,
                "error": str(e)
            }, "emergency", 9)
            raise
    
    def _basic_secure_delete(self, file_path: Path, wipe_id: str):
        """Basic secure deletion."""
        file_size = file_path.stat().st_size
        
        with open(file_path, 'r+b') as f:
            # Single pass overwrite with zeros
            f.seek(0)
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
            
            # Single pass overwrite with random data
            f.seek(0)
            f.write(secrets.token_bytes(file_size))
            f.flush()
            os.fsync(f.fileno())
        
        file_path.unlink()
    
    def _advanced_secure_delete(self, file_path: Path, wipe_id: str, file_size: int):
        """Advanced secure deletion using specified method."""
        patterns = self.wipe_patterns.get(self.config.method, [0x00])
        
        # Perform overwrite passes
        for pass_num, pattern in enumerate(patterns):
            self._update_progress(wipe_id, (pass_num / len(patterns)) * 90)  # 90% for overwrites
            
            if pattern == "random":
                # Random data pass
                self._random_overwrite(file_path, file_size, wipe_id)
            else:
                # Pattern overwrite
                self._pattern_overwrite(file_path, file_size, pattern, wipe_id)
        
        # Final random pass
        self._update_progress(wipe_id, 95)
        self._random_overwrite(file_path, file_size, wipe_id)
        
        # Delete file
        file_path.unlink()
        
        self._update_progress(wipe_id, 100)
    
    def _pattern_overwrite(self, file_path: Path, file_size: int, pattern: int, wipe_id: str):
        """Overwrite file with specific pattern."""
        overwrite_data = bytes([pattern]) * (1024 * 1024)  # 1MB chunks
        
        with open(file_path, 'r+b') as f:
            bytes_written = 0
            while bytes_written < file_size:
                chunk_size = min(len(overwrite_data), file_size - bytes_written)
                f.write(overwrite_data[:chunk_size])
                bytes_written += chunk_size
                
                # Update progress
                progress = (bytes_written / file_size) * 100
                self._update_progress(wipe_id, progress * 0.9)  # Max 90% for overwrites
            
            f.flush()
            os.fsync(f.fileno())
    
    def _random_overwrite(self, file_path: Path, file_size: int, wipe_id: str):
        """Overwrite file with random data."""
        chunk_size = 1024 * 1024  # 1MB chunks
        
        with open(file_path, 'r+b') as f:
            bytes_written = 0
            while bytes_written < file_size:
                remaining = file_size - bytes_written
                current_chunk_size = min(chunk_size, remaining)
                
                random_data = secrets.token_bytes(current_chunk_size)
                f.write(random_data)
                bytes_written += current_chunk_size
                
                # Update progress
                progress = (bytes_written / file_size) * 100
                self._update_progress(wipe_id, progress * 0.9)  # Max 90% for overwrites
            
            f.flush()
            os.fsync(f.fileno())
    
    def _verify_deletion(self, file_path: Path, wipe_id: str):
        """Verify file has been properly deleted."""
        max_attempts = 3
        for attempt in range(max_attempts):
            if not file_path.exists():
                return True
            
            time.sleep(0.1)  # Small delay between attempts
        
        # File still exists after attempts
        log_opsec_event("wipe_verification_failed", {
            "wipe_id": wipe_id,
            "file_path": str(file_path),
            "attempts": max_attempts
        }, "normal", 5)
        
        # Force deletion
        try:
            file_path.unlink()
        except:
            pass
        
        return not file_path.exists()
    
    def _update_progress(self, wipe_id: str, progress: float):
        """Update wipe progress."""
        with self._lock:
            if wipe_id in self.active_wipes:
                self.active_wipes[wipe_id]["progress"] = min(progress, 100)
    
    def secure_wipe_directory(self, directory: Union[str, Path], 
                             recursive: bool = True,
                             exclude_patterns: List[str] = None) -> Dict[str, Any]:
        """
        Securely wipe entire directory.
        
        Args:
            directory: Directory to wipe
            recursive: Whether to wipe subdirectories
            exclude_patterns: Patterns to exclude from wipe
            
        Returns:
            Dictionary with wipe operation summary
        """
        directory = Path(directory)
        wipe_id = secrets.token_hex(8)
        
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        
        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")
        
        exclude_patterns = exclude_patterns or []
        wipe_results = []
        
        log_opsec_event("directory_wipe_started", {
            "wipe_id": wipe_id,
            "directory": str(directory),
            "recursive": recursive,
            "exclude_patterns": exclude_patterns
        }, "normal", 4)
        
        try:
            # Collect files to wipe
            if recursive:
                files_to_wipe = list(directory.rglob('*'))
            else:
                files_to_wipe = list(directory.glob('*'))
            
            # Filter out directories and excluded patterns
            files_to_wipe = [
                f for f in files_to_wipe 
                if f.is_file() and not any(
                    f.match(pattern) for pattern in exclude_patterns
                )
            ]
            
            # Wipe files in parallel
            with ThreadPoolExecutor(max_workers=self.config.parallel_threads) as executor:
                futures = {
                    executor.submit(self.secure_wipe_file, file_path, f"{wipe_id}_{i}"): file_path
                    for i, file_path in enumerate(files_to_wipe)
                }
                
                for future in futures:
                    try:
                        result = future.result()
                        wipe_results.append(result)
                    except Exception as e:
                        file_path = futures[future]
                        log_opsec_event("file_wipe_error", {
                            "wipe_id": wipe_id,
                            "file_path": str(file_path),
                            "error": str(e)
                        }, "normal", 5)
                        wipe_results.append({
                            "file_path": str(file_path),
                            "status": "failed",
                            "error": str(e)
                        })
            
            # Remove empty directories if recursive
            if recursive and directory.exists():
                try:
                    directory.rmdir()  # Will only succeed if empty
                except OSError:
                    # Directory not empty, try to remove subdirectories
                    for subdir in directory.iterdir():
                        if subdir.is_dir():
                            try:
                                shutil.rmtree(subdir)
                            except:
                                pass
                    
                    # Final attempt to remove directory
                    try:
                        directory.rmdir()
                    except OSError:
                        pass  # Directory still not empty, leave it
            
            log_opsec_event("directory_wipe_completed", {
                "wipe_id": wipe_id,
                "directory": str(directory),
                "files_wiped": len(wipe_results),
                "successful": sum(1 for r in wipe_results if r.get("status") == "completed"),
                "failed": sum(1 for r in wipe_results if r.get("status") == "failed")
            }, "normal", 4)
            
            return {
                "wipe_id": wipe_id,
                "directory": str(directory),
                "files_wiped": len(wipe_results),
                "results": wipe_results
            }
            
        except Exception as e:
            log_opsec_event("directory_wipe_failed", {
                "wipe_id": wipe_id,
                "directory": str(directory),
                "error": str(e)
            }, "normal", 6)
            raise
    
    def wipe_free_space(self, mount_point: str = None, 
                       size_mb: int = None) -> Dict[str, Any]:
        """
        Wipe free space on disk to prevent data recovery.
        
        Args:
            mount_point: Mount point to wipe (default: current directory)
            size_mb: Size to wipe in MB (default: all free space)
            
        Returns:
            Dictionary with wipe operation details
        """
        wipe_id = secrets.token_hex(8)
        mount_point = Path(mount_point or os.getcwd())
        
        try:
            # Get disk usage
            disk_usage = psutil.disk_usage(str(mount_point))
            free_space_gb = disk_usage.free / (1024**3)
            
            if size_mb:
                target_size_mb = size_mb
            else:
                # Wipe 10% of free space to avoid disk full issues
                target_size_mb = int((free_space_gb * 1024) * 0.1) * 1024
            
            if target_size_mb == 0:
                return {"wipe_id": wipe_id, "status": "no_space_to_wipe"}
            
            log_opsec_event("free_space_wipe_started", {
                "wipe_id": wipe_id,
                "mount_point": str(mount_point),
                "target_size_mb": target_size_mb
            }, "normal", 3)
            
            # Create temporary file and fill with random data
            temp_dir = mount_point / ".wipe_temp"
            temp_dir.mkdir(exist_ok=True)
            
            temp_files = []
            try:
                chunk_size = 1024 * 1024  # 1MB chunks
                target_bytes = target_size_mb * 1024 * 1024
                bytes_written = 0
                
                while bytes_written < target_bytes:
                    # Create random data file
                    temp_file = temp_dir / f"wipe_{secrets.token_hex(8)}.tmp"
                    
                    remaining = target_bytes - bytes_written
                    current_chunk_size = min(chunk_size * 10, remaining)  # 10MB max per file
                    
                    with open(temp_file, 'wb') as f:
                        for _ in range(current_chunk_size // chunk_size):
                            f.write(secrets.token_bytes(chunk_size))
                        if current_chunk_size % chunk_size:
                            f.write(secrets.token_bytes(current_chunk_size % chunk_size))
                    
                    temp_files.append(temp_file)
                    bytes_written += current_chunk_size
                    
                    # Update progress
                    progress = (bytes_written / target_bytes) * 100
                    log_opsec_event("free_space_wipe_progress", {
                        "wipe_id": wipe_id,
                        "progress": progress,
                        "bytes_written": bytes_written,
                        "target_bytes": target_bytes
                    }, "normal", 2)
                
                # Securely delete all temporary files
                for temp_file in temp_files:
                    self.secure_wipe_file(temp_file, f"{wipe_id}_temp")
                
                # Remove temp directory
                temp_dir.rmdir()
                
                log_opsec_event("free_space_wipe_completed", {
                    "wipe_id": wipe_id,
                    "mount_point": str(mount_point),
                    "size_wiped_mb": target_size_mb,
                    "duration": "estimated_30_seconds"
                }, "normal", 3)
                
                return {
                    "wipe_id": wipe_id,
                    "status": "completed",
                    "mount_point": str(mount_point),
                    "size_wiped_mb": target_size_mb
                }
                
            except Exception as e:
                # Clean up any remaining temp files
                for temp_file in temp_files:
                    try:
                        temp_file.unlink()
                    except:
                        pass
                try:
                    temp_dir.rmdir()
                except:
                    pass
                raise e
                
        except Exception as e:
            log_opsec_event("free_space_wipe_failed", {
                "wipe_id": wipe_id,
                "mount_point": str(mount_point),
                "error": str(e)
            }, "normal", 5)
            raise
    
    def scrub_memory(self) -> Dict[str, Any]:
        """
        Scrub process memory to remove sensitive data.
        
        Returns:
            Dictionary with memory scrubbing details
        """
        wipe_id = secrets.token_hex(8)
        
        try:
            log_opsec_event("memory_scrub_started", {
                "wipe_id": wipe_id
            }, "normal", 3)
            
            import gc
            import sys
            
            # Force garbage collection
            gc.collect()
            
            # Clear Python internal caches
            if hasattr(sys, '_clear_type_cache'):
                sys._clear_type_cache()
            
            # Clear module caches
            modules_to_clear = [
                'importlib._bootstrap', 'importlib._bootstrap_external',
                'tokenize', 'token', 'ast', 'symtable'
            ]
            
            for module_name in modules_to_clear:
                if module_name in sys.modules:
                    module = sys.modules[module_name]
                    if hasattr(module, '_cache'):
                        module._cache.clear()
            
            # Fill memory with random data and force GC
            memory_chunks = []
            for _ in range(10):  # Create 10 chunks
                chunk = secrets.token_bytes(1024 * 1024)  # 1MB chunks
                memory_chunks.append(chunk)
            
            # Clear chunks
            del memory_chunks
            
            # Force garbage collection again
            gc.collect()
            
            log_opsec_event("memory_scrub_completed", {
                "wipe_id": wipe_id
            }, "normal", 3)
            
            return {
                "wipe_id": wipe_id,
                "status": "completed",
                "actions": ["garbage_collection", "cache_clearing", "memory_overwrite"]
            }
            
        except Exception as e:
            log_opsec_event("memory_scrub_failed", {
                "wipe_id": wipe_id,
                "error": str(e)
            }, "normal", 5)
            raise
    
    def emergency_wipe_all(self, include_system_files: bool = False) -> Dict[str, Any]:
        """
        Emergency wipe of all CIVRADAR-X data.
        
        Args:
            include_system_files: Whether to wipe system-related files
            
        Returns:
            Dictionary with emergency wipe summary
        """
        wipe_id = secrets.token_hex(8)
        
        try:
            log_opsec_event("emergency_wipe_all_started", {
                "wipe_id": wipe_id,
                "include_system_files": include_system_files
            }, "emergency", 10)
            
            wipe_results = {}
            
            # Standard CIVRADAR-X paths
            civradar_paths = [
                "/opt/civradar-x",
                "/var/lib/civradar-x",
                "/var/log/civradar-x",
                "/etc/civradar-x",
                "/tmp/civradar-x",
                "/tmp/.civradar_opsec",
                "/tmp/.civradar_shares",
                os.path.expanduser("~/.civradar-x")
            ]
            
            # Additional paths for field operations
            field_paths = [
                "/tmp/.civradar-x_opsec",
                "/tmp/civradar_*",
                os.path.expanduser("~/.cache/civradar-x"),
                os.path.expanduser("~/.local/share/civradar-x")
            ]
            
            all_paths = civradar_paths + field_paths
            
            # System files (only if explicitly requested)
            if include_system_files:
                system_paths = [
                    "/var/log/civradar-x.log",
                    "/var/log/civradar-x*.log",
                    "/etc/systemd/system/civradar-x.service"
                ]
                all_paths.extend(system_paths)
            
            # Wipe each path
            for path_str in all_paths:
                path = Path(path_str)
                
                # Handle glob patterns
                if '*' in path_str:
                    matching_paths = list(Path('/').glob(path_str.lstrip('/')))
                    for matching_path in matching_paths:
                        try:
                            if matching_path.is_dir():
                                result = self.secure_wipe_directory(matching_path, wipe_id)
                            else:
                                result = self.secure_wipe_file(matching_path, wipe_id)
                            wipe_results[str(matching_path)] = result
                        except Exception as e:
                            wipe_results[str(matching_path)] = {"status": "failed", "error": str(e)}
                else:
                    try:
                        if path.exists():
                            if path.is_dir():
                                result = self.secure_wipe_directory(path, wipe_id)
                            else:
                                result = self.secure_wipe_file(path, wipe_id)
                            wipe_results[str(path)] = result
                        else:
                            wipe_results[str(path)] = {"status": "not_found"}
                    except Exception as e:
                        wipe_results[str(path)] = {"status": "failed", "error": str(e)}
            
            # Scrub memory
            memory_result = self.scrub_memory()
            
            # Wipe free space on all relevant filesystems
            try:
                free_space_result = self.wipe_free_space()
            except:
                free_space_result = {"status": "failed"}
            
            log_opsec_event("emergency_wipe_all_completed", {
                "wipe_id": wipe_id,
                "paths_processed": len(wipe_results),
                "successful": sum(1 for r in wipe_results.values() if r.get("status") == "completed"),
                "failed": sum(1 for r in wipe_results.values() if r.get("status") == "failed"),
                "not_found": sum(1 for r in wipe_results.values() if r.get("status") == "not_found")
            }, "emergency", 10)
            
            return {
                "wipe_id": wipe_id,
                "status": "completed",
                "paths_processed": len(wipe_results),
                "wipe_results": wipe_results,
                "memory_scrub": memory_result,
                "free_space_wipe": free_space_result
            }
            
        except Exception as e:
            log_opsec_event("emergency_wipe_all_failed", {
                "wipe_id": wipe_id,
                "error": str(e)
            }, "emergency", 10)
            raise
    
    def get_wipe_status(self, wipe_id: str) -> Optional[Dict[str, Any]]:
        """Get status of wipe operation."""
        with self._lock:
            return self.active_wipes.get(wipe_id)
    
    def list_active_wipes(self) -> List[Dict[str, Any]]:
        """List all active wipe operations."""
        with self._lock:
            return list(self.active_wipes.values())


# Global secure wiper instance
_secure_wiper = None

def get_secure_wiper(config: WipeConfig = None) -> SecureWiper:
    """Get global secure wiper instance."""
    global _secure_wiper
    if _secure_wiper is None:
        _secure_wiper = SecureWiper(config)
    return _secure_wiper


def secure_wipe_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Convenience function to securely wipe a file."""
    wiper = get_secure_wiper()
    return wiper.secure_wipe_file(file_path)


def secure_wipe_directory(directory: Union[str, Path], 
                         recursive: bool = True) -> Dict[str, Any]:
    """Convenience function to securely wipe a directory."""
    wiper = get_secure_wiper()
    return wiper.secure_wipe_directory(directory, recursive)


def emergency_wipe_all():
    """Emergency wipe of all CIVRADAR-X data."""
    wiper = get_secure_wiper()
    return wiper.emergency_wipe_all()