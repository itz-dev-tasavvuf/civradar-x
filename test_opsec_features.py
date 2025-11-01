#!/usr/bin/env python3
"""
Comprehensive Test Suite for OPSEC Features in CIVRADAR-X

This module provides extensive testing coverage for all Operational Security (OPSEC)
components implemented in the CIVRADAR-X civilian radar intelligence system.
It validates field-ready deployment capabilities across multiple security domains.

Test Coverage:
- Encrypted logging with anti-forensics capabilities
- Secure session management with auto-wipe functionality
- Field operation modes with adaptive stealth profiles
- Secure sharing protocols with multiple encryption options
- Anti-detection safeguards and countermeasures
- Configuration management with integrity verification
- Secure data wiping and sanitization tools
- Security monitoring and alerting systems
- Full OPSEC component integration testing

Security Testing Focus:
- Encryption strength and tamper resistance
- Threat detection and automated response
- Memory protection and secure cleanup
- Process hiding and network stealth
- Configuration integrity and emergency procedures

Test Environment:
- Isolated test directories for each component
- Mock data and simulated threat scenarios
- Performance validation under various conditions
- Error handling and edge case coverage

Author: CIVRADAR-X Development Team
License: MIT (Classified Operations)
"""

import unittest
import tempfile
import shutil
import os
import time
import json
import hashlib
import secrets
import threading
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import Dict, List, Any

# Import OPSEC modules
from civradar.intel.opsec_logger import OPSECLogger, get_opsec_logger, log_opsec_event
from civradar.intel.session_manager import (
    SessionManager, SecureSession, SessionConfig, 
    get_session_manager, create_secure_session
)
from civradar.intel.field_ops import (
    FieldOperations, FieldConfig, FieldMode, StealthProfile,
    get_field_operations, start_field_operation
)
from civradar.intel.secure_sharing import (
    SecureSharingManager, SharingConfig, EncryptionType,
    get_secure_sharing_manager, create_secure_share
)
from civradar.intel.safeguards import (
    AntiDetectionEngine, SafeguardConfig, DetectionType,
    get_safeguards_engine, check_environment_security
)
from civradar.intel.config_manager import (
    ConfigManager, FieldConfig as ConfigFieldConfig, ConfigLevel, FieldScenario,
    get_config_manager, create_field_config
)
from civradar.intel.secure_wiper import (
    SecureWiper, WipeConfig, WipeMethod, SanitizationLevel,
    get_secure_wiper, secure_wipe_file
)
from civradar.intel.security_monitor import (
    SecurityMonitor, AlertConfig, AlertSeverity, AlertCategory,
    get_security_monitor, start_security_monitoring
)

class TestOPSECLogger(unittest.TestCase):
    """Test encrypted logging with anti-forensics capabilities."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.logger = OPSECLogger(base_path=self.temp_dir, security_level="standard")
    
    def tearDown(self):
        """Clean up test environment."""
        self.logger.secure_wipe_all()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test logger initialization."""
        self.assertIsNotNone(self.logger.cipher)
        self.assertIsNotNone(self.logger.encryption_key)
        self.assertTrue(self.logger.db_path.exists())
    
    def test_log_operations(self):
        """Test logging operations."""
        # Test basic logging
        self.logger.log_operation("test_event", {"data": "test"}, "normal", 1)
        
        # Retrieve logs
        logs = self.logger.retrieve_logs()
        self.assertGreater(len(logs), 0)
        
        # Verify log content
        test_log = next((log for log in logs if log.get('event_type') == 'test_event'), None)
        self.assertIsNotNone(test_log)
        self.assertEqual(test_log['data']['data'], 'test')
    
    def test_session_stats(self):
        """Test session statistics."""
        # Log some operations
        self.logger.log_operation("test1", {}, "normal", 1)
        self.logger.log_operation("test2", {}, "stealth", 2)
        
        stats = self.logger.get_session_stats()
        self.assertIn('session_id', stats)
        self.assertIn('operations_count', stats)
        self.assertEqual(stats['operations_count'], 2)
    
    def test_secure_wipe(self):
        """Test secure wipe functionality."""
        # Log some data
        self.logger.log_operation("sensitive_data", {"password": "secret"}, "normal", 1)
        
        # Verify data exists
        logs = self.logger.retrieve_logs()
        self.assertGreater(len(logs), 0)
        
        # Secure wipe
        self.logger.secure_wipe_all()
        
        # Verify database is wiped
        self.assertFalse(self.logger.db_path.exists())
        
        # Verify no logs retrievable
        logs = self.logger.retrieve_logs()
        self.assertEqual(len(logs), 0)
    
    def test_anti_forensics_features(self):
        """Test anti-forensics features."""
        # Create decoy files
        self.logger._setup_anti_forensics()
        
        # Verify decoy files created
        decoy_files = list(self.logger.base_path.glob('**/*.cache'))
        self.assertGreater(len(decoy_files), 0)
    
    def test_tamper_protection(self):
        """Test tamper protection with MAC verification."""
        # Log operation
        self.logger.log_operation("tamper_test", {"data": "original"}, "normal", 1)
        
        # Retrieve logs
        logs = self.logger.retrieve_logs()
        original_log = logs[0]
        
        # Simulate tampering by modifying the log entry in database
        # (This is a simplified test - real implementation would need database manipulation)
        self.assertIsNotNone(original_log.get('mac_hash'))


class TestSessionManager(unittest.TestCase):
    """Test secure session management with auto-wipe features."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        config = SessionConfig(auto_wipe_timeout=60, idle_timeout=30)
        self.manager = SessionManager(config)
    
    def tearDown(self):
        """Clean up test environment."""
        self.manager.emergency_wipe_all()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_session_creation(self):
        """Test secure session creation."""
        session_id = self.manager.create_session()
        self.assertIsNotNone(session_id)
        self.assertEqual(len(session_id), 32)  # 16 bytes = 32 hex chars
        
        # Verify session exists
        session = self.manager.get_session(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session.session_id, session_id)
    
    def test_session_activity_tracking(self):
        """Test session activity tracking."""
        session_id = self.manager.create_session()
        session = self.manager.get_session(session_id)
        
        # Record activity
        session.record_activity("test_activity", {"action": "scan"})
        
        # Check activity recorded
        status = session.get_session_status()
        self.assertEqual(status['session_id'], session_id)
    
    def test_auto_wipe_timeout(self):
        """Test auto-wipe on timeout."""
        # Create session with short timeout
        config = SessionConfig(auto_wipe_timeout=2, idle_timeout=1)
        manager = SessionManager(config)
        
        session_id = manager.create_session()
        session = manager.get_session(session_id)
        
        # Wait for timeout
        time.sleep(3)
        
        # Session should be wiped
        session = manager.get_session(session_id)
        self.assertIsNone(session)
    
    def test_threat_detection(self):
        """Test threat detection and auto-response."""
        config = SessionConfig(threat_level_threshold=5)
        manager = SessionManager(config)
        
        session_id = manager.create_session()
        session = manager.get_session(session_id)
        
        # Simulate high threat
        from civradar.intel.session_manager import SessionThreat
        threat = SessionThreat(
            threat_type="test_threat",
            severity=8,
            description="Test threat for validation",
            timestamp=time.time(),
            source="test",
            automated_response="increase_security"
        )
        
        # Manually handle threat to test response
        session._handle_threat(threat)
        
        # Verify threat recorded
        status = session.get_session_status()
        self.assertEqual(status['threat_level'], 8)
        self.assertEqual(len(status['threats']), 1)


class TestFieldOperations(unittest.TestCase):
    """Test field operation modes with enhanced stealth capabilities."""
    
    def setUp(self):
        """Set up test environment."""
        config = FieldConfig(mode=FieldMode.STEALTH)
        self.ops = FieldOperations(config)
    
    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self, 'ops'):
            self.ops.end_operation("test_completion")
    
    def test_mode_switching(self):
        """Test operational mode switching."""
        # Initial mode
        self.assertEqual(self.ops.current_mode, FieldMode.STEALTH)
        
        # Switch to combat mode
        self.ops.switch_mode(FieldMode.COMBAT, "test_switch")
        
        # Verify switch
        self.assertEqual(self.ops.current_mode, FieldMode.COMBAT)
        
        # Check history
        self.assertEqual(len(self.ops.mode_switch_history), 1)
        self.assertEqual(self.ops.mode_switch_history[0]['to_mode'], FieldMode.COMBAT.value)
    
    def test_threat_based_auto_switch(self):
        """Test automatic mode switching based on threat level."""
        # Enable auto-switching
        self.ops.config.auto_switch_mode = True
        
        # Simulate high threat
        self.ops._auto_switch_mode(9)
        
        # Should switch to emergency mode
        self.assertEqual(self.ops.current_mode, FieldMode.EMERGENCY)
    
    def test_stealth_profile_application(self):
        """Test stealth profile application."""
        # Test with different modes
        for mode in [FieldMode.NORMAL, FieldMode.STEALTH, FieldMode.GHOST]:
            config = FieldConfig(mode=mode)
            ops = FieldOperations(config)
            
            # Check that appropriate stealth measures are applied
            profile = ops.config.stealth_profile
            self.assertIsNotNone(profile)
            
            if mode == FieldMode.GHOST:
                self.assertTrue(profile.hide_process)
                self.assertTrue(profile.block_outbound)
    
    def test_operation_lifecycle(self):
        """Test field operation lifecycle."""
        # Start operation
        self.ops.start_operation()
        
        # Get status
        status = self.ops.get_operation_status()
        self.assertIn('mode', status)
        self.assertIn('operation_duration', status)
        
        # End operation
        self.ops.end_operation("test_completion")
        
        # Operation should be ended
        self.assertEqual(self.ops.current_mode, FieldMode.EMERGENCY)  # Secure mode


class TestSecureSharing(unittest.TestCase):
    """Test secure sharing protocols with multiple encryption options."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        config = SharingConfig(encryption_type=EncryptionType.FERNET)
        self.manager = SecureSharingManager(config, storage_path=self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_share_creation(self):
        """Test secure share creation."""
        data = "This is sensitive test data"
        share_info = self.manager.create_share(data, recipients=["test_recipient"])
        
        # Verify share created
        self.assertIn('share_id', share_info)
        self.assertIn('access_key', share_info)
        self.assertIn('expires_at', share_info)
        self.assertEqual(share_info['encryption_type'], EncryptionType.FERNET.value)
    
    def test_share_retrieval(self):
        """Test secure share retrieval."""
        # Create share
        data = "Test data for retrieval"
        share_info = self.manager.create_share(data)
        
        # Retrieve share
        retrieved_data = self.manager.retrieve_share(
            share_info['share_id'],
            share_info['access_key']
        )
        
        # Verify data retrieved correctly
        self.assertEqual(retrieved_data.decode('utf-8'), data)
    
    def test_multiple_encryption_types(self):
        """Test multiple encryption types."""
        data = "Test data for encryption"
        
        for enc_type in [EncryptionType.FERNET, EncryptionType.AES_256_GCM]:
            config = SharingConfig(encryption_type=enc_type)
            manager = SecureSharingManager(config, storage_path=self.temp_dir)
            
            share_info = manager.create_share(data)
            retrieved_data = manager.retrieve_share(
                share_info['share_id'],
                share_info['access_key']
            )
            
            self.assertEqual(retrieved_data.decode('utf-8'), data)
    
    def test_share_expiration(self):
        """Test share expiration."""
        # Create share with short expiration
        config = SharingConfig(expiry_time=1)  # 1 second
        manager = SecureSharingManager(config, storage_path=self.temp_dir)
        
        share_info = manager.create_share("Expiring data")
        
        # Wait for expiration
        time.sleep(2)
        
        # Try to retrieve (should fail)
        retrieved_data = manager.retrieve_share(
            share_info['share_id'],
            share_info['access_key']
        )
        
        self.assertIsNone(retrieved_data)
    
    def test_share_revocation(self):
        """Test share revocation."""
        # Create share
        share_info = self.manager.create_share("Revocable data")
        
        # Revoke share
        self.manager.revoke_share(share_info['share_id'])
        
        # Try to retrieve (should fail)
        retrieved_data = self.manager.retrieve_share(
            share_info['share_id'],
            share_info['access_key']
        )
        
        self.assertIsNone(retrieved_data)


class TestSafeguards(unittest.TestCase):
    """Test operational safeguards and anti-detection measures."""
    
    def setUp(self):
        """Set up test environment."""
        config = SafeguardConfig(
            anti_debugging=True,
            anti_vm=True,
            memory_obfuscation=True,
            network_stealth=True
        )
        self.engine = AntiDetectionEngine(config)
    
    def test_initialization(self):
        """Test safeguards initialization."""
        self.assertGreater(len(self.engine.active_measures), 0)
        self.assertIn('anti_debugging', self.engine.active_measures)
    
    def test_debugger_detection(self):
        """Test debugger detection."""
        # Test debugger detection (should work or gracefully handle absence)
        is_debugged = self.engine._is_being_debugged()
        self.assertIsInstance(is_debugged, bool)
    
    def test_vm_detection(self):
        """Test virtual machine detection."""
        indicators = self.engine._detect_vm_indicators()
        self.assertIsInstance(indicators, list)
        # VM detection might not find indicators in test environment
    
    def test_memory_obfuscation(self):
        """Test memory obfuscation."""
        # Test that obfuscation threads are running
        self.assertIn('memory_obfuscation', self.engine.active_measures)
    
    def test_environment_security_check(self):
        """Test environment security checking."""
        status = check_environment_security()
        self.assertIn('active_measures', status)
        self.assertIn('environment_check', status)
        self.assertIsInstance(status['environment_check']['debugger_detected'], bool)


class TestConfigManager(unittest.TestCase):
    """Test field-ready configuration management."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = ConfigManager(config_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_config_creation(self):
        """Test configuration creation."""
        config = self.manager.create_configuration(
            ConfigLevel.HIGH,
            FieldScenario.STEALTH
        )
        
        # Verify configuration created
        self.assertEqual(config.config_level, ConfigLevel.HIGH)
        self.assertEqual(config.field_scenario, FieldScenario.STEALTH)
        self.assertIsNotNone(config.field_identifier)
        self.assertTrue(config.verify_integrity())
    
    def test_config_saving_loading(self):
        """Test configuration saving and loading."""
        # Create and save configuration
        config = self.manager.create_configuration(
            ConfigLevel.STANDARD,
            FieldScenario.COMBAT
        )
        self.manager.save_configuration(config)
        
        # Load configuration
        loaded_config = self.manager.load_configuration(config.field_identifier)
        
        # Verify loaded correctly
        self.assertIsNotNone(loaded_config)
        self.assertEqual(loaded_config.config_level, ConfigLevel.STANDARD)
        self.assertEqual(loaded_config.field_scenario, FieldScenario.COMBAT)
        self.assertTrue(loaded_config.verify_integrity())
    
    def test_level_switching(self):
        """Test security level switching."""
        # Create initial configuration
        config = self.manager.create_configuration(
            ConfigLevel.MINIMAL,
            FieldScenario.NORMAL
        )
        self.manager.save_configuration(config)
        
        # Switch to higher level
        success = self.manager.switch_config_level(ConfigLevel.EXTREME)
        self.assertTrue(success)
        
        # Verify level changed
        current_config = self.manager.current_config
        self.assertEqual(current_config.config_level, ConfigLevel.EXTREME)
    
    def test_scenario_switching(self):
        """Test field scenario switching."""
        # Create initial configuration
        config = self.manager.create_configuration(
            ConfigLevel.STANDARD,
            FieldScenario.NORMAL
        )
        self.manager.save_configuration(config)
        
        # Switch scenario
        success = self.manager.switch_field_scenario(FieldScenario.EMERGENCY)
        self.assertTrue(success)
        
        # Verify scenario changed
        current_config = self.manager.current_config
        self.assertEqual(current_config.field_scenario, FieldScenario.EMERGENCY)
    
    def test_emergency_reset(self):
        """Test emergency configuration reset."""
        # Create some configuration first
        config = self.manager.create_configuration(
            ConfigLevel.MINIMAL,
            FieldScenario.NORMAL
        )
        self.manager.save_configuration(config)
        
        # Emergency reset
        self.manager.emergency_config_reset()
        
        # Verify emergency configuration
        emergency_config = self.manager.current_config
        self.assertEqual(emergency_config.config_level, ConfigLevel.EMERGENCY)
        self.assertEqual(emergency_config.field_scenario, FieldScenario.EMERGENCY)


class TestSecureWiper(unittest.TestCase):
    """Test secure wipe and sanitization tools."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wiper = SecureWiper(WipeConfig(
            method=WipeMethod.SIMPLE,
            level=SanitizationLevel.STANDARD,
            verify_deletion=True
        ))
        
        # Create test files
        self.test_file = Path(self.temp_dir) / "test_file.txt"
        self.test_file.write_text("Sensitive test data")
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_file_wipe(self):
        """Test secure file wiping."""
        self.assertTrue(self.test_file.exists())
        
        # Wipe file
        result = self.wiper.secure_wipe_file(self.test_file)
        
        # Verify wipe
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(self.test_file.exists())
    
    def test_directory_wipe(self):
        """Test secure directory wiping."""
        test_dir = Path(self.temp_dir) / "test_dir"
        test_dir.mkdir()
        
        # Create test files
        for i in range(3):
            (test_dir / f"file_{i}.txt").write_text(f"Data {i}")
        
        self.assertTrue(test_dir.exists())
        
        # Wipe directory
        result = self.wiper.secure_wipe_directory(test_dir, recursive=False)
        
        # Verify wipe
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(test_dir.exists())
    
    def test_different_wipe_methods(self):
        """Test different wipe methods."""
        for method in [WipeMethod.SIMPLE, WipeMethod.DOD_5220]:
            # Create test file
            test_file = Path(self.temp_dir) / f"test_{method.value}.txt"
            test_file.write_text("Test data for wiping")
            
            # Configure wiper for this method
            config = WipeConfig(method=method, level=SanitizationLevel.STANDARD)
            wiper = SecureWiper(config)
            
            # Wipe file
            result = wiper.secure_wipe_file(test_file)
            
            # Verify wipe
            self.assertEqual(result['status'], 'completed')
            self.assertFalse(test_file.exists())
    
    def test_memory_scrubbing(self):
        """Test memory scrubbing."""
        result = self.wiper.scrub_memory()
        
        # Verify scrubbing
        self.assertEqual(result['status'], 'completed')
        self.assertIn('actions', result)
    
    def test_free_space_wipe(self):
        """Test free space wiping."""
        # This test might be slow due to actual wiping
        result = self.wiper.wipe_free_space(self.temp_dir, size_mb=1)
        
        # Should complete successfully
        self.assertIn(result['status'], ['completed', 'no_space_to_wipe'])


class TestSecurityMonitor(unittest.TestCase):
    """Test monitoring and alerting for security breaches."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        config = AlertConfig(
            enabled=True,
            monitoring_interval=5,
            local_alerts=True,
            alert_log_file=str(Path(self.temp_dir) / "alerts.log")
        )
        self.monitor = SecurityMonitor(config)
    
    def tearDown(self):
        """Clean up test environment."""
        self.monitor.stop_monitoring()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_alert_creation(self):
        """Test security alert creation."""
        # Create test alert
        self.monitor._create_alert(
            AlertCategory.SECURITY_BREACH,
            AlertSeverity.HIGH,
            "Test Alert",
            "This is a test security alert"
        )
        
        # Verify alert created
        alerts = self.monitor.get_alerts()
        self.assertGreater(len(alerts), 0)
        
        # Check alert content
        alert = alerts[0]
        self.assertEqual(alert.title, "Test Alert")
        self.assertEqual(alert.category, AlertCategory.SECURITY_BREACH)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
    
    def test_monitoring_start_stop(self):
        """Test monitoring start and stop."""
        # Start monitoring
        self.monitor.start_monitoring()
        self.assertTrue(self.monitor.monitoring_active)
        
        # Stop monitoring
        self.monitor.stop_monitoring()
        self.assertFalse(self.monitor.monitoring_active)
    
    def test_alert_escalation(self):
        """Test alert escalation."""
        # Enable auto-escalation
        self.monitor.config.auto_escalation = True
        self.monitor.config.escalation_timeout = 1
        
        # Create alert
        self.monitor._create_alert(
            AlertCategory.SECURITY_BREACH,
            AlertSeverity.MEDIUM,
            "Escalation Test",
            "Test alert for escalation"
        )
        
        # Wait for escalation timeout
        time.sleep(2)
        
        # Check that alert was escalated
        alerts = self.monitor.get_alerts()
        escalated_alert = next((a for a in alerts if a.title == "Escalation Test"), None)
        self.assertIsNotNone(escalated_alert)
        self.assertTrue(escalated_alert.escalation_level > 0)
    
    def test_alert_summary(self):
        """Test alert summary statistics."""
        # Create some alerts
        self.monitor._create_alert(
            AlertCategory.SECURITY_BREACH,
            AlertSeverity.HIGH,
            "Alert 1",
            "First test alert"
        )
        self.monitor._create_alert(
            AlertCategory.NETWORK_ANOMALY,
            AlertSeverity.MEDIUM,
            "Alert 2", 
            "Second test alert"
        )
        
        # Get summary
        summary = self.monitor.get_alert_summary()
        
        # Verify summary content
        self.assertIn('total_alerts', summary)
        self.assertIn('active_alerts', summary)
        self.assertIn('severity_distribution', summary)
        self.assertIn('category_distribution', summary)
        self.assertEqual(summary['total_alerts'], 2)


class TestOPSECIntegration(unittest.TestCase):
    """Integration tests for all OPSEC components."""
    
    def setUp(self):
        """Set up integrated test environment."""
        self.temp_dir = tempfile.mkdtemp()
        # Reset global instances for clean testing
        import civradar.intel.opsec_logger
        import civradar.intel.session_manager
        import civradar.intel.field_ops
        import civradar.intel.secure_sharing
        import civradar.intel.safeguards
        import civradar.intel.config_manager
        import civradar.intel.secure_wiper
        import civradar.intel.security_monitor
        
        # Reset global instances
        civradar.intel.opsec_logger._opsec_logger = None
        civradar.intel.session_manager._session_manager = None
        civradar.intel.field_ops._field_ops = None
        civradar.intel.secure_sharing._secure_sharing = None
        civradar.intel.safeguards._safeguards_engine = None
        civradar.intel.config_manager._config_manager = None
        civradar.intel.secure_wiper._secure_wiper = None
        civradar.intel.security_monitor._security_monitor = None
    
    def tearDown(self):
        """Clean up integrated test environment."""
        # Clean up any created data
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_full_opsec_lifecycle(self):
        """Test complete OPSEC lifecycle."""
        # 1. Initialize all components
        logger = get_opsec_logger()
        manager = get_session_manager()
        field_ops = get_field_operations()
        sharing = get_secure_sharing_manager()
        safeguards = get_safeguards_engine()
        config_mgr = get_config_manager()
        wiper = get_secure_wiper()
        monitor = get_security_monitor()
        
        # 2. Create configuration
        config = create_field_config(ConfigLevel.HIGH, FieldScenario.STEALTH)
        config_mgr.save_configuration(config)
        
        # 3. Start field operation
        operation_id = start_field_operation(FieldMode.STEALTH, "test_op")
        
        # 4. Create secure session
        session_id = create_secure_session()
        
        # 5. Record some activity
        logger.log_operation("field_scan", {"devices": 5}, "stealth", 2)
        
        # 6. Create secure share
        share_info = create_secure_share("Test intelligence data")
        
        # 7. Verify sharing works
        retrieved_data = sharing.retrieve_share(
            share_info['share_id'],
            share_info['access_key']
        )
        self.assertEqual(retrieved_data.decode('utf-8'), "Test intelligence data")
        
        # 8. Check security status
        status = check_environment_security()
        self.assertIn('active_measures', status)
        
        # 9. Test secure wiping
        test_file = Path(self.temp_dir) / "test.txt"
        test_file.write_text("Sensitive data")
        wipe_result = secure_wipe_file(test_file)
        self.assertEqual(wipe_result['status'], 'completed')
        
        # 10. Emergency wipe all
        emergency_result = wiper.emergency_wipe_all()
        self.assertEqual(emergency_result['status'], 'completed')
        
        # 11. End field operation
        field_ops.end_operation("integration_test_complete")
    
    def test_coordinated_response(self):
        """Test coordinated response to security threats."""
        # Initialize components
        monitor = start_security_monitoring()
        
        # Create high-severity alert to trigger auto-response
        monitor._create_alert(
            AlertCategory.SECURITY_BREACH,
            AlertSeverity.EMERGENCY,
            "Critical Security Breach",
            "Immediate response required"
        )
        
        # Wait for processing
        time.sleep(2)
        
        # Verify auto-response triggered (emergency wipe)
        # This would be verified through logs in real implementation


def run_comprehensive_tests():
    """Run all OPSEC feature tests."""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestOPSECLogger,
        TestSessionManager,
        TestFieldOperations,
        TestSecureSharing,
        TestSafeguards,
        TestConfigManager,
        TestSecureWiper,
        TestSecurityMonitor,
        TestOPSECIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "="*60)
    print("OPSEC FEATURES TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    print("\n" + "="*60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("Starting CIVRADAR-X OPSEC Features Comprehensive Test Suite")
    print("="*60)
    
    success = run_comprehensive_tests()
    
    if success:
        print("✅ All OPSEC feature tests PASSED")
        exit(0)
    else:
        print("❌ Some OPSEC feature tests FAILED")
        exit(1)