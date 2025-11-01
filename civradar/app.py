"""
CIVRADAR-X Main Application Module

This module serves as the primary entry point for the CIVRADAR-X civilian radar
intelligence system. It provides a Flask-based web interface with real-time
device scanning, OPSEC-enhanced security features, and comprehensive field
operation capabilities.

Key Features:
- Real-time device discovery across multiple protocols (WiFi, BLE, mDNS, ARP)
- Web-based radar visualization with live updates via WebSocket
- OPSEC-enhanced security with encrypted logging and threat monitoring
- Secure data export with multiple formats and encryption options
- GPS integration with manual override capabilities
- Stealth mode operation for low-visibility deployments
- Emergency wipe and secure termination capabilities

System Architecture:
- Flask web framework for HTTP API endpoints
- SocketIO for real-time client communication
- Background scanning thread for continuous device discovery
- OPSEC components for operational security and threat response
- SQLite database for persistent device logging
- Multi-protocol device fusion engine for intelligence correlation

Security Features:
- Session-based security with threat monitoring
- Field operation modes (Normal, Stealth, Ghost, Emergency)
- Secure data wiping and memory cleanup
- Encrypted configuration and logging
- Process hiding and network stealth capabilities

API Endpoints:
- /: Main web interface
- /api/devices: Current device list (JSON)
- /api/export/<fmt>: Data export (CSV, JSON, GeoJSON)
- /api/export/secure: Encrypted secure export
- /api/gps/*: GPS configuration and override
- /api/stealth: Stealth mode control
- /api/opsec/*: OPSEC system management

Operational Modes:
- Normal: Full functionality with logging
- Stealth: Reduced activity, process hiding
- Ghost: Maximum stealth, encrypted memory
- Emergency: Crisis mode with auto-wipe

Dependencies:
- flask: Web framework
- flask-socketio: Real-time communication
- Core scanners: Device discovery modules
- Intel modules: Security and intelligence features

Author: CIVRADAR-X Development Team
License: MIT (Classified Operations)
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import threading
import time
import json
import signal
import os
import sys
from .core.scanner_wifi import scan_wifi
from .core.scanner_ble import scan_ble
from .core.scanner_mdns import scan_mdns
from .core.scanner_arp import scan_arp
from .intel.logger import init_db, log_devices
from .intel.gps_handler import get_gps, set_manual_override, update_gps_config, GPS_CONFIG
from .intel.fusion_engine import fuse_devices

# OPSEC Imports
from .intel.opsec_logger import get_opsec_logger, log_opsec_event
from .intel.session_manager import get_session_manager, create_secure_session
from .intel.field_ops import get_field_operations, FieldMode, start_field_operation
from .intel.secure_sharing import get_secure_sharing_manager
from .intel.safeguards import get_safeguards_engine
from .intel.config_manager import get_config_manager, ConfigLevel, FieldScenario
from .intel.secure_wiper import get_secure_wiper, emergency_wipe_all
from .intel.security_monitor import get_security_monitor, start_security_monitoring

app = Flask(__name__, static_folder='../web/static', template_folder='../web/templates')
socketio = SocketIO(app, async_mode='threading')
latest_devices = []
geo_cache = None
stealth_mode = False

# OPSEC Component Initialization
opsec_logger = None
session_manager = None
field_operations = None
secure_sharing = None
safeguards = None
config_manager = None
secure_wiper = None
security_monitor = None
field_session_id = None

def init_opsec_components():
    """Initialize all OPSEC components."""
    global opsec_logger, session_manager, field_operations, secure_sharing
    global safeguards, config_manager, secure_wiper, security_monitor, field_session_id
    
    try:
        # Initialize OPSEC components
        opsec_logger = get_opsec_logger()
        session_manager = get_session_manager()
        field_operations = get_field_operations()
        secure_sharing = get_secure_sharing_manager()
        safeguards = get_safeguards_engine()
        config_manager = get_config_manager()
        secure_wiper = get_secure_wiper()
        security_monitor = start_security_monitoring()
        
        # Create field session
        field_session_id = create_secure_session()
        
        # Start field operation
        operation_id = start_field_operation(FieldMode.STEALTH, "civradar_app")
        
        log_opsec_event("app_initialized", {
            "field_session_id": field_session_id,
            "operation_id": operation_id,
            "opsec_components": "all_initialized"
        }, "normal", 2)
        
    except Exception as e:
        print(f"⚠️ OPSEC initialization error: {e}")
        # Continue without OPSEC if initialization fails
        pass

def background_scanner(stealth=False):
    global latest_devices, geo_cache, stealth_mode
    while True:
        try:
            if not stealth and not stealth_mode:
                geo_cache = get_gps()
                all_devices = []
                all_devices.extend(scan_wifi(stealth=stealth or stealth_mode))
                all_devices.extend(scan_ble(stealth=stealth or stealth_mode))
                all_devices.extend(scan_mdns(stealth=stealth or stealth_mode))
                all_devices.extend(scan_arp(stealth=stealth or stealth_mode))
                # Fuse devices into unified profiles
                fused_devices = fuse_devices(all_devices)
                latest_devices = fused_devices
                log_devices(fused_devices, geo_cache)
                socketio.emit('scan_update', fused_devices)
                
                # OPSEC logging for scan operations
                if opsec_logger:
                    opsec_logger.log_operation("device_scan", {
                        "device_count": len(fused_devices),
                        "scan_types": ["wifi", "ble", "mdns", "arp"],
                        "geo_available": geo_cache is not None
                    }, "normal", 1)
                    
            else:
                # In stealth mode, clear devices and don't emit updates
                latest_devices = []
                
                # OPSEC logging for stealth mode
                if opsec_logger:
                    opsec_logger.log_operation("stealth_scan", {
                        "mode": "stealth",
                        "devices_hidden": True
                    }, "stealth", 2)
                    
        except Exception as e:
            # OPSEC logging for scan errors
            if opsec_logger:
                opsec_logger.log_operation("scan_error", {
                    "error": str(e),
                    "stealth_mode": stealth or stealth_mode
                }, "normal", 5)
        
        time.sleep(10)  # Slightly longer for BLE/mDNS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices')
def api_devices():
    return jsonify(latest_devices)

@app.route('/api/export/<fmt>')
def export(fmt):
    from .intel.exporter import export_csv, export_json, export_geojson
    if fmt == 'csv':
        return export_csv(latest_devices)
    elif fmt == 'json':
        return jsonify(latest_devices)
    elif fmt == 'geojson':
        return export_geojson(latest_devices)
    return "Invalid format", 400

@app.route('/api/export/secure', methods=['POST'])
def export_secure():
    from .intel.secure_exporter import export_secure_zip
    data = request.get_json() or {}
    password = data.get('password')
    recipient = data.get('recipient')

    if not password and not recipient:
        return jsonify({'error': 'Either password or recipient required for secure export'}), 400

    return export_secure_zip(latest_devices, geo_cache, password=password, recipient=recipient)

@app.route('/api/gps/override', methods=['POST'])
def gps_override():
    data = request.get_json()
    if not data or 'lat' not in data or 'lon' not in data:
        return jsonify({'error': 'lat and lon required'}), 400
    set_manual_override(
        data['lat'],
        data['lon'],
        data.get('alt'),
        data.get('acc')
    )
    return jsonify({'status': 'GPS override set'})

@app.route('/api/gps/config', methods=['GET', 'POST'])
def gps_config():
    if request.method == 'POST':
        data = request.get_json()
        for source, config in data.items():
            update_gps_config(source, **config)
        return jsonify({'status': 'GPS config updated'})
    return jsonify(GPS_CONFIG)

@app.route('/api/gps/status')
def gps_status():
    current = get_gps()
    return jsonify({
        'current': current,
        'config': GPS_CONFIG
    })

@app.route('/api/stealth', methods=['GET', 'POST'])
def stealth_mode_api():
    global stealth_mode
    if request.method == 'POST':
        data = request.get_json()
        if 'enabled' in data:
            stealth_mode = bool(data['enabled'])
            return jsonify({'status': f'Stealth mode {"enabled" if stealth_mode else "disabled"}'})
        return jsonify({'error': 'enabled field required'}), 400
    return jsonify({'stealth_mode': stealth_mode})

# OPSEC API Endpoints
@app.route('/api/opsec/status')
def opsec_status():
    """Get OPSEC system status."""
    status = {
        "opsec_initialized": opsec_logger is not None,
        "session_active": session_manager is not None,
        "field_operation": field_operations is not None if field_operations else None,
        "security_monitoring": security_monitor is not None if security_monitor else None,
        "field_session_id": field_session_id
    }
    return jsonify(status)

@app.route('/api/opsec/session/create', methods=['POST'])
def opsec_create_session():
    """Create new OPSEC session."""
    try:
        session_id = create_secure_session()
        return jsonify({"status": "session_created", "session_id": session_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/opsec/field/mode', methods=['GET', 'POST'])
def opsec_field_mode():
    """Manage field operation mode."""
    if request.method == 'POST':
        data = request.get_json()
        mode = data.get('mode')
        reason = data.get('reason', 'api_request')
        
        try:
            if mode:
                from .intel.field_ops import FieldMode
                field_mode = FieldMode(mode)
                field_operations.switch_mode(field_mode, reason)
                return jsonify({"status": "mode_changed", "new_mode": mode})
            else:
                return jsonify({"error": "mode parameter required"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # GET request - return current status
    if field_operations:
        status = field_operations.get_operation_status()
        return jsonify(status)
    else:
        return jsonify({"error": "field operations not initialized"}), 500

@app.route('/api/opsec/share/create', methods=['POST'])
def opsec_create_share():
    """Create secure share."""
    try:
        data = request.get_json() or {}
        content = data.get('content', '')
        encryption_type = data.get('encryption_type', 'fernet')
        
        from .intel.secure_sharing import EncryptionType
        enc_type = EncryptionType(encryption_type)
        
        share_info = secure_sharing.create_share(content, encryption_type=enc_type)
        return jsonify({"status": "share_created", "share": share_info})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/opsec/share/retrieve', methods=['POST'])
def opsec_retrieve_share():
    """Retrieve secure share."""
    try:
        data = request.get_json() or {}
        share_id = data.get('share_id')
        access_key = data.get('access_key')
        
        if not share_id or not access_key:
            return jsonify({"error": "share_id and access_key required"}), 400
        
        content = secure_sharing.retrieve_share(share_id, access_key)
        if content:
            return jsonify({"status": "share_retrieved", "content": content.decode('utf-8')})
        else:
            return jsonify({"error": "share not found or expired"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/opsec/wipe', methods=['POST'])
def opsec_emergency_wipe():
    """Emergency wipe all data."""
    try:
        data = request.get_json() or {}
        confirm = data.get('confirm', False)
        
        if not confirm:
            return jsonify({"error": "confirmation required"}), 400
        
        # OPSEC logging before wipe
        if opsec_logger:
            opsec_logger.log_operation("emergency_wipe_initiated", {
                "trigger": "api_request",
                "confirmed": True
            }, "emergency", 10)
        
        # Perform emergency wipe
        result = emergency_wipe_all()
        
        return jsonify({"status": "emergency_wipe_completed", "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/opsec/security/alerts')
def opsec_security_alerts():
    """Get security alerts."""
    try:
        if security_monitor:
            alerts = security_monitor.get_alerts()
            return jsonify({
                "status": "alerts_retrieved",
                "alerts": [alert.__dict__ for alert in alerts],
                "count": len(alerts)
            })
        else:
            return jsonify({"error": "security monitor not initialized"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/opsec/config', methods=['GET', 'POST'])
def opsec_config():
    """Manage OPSEC configuration."""
    if request.method == 'POST':
        try:
            data = request.get_json() or {}
            level = data.get('security_level')
            
            if level:
                from .intel.config_manager import ConfigLevel
                config_level = ConfigLevel(level)
                success = config_manager.switch_config_level(config_level)
                if success:
                    return jsonify({"status": "config_updated", "level": level})
                else:
                    return jsonify({"error": "configuration update failed"}), 500
            else:
                return jsonify({"error": "security_level parameter required"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # GET request - return current configuration
    if config_manager:
        summary = config_manager.get_config_summary()
        return jsonify({"status": "config_retrieved", "config": summary})
    else:
        return jsonify({"error": "config manager not initialized"}), 500

def signal_handler(signum, frame):
    """Handle shutdown signals with OPSEC cleanup."""
    print("\n🛡️  Shutting down CIVRADAR-X with OPSEC cleanup...")
    
    try:
        # OPSEC logging for shutdown
        if opsec_logger:
            opsec_logger.log_operation("application_shutdown", {
                "signal": signum,
                "graceful": True
            }, "normal", 3)
        
        # End field operation if active
        if field_operations:
            field_operations.end_operation("application_shutdown")
        
        # Secure wipe if requested
        if signum == signal.SIGTERM:  # Emergency termination
            emergency_wipe_all()
        
        print("✅ OPSEC cleanup completed")
        
    except Exception as e:
        print(f"⚠️ OPSEC cleanup error: {e}")
    
    finally:
        sys.exit(0)

if __name__ == '__main__':
    # Initialize OPSEC components
    init_opsec_components()
    
    # Initialize database
    init_db()
    
    # Start background scanner
    threading.Thread(target=background_scanner, daemon=True).start()
    
    # Setup signal handlers for OPSEC cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("☠️  CIVRADAR-X OPSEC-Enhanced running at http://127.0.0.1:5000")
    print("🛡️  Field operations mode: ACTIVE")
    print("🔒 Security level: HIGH")
    print("⚡ Auto-wipe: ENABLED")
    print("🚨 Monitoring: ACTIVE")
    
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)