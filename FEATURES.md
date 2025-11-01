# CIVRADAR-X Comprehensive Features Documentation

**Author: Tasavvuf Tev**

## Overview
CIVRADAR-X is a **free, open-source, privacy-first** reconnaissance system designed for tactical operations in hostile environments. As a powerful alternative to expensive commercial privacy tools, CIVRADAR-X operates **100% offline** with no subscriptions, ads, or data collection—giving you complete control over your digital security. This document provides detailed technical specifications, code references, and operational guidance for all system capabilities.

## Table of Contents
1. [Core Scanning Capabilities](#core-scanning-capabilities)
2. [Intelligence Features](#intelligence-features)
3. [Web Interface](#web-interface)
4. [Security & Export Features](#security--export-features)
5. [Configuration & Session Management](#configuration--session-management)
6. [Manipulation Guides](#manipulation-guides)
7. [Development Guidance](#development-guidance)

---

## Core Scanning Capabilities

### WiFi Scanning (`civradar/core/scanner_wifi.py`)
**Purpose**: Passive WiFi network discovery and signal strength analysis.

**Key Functions**:
- `scan_wifi(stealth=False)`: Main scanning function (lines 5-18)
- `parse_iw(output)`: Parse iw scan output (lines 20-37)
- `finalize(net, networks)`: Finalize network data (lines 39-41)

**Capabilities**:
- Uses `iw` command for wireless scanning
- Extracts SSID, BSSID, RSSI, channel, and signal strength
- Calculates distance using RSSI-to-distance conversion
- Stealth mode support (returns empty list when enabled)

**Code Reference**: [`civradar/core/scanner_wifi.py`](civradar/core/scanner_wifi.py:5-41)

### BLE Scanning (`civradar/core/scanner_ble.py`)
**Purpose**: Bluetooth Low Energy device discovery.

**Key Functions**:
- `scan_ble(timeout=10, stealth=False)`: Main BLE scanning (lines 7-30)
- `parse_btmon(output)`: Parse btmon output (lines 32-51)

**Capabilities**:
- Uses `btmon` and `hcitool` for passive BLE scanning
- Extracts device names and MAC addresses
- Sanitizes MAC addresses for consistency
- Configurable timeout (default 10 seconds)

**Code Reference**: [`civradar/core/scanner_ble.py`](civradar/core/scanner_ble.py:7-51)

### mDNS Scanning (`civradar/core/scanner_mdns.py`)
**Purpose**: Multicast DNS service discovery for IoT devices.

**Key Functions**:
- `scan_mdns(timeout=8, stealth=False)`: Main mDNS scanning (lines 5-18)
- `parse_avahi(output)`: Parse Avahi browse output (lines 20-39)
- `get_mac_from_ip(ip)`: ARP lookup for MAC addresses (lines 41-47)

**Capabilities**:
- Uses `avahi-browse` for service discovery
- Extracts device names and IP addresses
- Performs ARP lookups to correlate IP with MAC
- Common for smart home and IoT device detection

**Code Reference**: [`civradar/core/scanner_mdns.py`](civradar/core/scanner_mdns.py:5-47)

### ARP Scanning (`civradar/core/scanner_arp.py`)
**Purpose**: Local network host discovery via ARP.

**Key Functions**:
- `scan_arp(stealth=False)`: Main ARP scanning (lines 5-15)
- `parse_arp(output)`: Parse ARP table output (lines 17-28)

**Capabilities**:
- Uses `arp -a` command for passive host discovery
- Extracts IP addresses and MAC addresses
- Fast and reliable for local network mapping
- Triggers ARP population with ping broadcast

**Code Reference**: [`civradar/core/scanner_arp.py`](civradar/core/scanner_arp.py:5-28)

---

## Intelligence Features

### Device Fusion Engine (`civradar/intel/fusion_engine.py`)
**Purpose**: Correlates device data from multiple protocols into unified profiles.

**Key Functions**:
- `fuse_devices(devices)`: Main fusion logic (lines 8-81)
- `merge_devices(devices)`: Merge device dictionaries (lines 83-111)
- `similar_names(name1, name2, threshold=0.8)`: Name similarity matching (lines 114-120)

**Capabilities**:
- Groups devices by MAC address first
- Uses name similarity for cross-protocol correlation
- Applies threat intelligence scoring
- Calculates confidence based on protocol count

**Code Reference**: [`civradar/intel/fusion_engine.py`](civradar/intel/fusion_engine.py:8-120)

### GPS Handler (`civradar/intel/gps_handler.py`)
**Purpose**: Multi-source GPS coordinate acquisition.

**Key Functions**:
- `get_gps()`: Main GPS acquisition with fallback chain (lines 29-44)
- `_get_gpsd()`: GPSD daemon interface (lines 46-59)
- `_get_serial_nmea()`: Serial NMEA parsing (lines 61-77)
- `_get_bluetooth_gps()`: Bluetooth GPS discovery (lines 79-103)
- `_get_manual()`: Manual coordinate override (lines 105-106)

**Capabilities**:
- GPSD, serial NMEA, Bluetooth GPS, and manual override support
- Automatic fallback chain for reliability
- Dynamic configuration updates
- Altitude and accuracy tracking

**Code Reference**: [`civradar/intel/gps_handler.py`](civradar/intel/gps_handler.py:29-106)

### Database Logger (`civradar/intel/logger.py`)
**Purpose**: Persistent device data storage with SQLite.

**Key Functions**:
- `init_db()`: Database initialization (lines 7-40)
- `log_devices(devices, geo=None)`: Device logging (lines 42-62)
- `log_export_history(...)`: Export tracking (lines 64-72)

**Capabilities**:
- Stores device metadata, geolocation, and timestamps
- Tracks export operations
- SQLite database with structured schema
- UTC timestamp standardization

**Code Reference**: [`civradar/intel/logger.py`](civradar/intel/logger.py:7-72)

### OPSEC Logger (`civradar/intel/opsec_logger.py`)
**Purpose**: Encrypted operational security logging with anti-forensics.

**Key Functions**:
- `OPSECLogger.__init__(...)`: Logger initialization (lines 32-92)
- `log_operation(...)`: Encrypted operation logging (lines 282-357)
- `retrieve_logs(...)`: Decrypt and retrieve logs (lines 373-425)
- `secure_wipe_all()`: Complete data sanitization (lines 427-453)

**Capabilities**:
- Fernet encryption with PBKDF2 key derivation
- Anti-forensic features (time stomping, decoy files)
- Tamper detection with HMAC
- Multiple security levels (minimal to extreme)
- Secure deletion with multiple overwrite passes

**Code Reference**: [`civradar/intel/opsec_logger.py`](civradar/intel/opsec_logger.py:32-453)

---

## Web Interface

### Main Template (`web/templates/index.html`)
**Purpose**: HTML interface for radar visualization and controls.

**Features**:
- Canvas-based radar display
- Real-time device visualization
- Export controls (CSV, JSON, GeoJSON)
- Mode toggles (Night Vision, Tactical)
- GPS status display

**Code Reference**: [`web/templates/index.html`](web/templates/index.html:1-28)

### Radar JavaScript (`web/static/js/radar.js`)
**Purpose**: Client-side radar rendering and interaction.

**Key Functions**:
- `drawRadar(devices)`: Main rendering loop (lines 21-134)
- `toggleNightVision()`: Night vision mode toggle (lines 148-152)
- `toggleTactical()`: Tactical mode toggle (lines 154-158)

**Capabilities**:
- Animated radar sweeps and device blips
- Motion trails for device tracking
- Risk-based color coding (green/yellow/red)
- Audio alerts for high-risk devices
- Real-time polling every 3 seconds

**Code Reference**: [`web/static/js/radar.js`](web/static/js/radar.js:21-158)

### Phantom CSS (`web/static/css/phantom.css`)
**Purpose**: Tactical UI styling with night vision effects.

**Features**:
- Monospace font for tactical appearance
- Green-on-black color scheme
- Night vision filter effects
- Pulsing animations for high-risk devices
- Responsive sidebar layout

**Code Reference**: [`web/static/css/phantom.css`](web/static/css/phantom.css:1-66)

---

## Security & Export Features

### Secure Exporter (`civradar/intel/secure_exporter.py`)
**Purpose**: Encrypted data export with multiple formats.

**Key Functions**:
- `create_zip_export(devices, geo_cache=None)`: Multi-format ZIP creation (lines 13-42)
- `encrypt_with_gpg(data, password=None, recipient=None)`: GPG encryption (lines 47-74)
- `export_secure_zip(...)`: Main secure export function (lines 76-109)

**Capabilities**:
- Exports CSV, JSON, GeoJSON, and SQLite database
- GPG encryption with password or key-based methods
- Metadata inclusion with timestamps and device counts
- Secure filename generation

**Code Reference**: [`civradar/intel/secure_exporter.py`](civradar/intel/secure_exporter.py:13-109)

### Secure Wiper (`civradar/intel/secure_wiper.py`)
**Purpose**: Comprehensive data sanitization with multiple wipe methods.

**Key Functions**:
- `secure_wipe_file(...)`: Single file secure deletion (lines 89-168)
- `secure_wipe_directory(...)`: Directory recursive wiping (lines 323-427)
- `wipe_free_space(...)`: Free space overwriting (lines 438-547)
- `emergency_wipe_all(...)`: Complete system wipe (lines 614-718)

**Capabilities**:
- Multiple wipe methods (DoD 5220.22-M, Gutmann, random)
- Parallel processing for directory operations
- Free space wiping to prevent recovery
- Emergency rapid wipe for crisis situations
- Verification of successful deletion

**Code Reference**: [`civradar/intel/secure_wiper.py`](civradar/intel/secure_wiper.py:89-718)

### Security Monitor (`civradar/intel/security_monitor.py`)
**Purpose**: Real-time threat detection and alerting.

**Key Functions**:
- `SecurityMonitor.__init__(...)`: Monitor initialization (lines 97-117)
- `start_monitoring()`: Begin monitoring (lines 173-185)
- `_scan_processes()`: Process threat detection (lines 251-284)
- `_scan_network_activity()`: Network anomaly detection (lines 293-340)

**Capabilities**:
- Process monitoring for suspicious tools
- Network connection analysis
- System resource anomaly detection
- Behavioral baseline establishment
- Automated alerting and escalation

**Code Reference**: [`civradar/intel/security_monitor.py`](civradar/intel/security_monitor.py:97-340)

---

## Configuration & Session Management

### Config Manager (`civradar/intel/config_manager.py`)
**Purpose**: Secure, dynamic configuration management.

**Key Functions**:
- `create_configuration(...)`: Generate field configurations (lines 170-214)
- `switch_config_level(...)`: Change security levels (lines 517-550)
- `switch_field_scenario(...)`: Change operational scenarios (lines 552-580)
- `save_configuration(...)`: Encrypted config storage (lines 393-427)

**Capabilities**:
- Multiple security levels (Minimal to Extreme)
- Field scenarios (Normal, Stealth, Combat, Emergency)
- Encrypted configuration storage
- Integrity verification with checksums
- Dynamic configuration updates

**Code Reference**: [`civradar/intel/config_manager.py`](civradar/intel/config_manager.py:170-427)

### Session Manager (`civradar/intel/session_manager.py`)
**Purpose**: Secure session handling with auto-wipe capabilities.

**Key Functions**:
- `SecureSession.__init__(...)`: Session initialization (lines 49-83)
- `create_session()`: New session creation (lines 550-563)
- `terminate_session(...)`: Secure session cleanup (lines 573-580)
- `_scan_threats()`: Continuous threat monitoring (lines 130-178)

**Capabilities**:
- Session-specific encryption keys
- Auto-wipe on timeout or threats
- Process hiding and memory protection
- Threat detection with automated responses
- Session isolation and cleanup

**Code Reference**: [`civradar/intel/session_manager.py`](civradar/intel/session_manager.py:49-178)

### Field Operations (`civradar/intel/field_ops.py`)
**Purpose**: Operational mode management for different threat environments.

**Key Functions**:
- `FieldOperations.__init__(...)`: Operations initialization (lines 440-462)
- `switch_mode(...)`: Mode switching logic (lines 497-523)
- `_apply_mode_config()`: Mode-specific configuration (lines 524-558)
- `start_operation()`: Operation commencement (lines 621-629)

**Capabilities**:
- Multiple operational modes (Normal, Stealth, Ghost, Emergency)
- Threat detection with auto-mode switching
- Process hiding and network stealth
- Hardware LED disabling and MAC randomization
- Operation status tracking

**Code Reference**: [`civradar/intel/field_ops.py`](civradar/intel/field_ops.py:440-558)

---

## Manipulation Guides

### Stealth Mode Activation
```python
# Enable stealth mode via API
curl -X POST http://localhost:5000/api/stealth -d '{"enabled": true}'

# Or programmatically in field_ops.py
from civradar.intel.field_ops import switch_field_mode, FieldMode
switch_field_mode(FieldMode.STEALTH, "manual_activation")
```

### GPS Override for Testing
```python
# Set manual GPS coordinates
from civradar.intel.gps_handler import set_manual_override
set_manual_override(lat=37.7749, lon=-122.4194, alt=100, acc=5)
```

### Secure Export with Encryption
```python
# Export with password protection
from civradar.intel.secure_exporter import export_secure_zip
response = export_secure_zip(devices, geo_cache, password="secure_password")
```

### Emergency Wipe Trigger
```python
# Complete system wipe
from civradar.intel.secure_wiper import emergency_wipe_all
emergency_wipe_all(include_system_files=True)
```

### Configuration Level Switching
```python
# Switch to high security
from civradar.intel.config_manager import switch_security_level, ConfigLevel
switch_security_level(ConfigLevel.HIGH)
```

---

## Development Guidance

### Adding New Scanner Modules
1. Create scanner in `civradar/core/scanner_[protocol].py`
2. Implement `scan_[protocol](stealth=False)` function
3. Return list of device dictionaries with consistent keys
4. Add import and call in `app.py` background_scanner (lines 84-87)

### Extending Threat Intelligence
1. Modify `data/iot_signatures.json` for new device signatures
2. Update `threat_intelligence.py` vendor reputation scores
3. Add new risk calculation factors in `calculate_dynamic_risk()`

### Custom Export Formats
1. Add new export function in `intel/exporter.py`
2. Update `app.py` export route (lines 131-140)
3. Include in secure ZIP export if needed

### OPSEC Feature Development
1. Use `get_opsec_logger()` for all security logging
2. Implement tamper detection with HMAC
3. Apply time stomping for file metadata
4. Use secure deletion for sensitive data cleanup

### Web Interface Extensions
1. Add new controls to `index.html`
2. Implement JavaScript functions in `radar.js`
3. Add API endpoints in `app.py`
4. Style with tactical theme in `phantom.css`

### Testing OPSEC Features
1. Use separate test database paths
2. Mock GPS coordinates for consistent testing
3. Test with various threat simulation scenarios
4. Verify secure deletion effectiveness

---

## Critical Logic Lines

### Main Application Loop
- Background scanner: [`app.py:77-121`](civradar/app.py:77-121)
- OPSEC initialization: [`app.py:44-75`](civradar/app.py:44-75)
- Signal handlers: [`app.py:346-372`](civradar/app.py:346-372)

### Device Fusion Logic
- MAC grouping: [`fusion_engine.py:13-23`](civradar/intel/fusion_engine.py:13-23)
- Name similarity: [`fusion_engine.py:27-69`](civradar/intel/fusion_engine.py:27-69)
- Risk calculation: [`fusion_engine.py:74-79`](civradar/intel/fusion_engine.py:74-79)

### Security Critical Functions
- Emergency wipe: [`secure_wiper.py:614-718`](civradar/intel/secure_wiper.py:614-718)
- Threat detection: [`security_monitor.py:251-340`](civradar/intel/security_monitor.py:251-340)
- Session encryption: [`session_manager.py:85-106`](civradar/intel/session_manager.py:85-106)

### GPS Fallback Chain
- Source priority: [`gps_handler.py:31-43`](civradar/intel/gps_handler.py:31-43)
- Manual override: [`gps_handler.py:25-27`](civradar/intel/gps_handler.py:25-27)

---

## Performance Considerations

### Scanning Optimization
- ARP scanning is fastest for local networks
- BLE scanning has 10-second timeout for battery life
- mDNS uses 8-second timeout for responsiveness
- WiFi scanning requires root privileges

### Memory Management
- Device history limited to recent entries
- SQLite database compaction recommended
- Memory scrubbing in idle sessions
- Secure deletion prevents forensic recovery

### Network Efficiency
- Stealth mode disables active scanning
- OPSEC limits outbound connections
- Tor integration for anonymous communications
- Connection pooling for GPS sources

---

## Security Best Practices

### Operational Security
- Always use stealth mode in hostile environments
- Enable OPSEC logging for audit trails
- Regular configuration backups with encryption
- Emergency wipe procedures for compromise

### Development Security
- Never log sensitive data in plaintext
- Use encrypted channels for remote access
- Implement proper input validation
- Regular security audits of code changes

### Deployment Security
- Use separate user accounts for CIVRADAR-X
- Configure firewall rules for port restrictions
- Enable system auditing and monitoring
- Regular updates of threat intelligence database

---

**Author**: Tasavvuf Tev

*This documentation is automatically generated from CIVRADAR-X codebase analysis. Last updated: 2025-11-01*