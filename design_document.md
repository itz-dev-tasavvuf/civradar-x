# CIVRADAR-X Extreme Vision Enhancement Design Document

**Author: Tasavvuf (Tev)**

## Overview
This document outlines the architectural enhancements to CIVRADAR-X to achieve the "extreme vision" capabilities: core GPS geotagging with auto-detect and manual override, data fusion for correlating devices across protocols, enhanced privacy threat intelligence with expanded DB and scoring, upgraded UI with motion/audio/night vision/tactical modes, stealth mode (passive-only), improved exports (encrypted ZIP), and field-ready opsec features. As a **free, open-source alternative to commercial privacy tools**, CIVRADAR-X maintains its privacy-first, offline ethos with **100% offline operation**, no subscriptions, and complete data control.

## Current Architecture Analysis
CIVRADAR-X is a Flask-based web application with:
- **Backend**: Python Flask with SocketIO for real-time updates
- **Scanners**: Separate modules for Wi-Fi (iw), BLE (btmon), mDNS (avahi), ARP (arp)
- **Intelligence**: Device classification via JSON signatures, SQLite logging, CSV/JSON/GeoJSON exports
- **UI**: Canvas-based radar with Three.js support, phantom green theme
- **Data Flow**: Scanners → Classification → Logging → UI Updates

Integration points identified:
- `background_scanner()` in app.py for adding new scanners
- `device_classifier.py` for intelligence enhancements
- `logger.py` and `exporter.py` for data handling
- `index.html` and radar.js for UI upgrades

## New Components and Enhancements

### 1. Core GPS Geotagging Module
**Location**: `civradar/intel/gps_handler.py` (enhanced)

**New Features**:
- Auto-detect sources: GPSD, NMEA over serial (/dev/tty*), Bluetooth GPS (RFCOMM)
- Manual override: UI/API endpoint for setting fixed coordinates
- Fallback chain: GPSD → Serial NMEA → Bluetooth GPS → Manual → None
- Enhanced data structure: Include altitude, accuracy, timestamp

**Integration**:
- Modify `get_gps()` to support multiple sources
- Add API endpoint `/api/gps/override` for manual coords
- Update `log_devices()` to store enhanced geo data

**Data Flow**:
```
GPS Sources → GPS Handler → Geo Cache → Device Logging → Exports
```

### 2. Data Fusion Module
**Location**: New `civradar/core/data_fusion.py`

**Purpose**: Correlate devices across protocols to identify multi-protocol threats (e.g., Wi-Fi + BLE tracker)

**Algorithm**:
- MAC address matching (primary key)
- Name/service fingerprinting (secondary)
- Proximity correlation (RSSI/distance within 5m)
- Temporal consistency (devices seen within 30s)

**Output**: Fused device profiles with combined risk scores, protocol list, unified location

**Integration**:
- Insert after individual scanners in `background_scanner()`
- Update UI to show fused devices with protocol badges

**Data Flow**:
```
Individual Scans → Fusion Engine → Fused Devices → UI/Logging
```

### 3. Enhanced Privacy Threat Intelligence
**Location**: `data/iot_signatures.json` (expanded), `civradar/core/device_classifier.py` (enhanced)

**Expansions**:
- Add 50+ new signatures: Dashcams, smart locks, fitness trackers, industrial IoT
- New risk factors: Data exfiltration, physical access, network pivoting
- Dynamic scoring: Base score + protocol multipliers + distance penalties

**Scoring Algorithm**:
```
Risk = Base_Risk + (Protocol_Count * 0.5) + (Distance < 10m ? 1 : 0) + (Flags_Weight)
Flags: camera=2, mic=1.5, cloud=1, recording=2, tracking=2
```

**Integration**:
- Update classifier to use enhanced DB
- Add real-time score recalculation in fusion module

### 4. Upgraded UI Modes
**Location**: `web/static/js/radar.js` (enhanced), `web/templates/index.html` (controls added)

**Modes**:
- **Motion**: Trail effects on blips, velocity vectors
- **Audio**: Proximity beeps (Web Audio API), risk-based tones (high-risk = urgent beep)
- **Night Vision**: IR simulation filter (grayscale + thermal overlay)
- **Tactical**: Threat assessment panels, risk heatmaps, device details overlay

**Controls**: Keyboard shortcuts (M/A/N/T) + UI buttons

**Integration**:
- Add mode state management in JS
- WebSocket updates for real-time mode switching

### 5. Stealth Mode
**Location**: `civradar/core/scanner_*.py` (passive flags), `app.py` (mode toggle)

**Implementation**:
- Ensure all scans are passive: No probe requests, no active queries
- Wi-Fi: Use `iw scan passive`
- BLE: Passive lescan only
- mDNS: Browse only, no announce
- ARP: Passive ARP table monitoring

**Toggle**: Global flag in app.py, UI indicator

### 6. Improved Exports
**Location**: `civradar/intel/exporter.py` (enhanced)

**New Formats**:
- Encrypted ZIP: AES-256 encryption with user passphrase
- Include metadata: Scan session info, GPS bounds, risk summary
- Secure deletion: Overwrite temp files

**Integration**:
- Add `/api/export/zip` endpoint
- Client-side passphrase prompt

### 7. Field-Ready OPSEC Features
**Location**: New `civradar/intel/opsec.py`

**Features**:
- Secure logging: Encrypted SQLite with SQLCipher
- Anti-forensics: Timestomping, random filenames
- Offline encryption: Fernet keys generated locally
- Wipe on exit: Secure delete logs on shutdown
- No network leakage: Block all outbound connections in stealth mode

**Integration**:
- Wrap logger.py with encryption
- Add OPSEC config in app.py

## Data Flows

### Primary Scan Flow
```
Scanners (Wi-Fi/BLE/mDNS/ARP) → Data Fusion → Classification → GPS Tagging → Logging → UI Update
```

### Export Flow
```
Logged Data → Encryption → ZIP Packaging → Secure Download
```

### OPSEC Flow
```
All Data → Encryption Layer → Anti-Forensic Storage → Wipe on Exit
```

## Integration Points
- **app.py**: Add fusion, GPS override, stealth toggle, OPSEC init
- **Scanners**: Passive flags, fusion input
- **Classifier**: Enhanced DB, dynamic scoring
- **Logger/Exporter**: Encryption, secure formats
- **UI**: Mode controls, real-time updates

## Privacy-First Considerations
- All GPS data optional, never transmitted
- Encryption keys generated locally, never stored
- No cloud dependencies, all offline
- Passive-only operations prevent detection
- Data fusion improves accuracy without new data collection

**Author**: Tasavvuf Tev

## Performance Impact
- Fusion: ~10% CPU increase (negligible)
- GPS: Minimal, cached every 10s
- UI Modes: Canvas redraws, <5% GPU
- Encryption: Export time +2-3s for ZIP
- OPSEC: Logging overhead ~5%

## Testing Strategy
- Unit tests for fusion logic
- Integration tests for GPS sources
- UI mode validation
- OPSEC audit (no leaks)
- Performance benchmarks

## Deployment
- Update install.sh for new dependencies (pynmea2, cryptography, sqlcipher)
- Maintain Kali Linux compatibility
- Backward compatibility with existing DB/logs