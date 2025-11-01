# CIVRADAR-X
## Tactical Recon Radar for Privacy-Aware Civilians

```
     ____  ____  ____  ____  ____  ____  ____  ____
    /___/ /___/ /___/ /___/ /___/ /___/ /___/ /___/
   |     |     |     |     |     |     |     |     |
    \___/ \___/ \___/ \___/ \___/ \___/ \___/ \___/
     ____  ____  ____  ____  ____  ____  ____  ____
    /___/ /___/ /___/ /___/ /___/ /___/ /___/ /___/
   |     |     |     |     |     |     |     |     |
    \___/ \___/ \___/ \___/ \___/ \___/ \___/ \___/

   ██████  ██ ██    ██ ██████   █████  ██████   █████  ██████
  ██       ██ ██    ██ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██
  ██   ███ ██ ██    ██ ██████  ███████ ██████  ███████ ██████
  ██    ██ ██ ██    ██ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██
   ██████  ██  ██████  ██   ██ ██   ██ ██   ██ ██   ██ ██   ██

  ████████  █████   ██████ ████████ ██  ██████   █████  ██
     ██    ██   ██ ██         ██    ██ ██       ██   ██ ██
     ██    ███████ ██         ██    ██ ██   ███ ███████ ██
     ██    ██   ██ ██         ██    ██ ██    ██ ██   ██ ██
     ██    ██   ██  ██████    ██    ██  ██████  ██   ██ ███████

  ██████  ██████  ███████ ███    ██ ███████ ██    ██  ██████  ██    ██ ██████
 ██       ██   ██ ██      ████   ██ ██      ██    ██ ██       ██    ██ ██   ██
 ██   ███ ██████  █████   ██ ██  ██ ███████ ██    ██ ██   ███ ██    ██ ██████
 ██    ██ ██   ██ ██      ██  ██ ██      ██ ██    ██ ██    ██ ██    ██ ██   ██
  ██████  ██   ██ ███████ ██   ████ ███████  ██████   ██████   ██████  ██   ██

```

**Version 1.0.0** | **Author: Tasavvuf (Tev)** | **License: MIT**

---

## 🌟 What is CIVRADAR-X?

CIVRADAR-X is a **free, open-source, privacy-first** tool designed for civilians who want to protect their personal space from hidden surveillance devices. Unlike commercial privacy tools that often require subscriptions or cloud connectivity, CIVRADAR-X operates **100% offline** and gives you complete control over your data.

Think of it as a "radar" that scans for:
- **Hidden cameras** in smart devices
- **Tracking devices** like GPS trackers or smart tags
- **Networked IoT devices** that might be spying on you
- **Wireless threats** from Wi-Fi, Bluetooth, and other protocols

Built specifically for **Kali Linux**, it runs in airplane mode to ensure zero network leakage. CIVRADAR-X is your digital guardian, helping you detect privacy threats before they become problems.

**Why choose CIVRADAR-X?** It's a powerful alternative to expensive commercial tools like those from security companies, but completely free and open-source. No ads, no data collection, no hidden agendas—just pure privacy protection.

---

## 🔍 Key Features

### Core Detection Capabilities
- **Multi-Protocol Scanning**: Detects devices via Wi-Fi, Bluetooth Low Energy (BLE), mDNS (Bonjour), and ARP
- **Smart Device Identification**: Recognizes over 100 types of IoT devices, cameras, trackers, and smart home gadgets
- **Privacy Risk Scoring**: Rates devices from 0-5 based on potential privacy threats (e.g., cameras = high risk)
- **Real-Time Monitoring**: Continuous scanning with live updates on a web-based radar interface

### Advanced Privacy Features
- **Offline Operation**: Works completely offline—no internet required
- **Zero Telemetry**: No data is ever sent anywhere; everything stays on your device
- **GPS Geotagging**: Optional location tagging for mapping threats (uses local GPS hardware)
- **Data Fusion**: Combines data from multiple protocols to identify sophisticated multi-device threats

### Security & OPSEC (Operational Security)
- **Field-Ready Modes**: Stealth, Combat, Emergency, and Radio Silence modes for different threat levels
- **Encrypted Logging**: All data is encrypted and stored securely
- **Secure Exports**: Export data in encrypted ZIP files with password protection
- **Emergency Wipe**: Instantly delete all data if threatened
- **Anti-Forensics**: Built-in protections against digital evidence tampering

### User Experience
- **Tactical UI**: Phantom green radar interface with night vision and motion modes
- **Audio Alerts**: Proximity beeps and risk-based tones for accessibility
- **Multiple Export Formats**: CSV, JSON, GeoJSON, and secure encrypted archives
- **Keyboard Shortcuts**: Quick mode switching (N for night vision, M for motion, etc.)

---

## 📦 Installation Guide

CIVRADAR-X is designed for **Kali Linux** but can work on other Debian-based systems. The installation is automated via a script.

### Prerequisites
- **Operating System**: Kali Linux (recommended) or Debian/Ubuntu
- **Hardware**: Wi-Fi adapter, Bluetooth (optional), GPS device (optional)
- **Permissions**: Root access for network scanning

### Step-by-Step Installation

1. **Download the Repository**:
   ```bash
   git clone https://github.com/yourusername/civradar-x.git
   cd civradar-x
   ```

2. **Run the Installation Script**:
   ```bash
   sudo ./install.sh
   ```
   This script will:
   - Update your package list
   - Install required system packages (aircrack-ng, bluez-tools, etc.)
   - Install Python dependencies (Flask, PyBluez, etc.)
   - Set up necessary permissions and directories

3. **Verify Installation**:
   The script will check that all components are installed correctly. If there are any errors, it will notify you.

### Troubleshooting
- **Permission Issues**: Ensure you're running as root for network access.
- **Missing Dependencies**: The script handles most dependencies, but if something fails, check the error messages.
- **Hardware Not Detected**: For GPS or Bluetooth, ensure your devices are connected and recognized by the system.

---

## 🚀 Usage Instructions

### Basic Operation

1. **Start CIVRADAR-X**:
   ```bash
   cd civradar-x
   sudo PYTHONPATH=/home/kali/Documents/civradar-x python3 -m civradar.app
   ```
   - Replace `/home/kali/Documents/civradar-x` with your actual path if different.

2. **Access the Web Interface**:
   Open your browser and go to: **http://127.0.0.1:5000**
   - You'll see the radar interface showing detected devices as blips.

3. **Scan for Devices**:
   - Scanning starts automatically every 10 seconds.
   - Devices appear as colored dots on the radar (color indicates risk level).
   - Click on a device for details: type, risk score, protocols used.

### Advanced Usage

#### Switching Modes
- **Stealth Mode**: Passive scanning only (no active probes). Toggle via the UI or API.
- **Night Vision**: Press 'N' for a green-tinted view.
- **Motion Mode**: Press 'M' to show device movement trails.
- **Audio Mode**: Press 'A' for proximity alerts.

#### GPS Integration
- If you have a GPS device, it will auto-detect and tag locations.
- Manual override: Use the API to set a fixed location if needed.

#### Exporting Data
- From the web interface, choose export format (CSV, JSON, GeoJSON).
- For secure export: Use the encrypted ZIP option with a password.

#### OPSEC Features
- **Field Modes**: Switch to Combat mode for high-threat environments.
- **Emergency Wipe**: Instantly delete all logs and data.
- **Secure Sharing**: Share encrypted data with others.

### For Non-Technical Users
- **Getting Started**: Just run the install script and start the app. The web interface is intuitive.
- **Understanding Results**: Green dots = low risk, Red dots = high risk. Hover for explanations.
- **Safety Tips**: Run in airplane mode. Don't connect to unknown networks.

### For Technical Users
- **API Access**: All features are available via REST API endpoints (e.g., `/api/devices` for device list).
- **Customization**: Modify `civradar/app.py` for advanced configurations.
- **Logging**: Check `/opt/civradar-x/logs` for detailed logs.

---

## 🛡️ Security & Privacy

CIVRADAR-X prioritizes your privacy:
- **No Data Transmission**: Everything stays local.
- **Encryption**: Logs and exports are encrypted.
- **OPSEC Built-In**: Designed for field operations in hostile environments.
- **Open-Source**: Code is auditable; no hidden backdoors.

**Legal Note**: Use responsibly. This tool is for defensive privacy protection, not offensive surveillance.

---

## 🤝 Contributing & Support

- **Report Issues**: Open issues on GitHub for bugs or feature requests.
- **Contribute Code**: Fork the repo and submit pull requests.
- **Documentation**: Help improve this README or add tutorials.

---

## 📜 License & Credits

**License**: MIT - Free for personal and defensive use. Not for surveillance or offensive operations.

**Credits**:
- Inspired by privacy tools like Wireshark and open-source security projects.
- Built with Flask, Three.js, and Python networking libraries.

**Author**: Tasavvuf Tev

---

*Stay vigilant. Protect your privacy. CIVRADAR-X: Your eyes in the digital shadows.*