"""
WiFi Network Scanner Module for CIVRADAR-X

This module implements WiFi network scanning capabilities for the CIVRADAR-X system
using Linux wireless tools. It discovers nearby WiFi access points and provides
signal strength information for proximity analysis.

Key Features:
- WiFi access point discovery using iw tool
- Signal strength (RSSI) measurement and distance estimation
- Automatic wireless interface detection
- Stealth mode support for passive operations
- Hidden network detection and handling

Technical Details:
- Uses 'iw scan' for active WiFi scanning
- Parses iw scan dump output for detailed AP information
- Converts RSSI values to estimated distance using RF propagation models
- Supports multiple wireless interfaces (uses first available)

Requirements:
- Linux wireless tools (iw command)
- Compatible wireless adapter with scanning capability
- Root privileges for scanning operations

Signal Processing:
- RSSI: Received Signal Strength Indicator (dBm)
- Distance estimation based on path loss calculations
- Channel information for frequency analysis

Limitations:
- Requires wireless hardware and drivers
- Active scanning may be detectable by monitoring systems
- Distance estimation is approximate (affected by interference, obstacles)

Author: CIVRADAR-X Development Team
"""

import subprocess
import re
from ..utils import rssi_to_distance


def scan_wifi(stealth=False):
    """
    Perform WiFi network scanning to discover nearby access points.

    This function scans for WiFi networks using the Linux iw tool, detecting
    access points and measuring their signal characteristics. It automatically
    detects available wireless interfaces and performs comprehensive scanning.

    Args:
        stealth (bool): If True, skip scanning and return empty list

    Returns:
        list: List of discovered WiFi networks, each containing:
            - mac: BSSID (MAC address of access point)
            - name: SSID (network name) or '<hidden>' for hidden networks
            - rssi: Signal strength in dBm
            - distance: Estimated distance in meters
            - channel: WiFi channel number
            - protocol: 'wifi'
            Or error dict with 'error' key if scan fails

    Process Flow:
        1. Detect available wireless interfaces
        2. Perform active scan on first available interface
        3. Dump scan results for detailed parsing
        4. Extract network information and calculate distances
    """
    # Stealth mode: return empty results without wireless activity
    if stealth:
        return []

    try:
        # Detect available wireless interfaces
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)

        # Extract interface names using regex
        interfaces = re.findall(r'Interface (\w+)', result.stdout)

        # Return empty if no wireless interfaces found
        if not interfaces:
            return []

        # Use first available wireless interface
        wlan = interfaces[0]

        # Perform active scan on the interface
        # This sends probe requests and listens for beacon frames
        subprocess.run(['sudo', 'iw', wlan, 'scan'],
                      check=True,
                      stdout=subprocess.DEVNULL)

        # Dump detailed scan results for parsing
        output = subprocess.check_output(['sudo', 'iw', wlan, 'scan', 'dump'], text=True)

        # Parse scan results into structured network data
        return parse_iw(output)

    except Exception as e:
        # Return error information instead of raising exception
        return [{"error": str(e)}]


def parse_iw(output):
    """
    Parse iw scan dump output to extract WiFi network information.

    This function processes the detailed output from 'iw scan dump' to identify
    WiFi access points and their characteristics. It handles the structured
    format where each network's information spans multiple lines.

    Args:
        output (str): Raw output from 'iw scan dump' command

    Returns:
        list: List of WiFi networks with standardized format:
            - mac: BSSID (access point MAC address)
            - name: SSID or '<hidden>' for hidden networks
            - rssi: Signal strength in dBm
            - distance: Estimated distance based on RSSI
            - channel: WiFi channel number
            - protocol: 'wifi'

    Parsing Logic:
        - Identifies new BSS (Basic Service Set) entries
        - Extracts SSID, signal strength, and channel information
        - Calculates distance from RSSI using propagation model
        - Handles hidden networks (no SSID broadcast)
    """
    networks = []
    current = {}

    # Process each line of iw scan output
    for line in output.splitlines():
        line = line.strip()

        # Check for new BSS (access point) entry
        if line.startswith('BSS '):
            # Finalize previous network if exists
            if current:
                finalize(current, networks)

            # Extract BSSID from BSS line (format: BSS XX:XX:XX:XX:XX:XX(on wlan0))
            bssid = line.split()[1].split('(')[0]

            # Initialize new network entry with defaults
            current = {
                'mac': bssid,
                'name': '',
                'rssi': -100,      # Default low signal
                'channel': 0,      # Unknown channel
                'protocol': 'wifi'
            }

        # Extract SSID (network name)
        elif 'SSID:' in line and current:
            ssid = line.split('SSID: ', 1)[1]
            current['name'] = ssid or '<hidden>'  # Handle hidden networks

        # Extract signal strength and calculate distance
        elif 'signal:' in line and current:
            # Parse RSSI value (format: signal: -45.00 dBm)
            current['rssi'] = float(line.split()[1])

            # Calculate estimated distance from signal strength
            current['distance'] = rssi_to_distance(current['rssi'])

    # Finalize the last network if it exists
    if current:
        finalize(current, networks)

    return networks


def finalize(net, networks):
    """
    Finalize and add a WiFi network entry to the results list.

    This function performs any final processing on a network entry before
    adding it to the results. Currently a placeholder for future classification
    logic that may be moved from the fusion engine.

    Args:
        net (dict): Network entry to finalize
        networks (list): Results list to append to

    Note:
        Originally contained classification logic, now reserved for
        future enhancements or preprocessing steps.
    """
    # Classification logic moved to fusion engine
    # This function remains for potential future preprocessing
    networks.append(net)