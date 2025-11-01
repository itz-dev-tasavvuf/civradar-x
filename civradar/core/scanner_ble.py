"""
Bluetooth Low Energy (BLE) Scanner Module for CIVRADAR-X

This module implements BLE device discovery capabilities for the CIVRADAR-X system.
It uses Linux Bluetooth tools (hcitool and btmon) to perform passive BLE scanning
without requiring device pairing or active connections.

Key Features:
- Passive BLE device discovery using btmon monitoring
- Device name extraction from advertisement packets
- Stealth mode support for passive-only operations
- Robust error handling with fallback mechanisms
- MAC address sanitization and deduplication

Technical Details:
- Uses hcitool lescan for BLE advertisement scanning
- Monitors HCI traffic with btmon for detailed packet analysis
- Parses btmon output to extract device addresses and names
- Supports configurable scan timeout for performance control

Requirements:
- Linux Bluetooth stack (bluez)
- Root privileges for HCI device access
- Compatible Bluetooth adapter (hci0 interface)

Limitations:
- Requires Bluetooth hardware and drivers
- May not detect devices in deep sleep modes
- Passive scanning only (no active probing)

Author: CIVRADAR-X Development Team
"""

import subprocess
import re
import time
from ..utils import sanitize_mac


def scan_ble(timeout=10, stealth=False):
    """
    Perform Bluetooth Low Energy device scanning using passive monitoring.

    This function discovers BLE devices by monitoring HCI traffic with btmon
    while running a passive LE scan. It captures advertisement packets and
    extracts device information without establishing connections.

    Args:
        timeout (int): Scan duration in seconds (default: 10)
        stealth (bool): If True, skip scanning and return empty list

    Returns:
        list: List of discovered BLE devices, each containing:
            - mac: Sanitized MAC address string
            - name: Device name from advertisements (or '<unknown>')
            - protocol: 'ble'
            Or error dict with 'error' key if scan fails

    Process Flow:
        1. Reset HCI interface for clean state
        2. Start btmon process to monitor HCI traffic
        3. Run passive LE scan with hcitool
        4. Wait for specified timeout to collect advertisements
        5. Terminate monitoring and parse collected data
    """
    # Stealth mode: return empty results without Bluetooth activity
    if stealth:
        return []

    try:
        # Reset Bluetooth HCI interface for consistent state
        # This ensures clean starting conditions for the scan
        subprocess.run(['sudo', 'hciconfig', 'hci0', 'reset'],
                      check=True,
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL)

        # Start Bluetooth monitor process to capture HCI packets
        # btmon provides detailed packet-level monitoring of Bluetooth traffic
        proc = subprocess.Popen(
            ['sudo', 'btmon'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        # Allow btmon to initialize and stabilize
        time.sleep(2)

        # Start passive LE scan using hcitool
        # --passive flag ensures no active scanning (advertisement-only)
        # Timeout prevents hanging if scan initiation fails
        subprocess.run(['sudo', 'hcitool', 'lescan', '--passive'],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL,
                      timeout=5)

        # Wait for the specified duration to collect advertisement packets
        time.sleep(timeout)

        # Terminate the monitoring process
        proc.terminate()

        # Retrieve all captured output from btmon
        output, _ = proc.communicate()

        # Parse the collected HCI traffic for device information
        return parse_btmon(output)

    except Exception as e:
        # Return error information instead of raising exception
        # Allows fusion engine to continue with other discovery methods
        return [{"error": f"BLE scan failed: {str(e)}"}]


def parse_btmon(output):
    """
    Parse btmon output to extract BLE device information.

    This function processes the detailed HCI packet output from btmon to identify
    BLE devices and their advertised names. It handles the structured output format
    where device information appears across multiple lines.

    Args:
        output (str): Raw output from btmon process

    Returns:
        list: List of unique BLE devices with standardized format:
            - mac: Sanitized MAC address
            - name: Device name from advertisements
            - protocol: 'ble'

    Parsing Logic:
        - Looks for 'Address:' lines to identify new devices
        - Associates subsequent 'Name:' lines with current device
        - Deduplicates devices by MAC address
        - Uses '<unknown>' for devices without advertised names
    """
    devices = {}  # Use dict to deduplicate by MAC address
    current_addr = None

    # Process each line of btmon output
    for line in output.splitlines():
        line = line.strip()

        # Check for device address announcement
        if 'Address:' in line:
            # Extract MAC address using regex pattern
            match = re.search(r'([0-9A-F:]{17})', line)
            if match:
                # Sanitize MAC address for consistent formatting
                current_addr = sanitize_mac(match.group(1))

                # Initialize device entry if not already seen
                if current_addr not in devices:
                    devices[current_addr] = {
                        'mac': current_addr,
                        'name': '<unknown>',  # Default until name found
                        'protocol': 'ble'
                    }

        # Check for device name in advertisement data
        elif 'Name:' in line and current_addr:
            # Extract name from btmon format (may be quoted)
            name = line.split('Name:', 1)[1].strip().strip('"')

            # Update device name if valid name found
            if name:
                devices[current_addr]['name'] = name

    # Convert device dictionary to list for return
    return list(devices.values())