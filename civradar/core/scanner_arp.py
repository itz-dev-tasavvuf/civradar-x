"""
ARP Network Scanner Module for CIVRADAR-X

This module implements ARP (Address Resolution Protocol) scanning capabilities
for the CIVRADAR-X system. ARP scanning is used to discover active hosts on
local network segments by leveraging the ARP table population mechanism.

Key Features:
- Fast network host discovery using ARP table analysis
- Stealth mode support (no network activity when enabled)
- Automatic ARP table population via broadcast ping
- Robust error handling and fallback mechanisms

Technical Details:
- Uses system 'arp' command to read ARP cache
- Triggers ARP requests via broadcast ping to 192.168.1.255
- Parses ARP output using regex for IP and MAC extraction
- Returns standardized device dictionaries for fusion engine

Limitations:
- Only discovers hosts that have communicated recently
- Requires local network access and appropriate permissions
- May not detect hosts that don't respond to ARP requests

Author: CIVRADAR-X Development Team
"""

import subprocess
import re


def scan_arp(stealth=False):
    """
    Perform ARP-based network scanning to discover local hosts.

    This function scans the local network segment using ARP table analysis.
    In normal mode, it triggers ARP table population by sending a broadcast ping,
    then reads the ARP cache to extract active host information.

    Args:
        stealth (bool): If True, skip scanning and return empty list.
                       Used for passive-only operation modes.

    Returns:
        list: List of discovered devices, each containing:
            - mac: MAC address string
            - name: IP address (used as identifier)
            - protocol: 'arp'
            Or error dict with 'error' key if scan fails

    Note:
        ARP scanning is fast but only finds hosts that have been active
        recently or respond to the broadcast ping trigger.
    """
    # Stealth mode: return empty results without network activity
    if stealth:
        return []

    try:
        # Trigger ARP table population by sending broadcast ping
        # This causes the system to send ARP requests for active hosts
        # -c1: send 1 packet, -W1: wait 1 second for response
        subprocess.run(['ping', '-c1', '-W1', '192.168.1.255'],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL)

        # Read the ARP cache using system arp command
        result = subprocess.check_output(['arp', '-a'], text=True)

        # Parse the ARP output to extract device information
        return parse_arp(result)

    except Exception as e:
        # Return error information instead of raising exception
        # Allows the fusion engine to continue with other scanners
        return [{"error": f"ARP scan failed: {str(e)}"}]


def parse_arp(output):
    """
    Parse the output from 'arp -a' command to extract device information.

    This function processes the human-readable ARP table output and extracts
    IP addresses and corresponding MAC addresses using regex pattern matching.

    Args:
        output (str): Raw output from 'arp -a' command

    Returns:
        list: List of device dictionaries with standardized format:
            - mac: Hardware address (format: XX:XX:XX:XX:XX:XX)
            - name: IP address string
            - protocol: 'arp'

    Regex Pattern:
        Matches lines like: "hostname (192.168.1.1) at 00:11:22:33:44:55"
        Captures IP in group 1, MAC in group 2
    """
    devices = []

    # Process each line of ARP output
    for line in output.splitlines():
        # Regex pattern to match ARP table entries
        # Format: hostname (IP) at MAC [other info]
        match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Fa-f:]{17})', line)

        if match:
            # Extract IP address and MAC address from regex groups
            ip, mac = match.groups()

            # Create standardized device dictionary
            devices.append({
                'mac': mac,           # Hardware address
                'name': ip,           # Use IP as device name/identifier
                'protocol': 'arp'     # Protocol used for discovery
            })

    return devices