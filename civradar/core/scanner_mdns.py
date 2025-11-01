"""
Multicast DNS (mDNS) Scanner Module for CIVRADAR-X

This module implements mDNS service discovery for the CIVRADAR-X system using
Avahi (Linux mDNS implementation). mDNS is commonly used by IoT devices for
service advertisement and discovery on local networks.

Key Features:
- mDNS service discovery using Avahi browse tool
- Automatic MAC address resolution via ARP lookup
- Stealth mode support for passive operations
- Device deduplication and timeout handling
- Integration with ARP for hardware address correlation

Technical Details:
- Uses 'avahi-browse -at' for all-service type discovery
- Parses Avahi output to extract service names and IP addresses
- Performs ARP lookups to correlate IP addresses with MAC addresses
- Supports configurable scan timeout for performance control

Requirements:
- Avahi daemon and tools installed
- Network access for multicast traffic
- ARP table access for MAC resolution

Common mDNS Services:
- _http._tcp: Web servers
- _ipp._tcp: Printers
- _airplay._tcp: Apple devices
- _googlecast._tcp: Chromecast devices
- _hap._tcp: HomeKit accessories

Author: CIVRADAR-X Development Team
"""

import subprocess
import re


def scan_mdns(timeout=8, stealth=False):
    """
    Discover devices and services using Multicast DNS (mDNS) browsing.

    This function uses Avahi to browse for mDNS services advertised on the
    local network. mDNS is widely used by IoT devices for automatic discovery
    and service advertisement.

    Args:
        timeout (int): Maximum scan time in seconds (default: 8)
        stealth (bool): If True, skip scanning and return empty list

    Returns:
        list: List of discovered mDNS services/devices, each containing:
            - mac: MAC address (from ARP lookup) or IP if lookup fails
            - name: Service/device name from mDNS advertisement
            - protocol: 'mdns'
            Or error dict with 'error' key if scan fails

    Avahi Command Details:
        -a: Browse all service types
        -t: Terminate after browsing (don't wait for new services)
        --no-db-lookup: Skip database lookups for performance
    """
    # Stealth mode: return empty results without network activity
    if stealth:
        return []

    try:
        # Execute Avahi browse command with timeout wrapper
        # timeout command prevents hanging if Avahi encounters issues
        result = subprocess.run(
            ['timeout', str(timeout), 'avahi-browse', '-at', '--no-db-lookup'],
            capture_output=True,
            text=True,
            check=True
        )

        # Parse the Avahi output to extract service information
        return parse_avahi(result.stdout)

    except Exception as e:
        # Return error information instead of raising exception
        # Allows fusion engine to continue with other discovery methods
        return [{"error": f"mDNS scan failed: {str(e)}"}]


def parse_avahi(output):
    """
    Parse Avahi browse output to extract mDNS service information.

    This function processes the structured output from avahi-browse to identify
    advertised services and their associated network information. It attempts
    to resolve MAC addresses for each discovered service.

    Args:
        output (str): Raw output from avahi-browse command

    Returns:
        list: List of unique mDNS services with standardized format:
            - mac: Hardware address (from ARP) or IP address
            - name: Service name from mDNS advertisement
            - protocol: 'mdns'

    Parsing Logic:
        - Filters for IPv4 service entries (marked with '=')
        - Extracts service name and IP address from structured output
        - Attempts MAC address resolution via ARP lookup
        - Deduplicates services by MAC/IP to avoid duplicates
    """
    devices = {}  # Use dict to deduplicate services

    # Process each line of Avahi output
    for line in output.splitlines():
        # Skip lines that don't contain service entries
        # Valid service lines start with '=' and contain 'IPv4'
        if '=' not in line or 'IPv4' not in line:
            continue

        # Split line into components (Avahi uses space-separated format)
        parts = line.split()

        # Ensure line has enough fields for parsing
        if len(parts) < 7:
            continue

        # Extract service name and IP address from known positions
        name = parts[3]  # Service name field
        ip = parts[6]    # IPv4 address field

        # Attempt to resolve MAC address for the IP
        # This provides hardware-level identification
        mac = get_mac_from_ip(ip)

        # Use MAC as key if available, otherwise use IP
        # This ensures deduplication even if MAC lookup fails
        key = mac or ip

        # Add service if not already discovered
        if key not in devices:
            devices[key] = {
                'mac': mac or ip,  # MAC if resolved, IP otherwise
                'name': name,       # Service name from mDNS
                'protocol': 'mdns'  # Discovery protocol
            }

    # Convert device dictionary to list for return
    return list(devices.values())


def get_mac_from_ip(ip):
    """
    Resolve MAC address for a given IP address using ARP table lookup.

    This helper function queries the system's ARP cache to find the MAC
    address associated with an IP address. This is useful for correlating
    network-layer addresses with hardware addresses.

    Args:
        ip (str): IPv4 address to resolve

    Returns:
        str or None: MAC address in XX:XX:XX:XX:XX:XX format if found,
                     None if resolution fails

    Note:
        ARP lookup will only succeed if the IP has been communicated with
        recently, as ARP entries expire over time.
    """
    try:
        # Query ARP table for the specific IP address
        arp_out = subprocess.check_output(['arp', '-n', ip], text=True)

        # Extract MAC address using regex pattern
        match = re.search(r'([0-9A-Fa-f:]{17})', arp_out)

        # Return MAC address if found, None otherwise
        return match.group(1) if match else None

    except:
        # Return None on any error (IP not in ARP table, command failure, etc.)
        return None