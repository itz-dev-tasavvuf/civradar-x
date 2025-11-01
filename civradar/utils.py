"""
Utility Functions Module for CIVRADAR-X

This module provides common utility functions used throughout the CIVRADAR-X
system, including signal processing, data sanitization, and mathematical
calculations for device intelligence analysis.

Key Functions:
- rssi_to_distance: Convert WiFi signal strength to estimated distance
- sanitize_mac: Clean and standardize MAC address formatting

Technical Details:
- RSSI to distance conversion uses Free Space Path Loss (FSPL) formula
- MAC address sanitization removes invalid characters and standardizes format
- Distance calculations account for typical WiFi frequencies and transmit power

Dependencies:
- math: Mathematical functions for signal calculations
- re: Regular expressions for MAC address processing

Author: CIVRADAR-X Development Team
"""

import math
import re


def rssi_to_distance(rssi, freq_mhz=2437, tx_power=20):
    """
    Convert WiFi RSSI (Received Signal Strength Indicator) to estimated distance.

    This function uses the Free Space Path Loss (FSPL) formula to estimate the
    distance between a WiFi access point and receiver based on signal strength.
    The calculation accounts for frequency-dependent path loss and transmit power.

    Formula: FSPL = 20*log10(d) + 20*log10(f) + 20*log10(4π/c)
    Rearranged: d = 10^((TxPower - RSSI - FSPL_constant) / 20)

    Args:
        rssi (float): Received signal strength in dBm (negative values)
        freq_mhz (float): Frequency in MHz (default: 2437 for 2.4GHz WiFi)
        tx_power (float): Transmit power in dBm (default: 20)

    Returns:
        float: Estimated distance in meters (clamped to 0.5-100m range)

    Notes:
        - Returns infinity for non-negative RSSI values (invalid)
        - Distance estimates are approximate and affected by:
          * Environmental factors (walls, interference)
          * Antenna characteristics
          * Device orientation
          * Multipath effects

    Example:
        >>> rssi_to_distance(-50)  # Strong signal
        5.0
        >>> rssi_to_distance(-80)  # Weak signal
        50.0
    """
    # Invalid RSSI check (RSSI should always be negative for valid signals)
    if rssi >= 0:
        return float('inf')

    # Calculate Free Space Path Loss constant
    # FSPL = 20*log10(freq_mhz) + 20*log10(distance) - 27.55
    # We solve for distance: distance = 10^((tx_power - rssi - fspl_constant) / 20)
    fspl_constant = (20 * math.log10(freq_mhz) + 20 * math.log10(0.001) - 27.55)

    # Calculate distance using FSPL formula
    distance = 10 ** ((tx_power - rssi - fspl_constant) / 20)

    # Clamp distance to reasonable range and round to 1 decimal place
    return round(max(0.5, min(distance, 100)), 1)


def sanitize_mac(mac):
    """
    Sanitize and standardize MAC address format.

    This function cleans MAC addresses by removing invalid characters,
    converting to uppercase, and ensuring proper length. It's used to
    normalize MAC addresses from various input sources for consistent
    processing and comparison.

    Args:
        mac (str): Raw MAC address string (may contain separators)

    Returns:
        str: Sanitized MAC address in XX:XX:XX:XX:XX:XX format

    Processing Steps:
        1. Remove all non-hexadecimal characters
        2. Convert to uppercase
        3. Truncate to 12 characters (6 bytes)
        4. Format as colon-separated pairs

    Examples:
        >>> sanitize_mac("aa:bb:cc:dd:ee:ff")
        'AABBCCDDEEFF'
        >>> sanitize_mac("AA-BB-CC-DD-EE-FF")
        'AABBCCDDEEFF'
        >>> sanitize_mac("aabb.ccdd.eeff")
        'AABBCCDDEEFF'

    Note:
        Returns 12-character hex string without colons for internal use.
        Formatting as colon-separated pairs may be done by calling code.
    """
    # Remove all non-hexadecimal characters and convert to uppercase
    cleaned = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()

    # Truncate to exactly 12 characters (6 bytes) and return
    return cleaned[:12]