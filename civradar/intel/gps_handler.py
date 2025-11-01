"""
GPS Handler Module for CIVRADAR-X

This module provides comprehensive GPS positioning capabilities for the
CIVRADAR-X system, supporting multiple GPS sources and automatic fallback
mechanisms. It enables precise geospatial correlation of device discoveries
for intelligence analysis and operational awareness.

Supported GPS Sources:
- GPSD: Linux GPS daemon for GPS receivers
- Serial NMEA: Direct serial connection to GPS devices
- Bluetooth GPS: Wireless GPS receivers over Bluetooth
- Manual Override: User-provided coordinates for testing/emergency

Key Features:
- Multi-source GPS with automatic failover
- Dynamic source configuration and enabling/disabling
- Manual coordinate override for controlled environments
- Timestamp synchronization with UTC
- Accuracy reporting and quality metrics
- Robust error handling and connection management

GPS Data Structure:
- lat: Latitude in decimal degrees (-90 to 90)
- lon: Longitude in decimal degrees (-180 to 180)
- alt: Altitude in meters (optional)
- acc: Horizontal accuracy estimate in meters (optional)
- timestamp: UTC timestamp in ISO format

Configuration:
- Source-specific settings (ports, timeouts, etc.)
- Runtime enable/disable of GPS sources
- Manual override for testing or emergency situations

Dependencies:
- gpsd: GPS daemon client library
- serial: Serial port communication
- pynmea2: NMEA sentence parsing
- bluetooth: Bluetooth device discovery and communication

Security Considerations:
- GPS data may reveal operational locations
- Consider GPS spoofing threats in hostile environments
- Manual override can be used for OPSEC in sensitive areas

Author: CIVRADAR-X Development Team
"""

import gpsd
import serial
import pynmea2
import bluetooth
import time
from datetime import datetime

# GPS source configuration with default settings
GPS_CONFIG = {
    'gpsd': {
        'enabled': True,
        'description': 'GPSD daemon for GPS receivers'
    },
    'serial': {
        'enabled': True,
        'ports': ['/dev/ttyACM0', '/dev/ttyUSB0', '/dev/ttyS0'],
        'baudrate': 9600,
        'timeout': 1,
        'description': 'Serial NMEA GPS devices'
    },
    'bluetooth': {
        'enabled': True,
        'devices': [],  # Auto-discovered Bluetooth GPS devices
        'port': 1,      # RFCOMM port for GPS service
        'timeout': 1,
        'description': 'Bluetooth GPS receivers'
    },
    'manual': {
        'enabled': True,
        'lat': None,
        'lon': None,
        'alt': None,
        'acc': None,
        'description': 'Manual coordinate override'
    }
}


def update_gps_config(source, enabled=None, **kwargs):
    """
    Dynamically update GPS source configuration.

    This function allows runtime modification of GPS source settings,
    enabling operational adaptation based on available hardware and
    environmental conditions.

    Args:
        source (str): GPS source name ('gpsd', 'serial', 'bluetooth', 'manual')
        enabled (bool, optional): Enable or disable the source
        **kwargs: Additional configuration parameters for the source

    Example:
        update_gps_config('serial', enabled=True, ports=['/dev/ttyUSB1'])
        update_gps_config('bluetooth', enabled=False)
    """
    if source in GPS_CONFIG:
        if enabled is not None:
            GPS_CONFIG[source]['enabled'] = enabled
        GPS_CONFIG[source].update(kwargs)


# Global manual coordinate override
manual_override = None


def set_manual_override(lat, lon, alt=None, acc=None):
    """
    Set manual GPS coordinate override.

    This function allows manual specification of GPS coordinates, useful for:
    - Testing in environments without GPS hardware
    - Emergency situations requiring specific coordinates
    - Operational security (OPSEC) in sensitive locations

    Args:
        lat (float): Latitude in decimal degrees
        lon (float): Longitude in decimal degrees
        alt (float, optional): Altitude in meters
        acc (float, optional): Accuracy estimate in meters

    Note:
        Manual override takes precedence in the GPS source priority chain.
    """
    global manual_override
    manual_override = {
        'lat': lat,
        'lon': lon,
        'alt': alt,
        'acc': acc,
        'timestamp': datetime.utcnow().isoformat()
    }


def get_gps():
    """
    Retrieve current GPS position using configured sources.

    This function attempts to obtain GPS coordinates from available sources
    in priority order, with automatic fallback to lower-priority sources
    if higher-priority sources fail or are unavailable.

    Returns:
        dict or None: GPS data dictionary or None if no source available

    GPS Data Dictionary:
        - lat: Latitude (-90 to 90)
        - lon: Longitude (-180 to 180)
        - alt: Altitude in meters (optional)
        - acc: Horizontal accuracy in meters (optional)
        - timestamp: UTC timestamp (ISO format)

    Priority Order:
        1. GPSD (most reliable for dedicated GPS hardware)
        2. Serial NMEA (direct hardware connection)
        3. Bluetooth GPS (wireless receivers)
        4. Manual override (user-specified coordinates)
    """
    # Define GPS source priority chain
    sources = [
        ('gpsd', _get_gpsd),
        ('serial', _get_serial_nmea),
        ('bluetooth', _get_bluetooth_gps),
        ('manual', _get_manual)
    ]

    # Try each enabled source in priority order
    for source_name, source_function in sources:
        if GPS_CONFIG[source_name]['enabled']:
            result = source_function()
            if result:
                # Add current timestamp to GPS data
                result['timestamp'] = datetime.utcnow().isoformat()
                return result

    # No GPS source available or all failed
    return None


def _get_gpsd():
    """
    Retrieve GPS data from GPSD daemon.

    This function connects to the local GPSD daemon and retrieves the current
    GPS fix information. GPSD provides a standardized interface to GPS receivers.

    Returns:
        dict or None: GPS coordinates from GPSD or None if unavailable

    Requirements:
        - gpsd daemon running
        - GPS receiver connected and providing fixes
        - gpsd Python library installed

    GPSD Mode Values:
        - 0: No fix
        - 1: No fix (deprecated)
        - 2: 2D fix (latitude/longitude)
        - 3: 3D fix (lat/lon/altitude)
    """
    try:
        # Connect to GPSD daemon
        gpsd.connect()

        # Get current GPS packet
        packet = gpsd.get_current()

        # Check for valid GPS fix (2D or 3D)
        if packet.mode >= 2:
            return {
                'lat': packet.lat,
                'lon': packet.lon,
                'alt': getattr(packet, 'alt', None),      # Altitude if available
                'acc': getattr(packet, 'epx', None)       # Horizontal accuracy
            }

    except Exception:
        # GPSD connection or data retrieval failed
        pass

    return None


def _get_serial_nmea():
    """
    Retrieve GPS data from serial NMEA devices.

    This function scans configured serial ports for NMEA-compatible GPS devices,
    parsing GPGGA and GPRMC sentences for position information.

    Returns:
        dict or None: GPS coordinates from serial GPS or None if unavailable

    Serial Port Configuration:
        - Scans multiple ports: /dev/ttyACM0, /dev/ttyUSB0, /dev/ttyS0
        - 9600 baud rate (standard NMEA speed)
        - 1 second timeout for responsiveness

    NMEA Sentences:
        - GPGGA: Global Positioning System Fix Data
        - GPRMC: Recommended Minimum Navigation Information
    """
    # Iterate through configured serial ports
    for port in GPS_CONFIG['serial']['ports']:
        try:
            # Open serial connection
            ser = serial.Serial(
                port,
                GPS_CONFIG['serial']['baudrate'],
                timeout=GPS_CONFIG['serial']['timeout']
            )

            # Read NMEA sentence
            line = ser.readline().decode('ascii', errors='ignore')

            # Check for position sentences
            if line.startswith('$GPGGA') or line.startswith('$GPRMC'):
                # Parse NMEA sentence
                msg = pynmea2.parse(line)

                # Extract coordinates if available
                if hasattr(msg, 'latitude') and hasattr(msg, 'longitude'):
                    return {
                        'lat': msg.latitude,
                        'lon': msg.longitude,
                        'alt': getattr(msg, 'altitude', None),
                        'acc': getattr(msg, 'horizontal_dil', None)
                    }

        except Exception:
            # Port unavailable or parsing failed, try next port
            continue

    return None


def _get_bluetooth_gps():
    """
    Retrieve GPS data from Bluetooth GPS receivers.

    This function discovers nearby Bluetooth devices and attempts to connect
    to GPS-enabled devices for position data retrieval.

    Returns:
        dict or None: GPS coordinates from Bluetooth GPS or None if unavailable

    Discovery Process:
        1. Scan for nearby Bluetooth devices
        2. Filter for devices with 'gps' or 'gnss' in name
        3. Connect to RFCOMM port 1 (standard GPS service)
        4. Parse NMEA data from Bluetooth connection

    Security Note:
        Bluetooth discovery may reveal device presence to nearby scanners.
    """
    try:
        # Discover nearby Bluetooth devices
        nearby_devices = bluetooth.discover_devices(lookup_names=True)

        # Check each discovered device for GPS capability
        for addr, name in nearby_devices:
            if 'gps' in name.lower() or 'gnss' in name.lower():
                try:
                    # Create Bluetooth socket connection
                    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                    sock.connect((addr, GPS_CONFIG['bluetooth']['port']))

                    # Set socket timeout
                    sock.settimeout(GPS_CONFIG['bluetooth']['timeout'])

                    # Receive GPS data
                    data = sock.recv(1024).decode('ascii', errors='ignore')

                    # Parse NMEA sentences from received data
                    for line in data.split('\n'):
                        if line.startswith('$GPGGA') or line.startswith('$GPRMC'):
                            msg = pynmea2.parse(line)

                            if hasattr(msg, 'latitude') and hasattr(msg, 'longitude'):
                                sock.close()
                                return {
                                    'lat': msg.latitude,
                                    'lon': msg.longitude,
                                    'alt': getattr(msg, 'altitude', None),
                                    'acc': getattr(msg, 'horizontal_dil', None)
                                }

                    # Close socket if no valid data found
                    sock.close()

                except Exception:
                    # Connection failed, try next device
                    continue

    except Exception:
        # Bluetooth discovery or connection failed
        pass

    return None


def _get_manual():
    """
    Retrieve manually overridden GPS coordinates.

    This function returns user-specified GPS coordinates when manual override
    is active. Used for testing, emergency situations, or operational security.

    Returns:
        dict or None: Manual GPS coordinates or None if not set

    Note:
        Manual coordinates include their own timestamp from when they were set.
    """
    return manual_override