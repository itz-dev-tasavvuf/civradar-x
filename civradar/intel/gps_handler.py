import gpsd
import serial
import pynmea2
import bluetooth
import time
from datetime import datetime

# Configuration for GPS sources
GPS_CONFIG = {
    'gpsd': {'enabled': True},
    'serial': {'enabled': True, 'ports': ['/dev/ttyACM0', '/dev/ttyUSB0', '/dev/ttyS0']},
    'bluetooth': {'enabled': True, 'devices': []},  # Will auto-discover
    'manual': {'enabled': True, 'lat': None, 'lon': None, 'alt': None, 'acc': None}
}

def update_gps_config(source, enabled=None, **kwargs):
    """Update GPS configuration dynamically"""
    if source in GPS_CONFIG:
        if enabled is not None:
            GPS_CONFIG[source]['enabled'] = enabled
        GPS_CONFIG[source].update(kwargs)

manual_override = None

def set_manual_override(lat, lon, alt=None, acc=None):
    global manual_override
    manual_override = {'lat': lat, 'lon': lon, 'alt': alt, 'acc': acc, 'timestamp': datetime.utcnow().isoformat()}

def get_gps():
    # Fallback chain: GPSD -> Serial NMEA -> Bluetooth GPS -> Manual -> None
    sources = [
        ('gpsd', _get_gpsd),
        ('serial', _get_serial_nmea),
        ('bluetooth', _get_bluetooth_gps),
        ('manual', _get_manual)
    ]

    for name, func in sources:
        if GPS_CONFIG[name]['enabled']:
            result = func()
            if result:
                result['timestamp'] = datetime.utcnow().isoformat()
                return result
    return None

def _get_gpsd():
    try:
        gpsd.connect()
        packet = gpsd.get_current()
        if packet.mode >= 2:  # 2D or 3D fix
            return {
                'lat': packet.lat,
                'lon': packet.lon,
                'alt': getattr(packet, 'alt', None),
                'acc': getattr(packet, 'epx', None)  # Horizontal accuracy
            }
    except Exception as e:
        pass
    return None

def _get_serial_nmea():
    for port in GPS_CONFIG['serial']['ports']:
        try:
            ser = serial.Serial(port, 9600, timeout=1)
            line = ser.readline().decode('ascii', errors='ignore')
            if line.startswith('$GPGGA') or line.startswith('$GPRMC'):
                msg = pynmea2.parse(line)
                if hasattr(msg, 'latitude') and hasattr(msg, 'longitude'):
                    return {
                        'lat': msg.latitude,
                        'lon': msg.longitude,
                        'alt': getattr(msg, 'altitude', None),
                        'acc': getattr(msg, 'horizontal_dil', None)
                    }
        except Exception as e:
            continue
    return None

def _get_bluetooth_gps():
    # Auto-discover Bluetooth GPS devices
    nearby_devices = bluetooth.discover_devices(lookup_names=True)
    for addr, name in nearby_devices:
        if 'gps' in name.lower() or 'gnss' in name.lower():
            try:
                sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                sock.connect((addr, 1))  # Assuming port 1 for GPS
                sock.settimeout(1)
                data = sock.recv(1024).decode('ascii', errors='ignore')
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
                sock.close()
            except Exception as e:
                continue
    return None

def _get_manual():
    return manual_override