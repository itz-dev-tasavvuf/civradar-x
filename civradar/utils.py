import math
import re

def rssi_to_distance(rssi, freq_mhz=2437, tx_power=20):
    if rssi >= 0:
        return float('inf')
    fspl = (20 * math.log10(freq_mhz) + 20 * math.log10(0.001) - 27.55)
    distance = 10 ** ((tx_power - rssi - fspl) / 20)
    return round(max(0.5, min(distance, 100)), 1)

def sanitize_mac(mac):
    return re.sub(r'[^0-9A-Fa-f]', '', mac)[:12].upper()