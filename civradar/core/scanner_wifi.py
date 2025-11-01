import subprocess
import re
from ..utils import rssi_to_distance

def scan_wifi(stealth=False):
    if stealth:
        return []
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        interfaces = re.findall(r'Interface (\w+)', result.stdout)
        if not interfaces:
            return []
        wlan = interfaces[0]
        subprocess.run(['sudo', 'iw', wlan, 'scan'], check=True, stdout=subprocess.DEVNULL)
        output = subprocess.check_output(['sudo', 'iw', wlan, 'scan', 'dump'], text=True)
        return parse_iw(output)
    except Exception as e:
        return [{"error": str(e)}]

def parse_iw(output):
    networks = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('BSS '):
            if current:
                finalize(current, networks)
            bssid = line.split()[1].split('(')[0]
            current = {'mac': bssid, 'name': '', 'rssi': -100, 'channel': 0, 'protocol': 'wifi'}
        elif 'SSID:' in line and current:
            current['name'] = line.split('SSID: ', 1)[1] or '<hidden>'
        elif 'signal:' in line and current:
            current['rssi'] = float(line.split()[1])
            current['distance'] = rssi_to_distance(current['rssi'])
    if current:
        finalize(current, networks)
    return networks

def finalize(net, networks):
    # Classification moved to fusion engine
    networks.append(net)