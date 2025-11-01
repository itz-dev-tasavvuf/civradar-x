# civradar/core/scanner_ble.py
import subprocess
import re
import time
from ..utils import sanitize_mac

def scan_ble(timeout=10, stealth=False):
    """Passive BLE scan using hcitool + btmon (no pairing)"""
    if stealth:
        return []
    try:
        # Reset HCI
        subprocess.run(['sudo', 'hciconfig', 'hci0', 'reset'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Start monitor
        proc = subprocess.Popen(
            ['sudo', 'btmon'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        time.sleep(2)
        # Trigger scan
        subprocess.run(['sudo', 'hcitool', 'lescan', '--passive'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        time.sleep(timeout)
        proc.terminate()
        output, _ = proc.communicate()

        return parse_btmon(output)
    except Exception as e:
        return [{"error": f"BLE scan failed: {str(e)}"}]

def parse_btmon(output):
    devices = {}
    current_addr = None
    for line in output.splitlines():
        line = line.strip()
        if 'Address:' in line:
            match = re.search(r'([0-9A-F:]{17})', line)
            if match:
                current_addr = sanitize_mac(match.group(1))
                if current_addr not in devices:
                    devices[current_addr] = {
                        'mac': current_addr,
                        'name': '<unknown>',
                        'protocol': 'ble'
                    }
        elif 'Name:' in line and current_addr:
            name = line.split('Name:', 1)[1].strip().strip('"')
            if name:
                devices[current_addr]['name'] = name
    return list(devices.values())