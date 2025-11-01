# civradar/core/scanner_arp.py
import subprocess
import re

def scan_arp(stealth=False):
    """Scan local network hosts via ARP (fast, passive after initial ping)"""
    if stealth:
        return []
    try:
        # Trigger ARP population
        subprocess.run(['ping', '-c1', '-W1', '192.168.1.255'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.check_output(['arp', '-a'], text=True)
        return parse_arp(result)
    except Exception as e:
        return [{"error": f"ARP scan failed: {str(e)}"}]

def parse_arp(output):
    devices = []
    for line in output.splitlines():
        match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Fa-f:]{17})', line)
        if match:
            ip, mac = match.groups()
            devices.append({
                'mac': mac,
                'name': ip,
                'protocol': 'arp'
            })
    return devices