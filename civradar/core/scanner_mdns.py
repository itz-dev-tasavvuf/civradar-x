# civradar/core/scanner_mdns.py
import subprocess
import re

def scan_mdns(timeout=8, stealth=False):
    """Discover mDNS services (Avahi) — common for IoT"""
    if stealth:
        return []
    try:
        result = subprocess.run(
            ['timeout', str(timeout), 'avahi-browse', '-at', '--no-db-lookup'],
            capture_output=True,
            text=True,
            check=True
        )
        return parse_avahi(result.stdout)
    except Exception as e:
        return [{"error": f"mDNS scan failed: {str(e)}"}]

def parse_avahi(output):
    devices = {}
    for line in output.splitlines():
        if '=' not in line or 'IPv4' not in line:
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        name = parts[3]
        ip = parts[6]
        # Extract MAC via ARP (best effort)
        mac = get_mac_from_ip(ip)
        key = mac or ip
        if key not in devices:
            devices[key] = {
                'mac': mac or ip,
                'name': name,
                'protocol': 'mdns'
            }
    return list(devices.values())

def get_mac_from_ip(ip):
    try:
        arp_out = subprocess.check_output(['arp', '-n', ip], text=True)
        match = re.search(r'([0-9A-Fa-f:]{17})', arp_out)
        return match.group(1) if match else None
    except:
        return None