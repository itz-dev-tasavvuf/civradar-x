import re
from difflib import SequenceMatcher
from ..core.device_classifier import classify_device
from .threat_intelligence import ThreatIntelligence

threat_intel = ThreatIntelligence()

def fuse_devices(devices):
    """
    Fuse device data from multiple protocols into unified threat profiles.
    Correlates devices by MAC address and name similarity.
    """
    # Group by MAC first
    mac_groups = {}
    for device in devices:
        if 'error' in device:
            continue  # Skip error entries
        mac = device.get('mac', '').upper()
        if mac:
            if mac not in mac_groups:
                mac_groups[mac] = []
            mac_groups[mac].append(device)

    # Handle devices without MAC (e.g., some mDNS with IP only)
    no_mac_devices = [d for d in devices if not d.get('mac') or 'error' in d]

    # Now, correlate by name similarity for no-MAC devices or cross-MAC
    name_groups = {}
    for mac, devs in mac_groups.items():
        # Merge within MAC group
        fused = merge_devices(devs)
        name = fused.get('name', '').lower()
        if name not in name_groups:
            name_groups[name] = []
        name_groups[name].append(fused)

    # For no-MAC, group by name
    for device in no_mac_devices:
        if 'error' in device:
            continue
        name = device.get('name', '').lower()
        if name not in name_groups:
            name_groups[name] = []
        name_groups[name].append(device)

    # Now, for each name group, if multiple, check similarity and merge if close
    fused_list = []
    for name, devs in name_groups.items():
        if len(devs) == 1:
            fused_list.append(devs[0])
        else:
            # Check pairwise similarity
            merged = []
            used = set()
            for i, d1 in enumerate(devs):
                if i in used:
                    continue
                group = [d1]
                for j, d2 in enumerate(devs):
                    if j != i and j not in used:
                        if similar_names(d1.get('name', ''), d2.get('name', '')):
                            group.append(d2)
                            used.add(j)
                if len(group) > 1:
                    merged_dev = merge_devices(group)
                else:
                    merged_dev = d1
                fused_list.append(merged_dev)
                used.add(i)

    # Final classification and enrichment
    for device in fused_list:
        # Classify based on merged name and MAC
        classification = classify_device(device.get('name', ''), device.get('mac', ''))
        device.update(classification)
        # Add confidence: number of protocols
        device['confidence'] = len(device.get('protocols', []))
        # Apply dynamic risk scoring with protocol context
        device['privacy_risk'] = threat_intel.calculate_dynamic_risk(device)

    return fused_list

def merge_devices(devices):
    """
    Merge a list of device dicts into one.
    """
    if not devices:
        return {}
    merged = {'protocols': []}
    for dev in devices:
        for key, value in dev.items():
            if key == 'protocols':
                continue
            if key not in merged or not merged[key]:
                merged[key] = value
            elif key == 'name' and merged[key] != value:
                # Concatenate names if different
                merged[key] = f"{merged[key]} / {value}"
            elif key in ['rssi', 'distance'] and isinstance(value, (int, float)):
                # Average numeric values
                if key not in merged:
                    merged[key] = []
                merged[key].append(value)
        merged['protocols'].append(dev.get('protocol', 'unknown'))

    # Average rssi/distance
    for key in ['rssi', 'distance']:
        if key in merged and isinstance(merged[key], list):
            merged[key] = sum(merged[key]) / len(merged[key])

    merged['protocols'] = list(set(merged['protocols']))  # Unique protocols
    return merged

def similar_names(name1, name2, threshold=0.8):
    """
    Check if two names are similar using sequence matcher.
    """
    if not name1 or not name2:
        return False
    return SequenceMatcher(None, name1.lower(), name2.lower()).ratio() > threshold