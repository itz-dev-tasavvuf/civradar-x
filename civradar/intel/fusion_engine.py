"""
Device Fusion Engine Module for CIVRADAR-X

This module implements intelligent device data fusion capabilities for the
CIVRADAR-X system. It correlates and merges device information discovered
through multiple protocols (ARP, BLE, mDNS, WiFi) into unified threat profiles,
eliminating duplicates and enhancing intelligence accuracy.

Key Features:
- Multi-protocol device correlation by MAC address and name similarity
- Intelligent deduplication with fuzzy name matching
- Protocol confidence scoring based on detection sources
- Dynamic threat intelligence integration
- Signal strength averaging and distance estimation
- Comprehensive device classification and risk assessment

Fusion Process:
1. Group devices by MAC address (primary correlation)
2. Handle MAC-less devices (IP-only mDNS entries)
3. Apply name similarity matching for cross-MAC correlation
4. Merge device attributes with conflict resolution
5. Apply final classification and threat scoring

Correlation Strategies:
- MAC Address: Primary identifier, most reliable
- Name Similarity: Fuzzy matching with configurable threshold (80%)
- Protocol Diversity: Higher confidence with multiple detection methods
- Signal Averaging: RSSI/distance values averaged across detections

Data Enrichment:
- Device classification using IoT signatures database
- Dynamic risk scoring with threat intelligence context
- Protocol confidence metrics
- Geospatial correlation capabilities

Dependencies:
- difflib.SequenceMatcher: For fuzzy name matching
- device_classifier: For device type identification
- threat_intelligence: For dynamic risk assessment

Performance Considerations:
- O(n) MAC-based grouping for efficiency
- O(n²) name similarity comparison (acceptable for typical device counts)
- Memory-efficient merging with in-place updates

Author: CIVRADAR-X Development Team
"""

import re
from difflib import SequenceMatcher
from ..core.device_classifier import classify_device
from .threat_intelligence import ThreatIntelligence

# Initialize threat intelligence for dynamic risk calculations
threat_intel = ThreatIntelligence()


def fuse_devices(devices):
    """
    Fuse device data from multiple protocols into unified threat profiles.

    This function performs comprehensive device correlation and merging,
    transforming raw scan results into enriched intelligence profiles.
    It handles duplicate detection, attribute merging, and threat assessment.

    Args:
        devices (list): Raw device list from multiple scanners

    Returns:
        list: Fused device profiles with enhanced intelligence

    Fusion Algorithm:
        1. Filter out error entries
        2. Group by MAC address (primary correlation)
        3. Handle MAC-less devices separately
        4. Apply name similarity matching
        5. Merge attributes within groups
        6. Apply final classification and scoring
    """
    # Step 1: Filter out scan errors
    valid_devices = [device for device in devices if 'error' not in device]

    # Step 2: Primary grouping by MAC address
    mac_groups = {}
    for device in valid_devices:
        mac = device.get('mac', '').upper().strip()
        if mac:  # Only group devices with valid MAC addresses
            if mac not in mac_groups:
                mac_groups[mac] = []
            mac_groups[mac].append(device)

    # Step 3: Handle devices without MAC addresses (e.g., IP-only mDNS)
    no_mac_devices = [
        device for device in valid_devices
        if not device.get('mac', '').strip()
    ]

    # Step 4: Secondary grouping by name similarity
    name_groups = {}

    # Process MAC-grouped devices
    for mac, device_list in mac_groups.items():
        # Merge devices within the same MAC group
        fused_device = merge_devices(device_list)
        name = fused_device.get('name', '').lower().strip()

        # Group by normalized name for similarity matching
        if name not in name_groups:
            name_groups[name] = []
        name_groups[name].append(fused_device)

    # Process MAC-less devices
    for device in no_mac_devices:
        name = device.get('name', '').lower().strip()
        if name not in name_groups:
            name_groups[name] = []
        name_groups[name].append(device)

    # Step 5: Apply similarity-based merging within name groups
    fused_list = []
    for name, device_list in name_groups.items():
        if len(device_list) == 1:
            # Single device, no merging needed
            fused_list.append(device_list[0])
        else:
            # Multiple devices with same/similar names - check similarity
            merged_devices = []
            used_indices = set()

            for i, device1 in enumerate(device_list):
                if i in used_indices:
                    continue

                # Start group with current device
                similar_group = [device1]

                # Find similar devices
                for j, device2 in enumerate(device_list):
                    if j != i and j not in used_indices:
                        if similar_names(
                            device1.get('name', ''),
                            device2.get('name', ''),
                            threshold=0.8
                        ):
                            similar_group.append(device2)
                            used_indices.add(j)

                # Merge group if multiple devices found
                if len(similar_group) > 1:
                    merged_device = merge_devices(similar_group)
                else:
                    merged_device = device1

                fused_list.append(merged_device)
                used_indices.add(i)

    # Step 6: Final classification and enrichment
    for device in fused_list:
        # Apply device classification using signatures database
        classification = classify_device(
            device.get('name', ''),
            device.get('mac', '')
        )
        device.update(classification)

        # Calculate confidence based on protocol diversity
        device['confidence'] = len(device.get('protocols', []))

        # Apply dynamic risk scoring with full device context
        device['privacy_risk'] = threat_intel.calculate_dynamic_risk(device)

    return fused_list


def merge_devices(devices):
    """
    Merge multiple device dictionaries into a single unified profile.

    This function intelligently combines device attributes from multiple
    detections, handling conflicts through predefined merge strategies.

    Args:
        devices (list): List of device dictionaries to merge

    Returns:
        dict: Merged device dictionary with unified attributes

    Merge Strategies:
        - protocols: Collect unique protocol list
        - name: Concatenate different names with " / " separator
        - rssi/distance: Average numeric values
        - other fields: Use first non-empty value
    """
    if not devices:
        return {}

    # Initialize merged device with protocol tracking
    merged = {'protocols': []}

    # Collect all protocols and merge attributes
    for device in devices:
        for key, value in device.items():
            if key == 'protocols':
                continue  # Handle separately

            if key not in merged or not merged[key]:
                # First value for this key
                merged[key] = value

            elif key == 'name' and merged[key] != value:
                # Concatenate different device names
                merged[key] = f"{merged[key]} / {value}"

            elif key in ['rssi', 'distance'] and isinstance(value, (int, float)):
                # Collect numeric values for averaging
                if not isinstance(merged[key], list):
                    merged[key] = [merged[key]] if merged[key] else []
                merged[key].append(value)

        # Track protocols used for detection
        protocol = device.get('protocol', 'unknown')
        merged['protocols'].append(protocol)

    # Average numeric fields
    for numeric_key in ['rssi', 'distance']:
        if numeric_key in merged and isinstance(merged[numeric_key], list):
            values = [v for v in merged[numeric_key] if isinstance(v, (int, float))]
            if values:
                merged[numeric_key] = sum(values) / len(values)
            else:
                del merged[numeric_key]

    # Ensure unique protocol list
    merged['protocols'] = list(set(merged['protocols']))

    return merged


def similar_names(name1, name2, threshold=0.8):
    """
    Determine if two device names are similar using sequence matching.

    This function uses difflib's SequenceMatcher to calculate name similarity,
    enabling fuzzy matching for device deduplication across different protocols.

    Args:
        name1 (str): First device name
        name2 (str): Second device name
        threshold (float): Similarity threshold (0.0 to 1.0)

    Returns:
        bool: True if names are similar above threshold

    Algorithm:
        - Uses difflib.SequenceMatcher for efficient comparison
        - Case-insensitive matching
        - Configurable similarity threshold (default 80%)
        - Returns False for empty names
    """
    if not name1 or not name2:
        return False

    # Calculate similarity ratio using sequence matching
    similarity = SequenceMatcher(
        None,
        name1.lower(),
        name2.lower()
    ).ratio()

    return similarity > threshold