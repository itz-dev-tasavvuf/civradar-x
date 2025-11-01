"""
Device Classification Module for CIVRADAR-X

This module provides intelligent device classification capabilities for the CIVRADAR-X
civilian radar intelligence system. It analyzes device signatures, MAC addresses,
and service information to identify device types, vendors, and potential privacy risks.

Key Features:
- MAC address-based vendor identification using OUI database
- IoT device signature matching for comprehensive classification
- Dynamic privacy risk assessment integration
- Support for multiple device types (smart home, security, medical, etc.)

Dependencies:
- iot_signatures.json: Database of device signatures and OUI mappings
- threat_intelligence.py: For dynamic risk scoring calculations

Author: CIVRADAR-X Development Team
"""

import json
import os
from ..intel.threat_intelligence import ThreatIntelligence

# Determine the base directory for relative path resolution
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Path to the IoT signatures database containing device profiles and OUI mappings
DB_PATH = os.path.join(BASE_DIR, '..', 'data', 'iot_signatures.json')

# Load the device signatures database at module initialization
# This database contains:
# - OUI: MAC address prefix to vendor mappings
# - SIGNATURES: Device brand profiles with risk assessments and flags
with open(DB_PATH) as f:
    DB = json.load(f)

# Initialize threat intelligence module for dynamic risk calculations
threat_intel = ThreatIntelligence()


def classify_device(name, mac, services=None):
    """
    Classify a device based on its name, MAC address, and optional services.

    This function performs comprehensive device identification by:
    1. Extracting vendor information from MAC address OUI
    2. Matching device signatures against known IoT profiles
    3. Applying dynamic risk scoring based on current threat intelligence

    Args:
        name (str): Device hostname or display name
        mac (str): MAC address in format XX:XX:XX:XX:XX:XX
        services (list, optional): List of discovered services (unused in current implementation)

    Returns:
        dict: Classification result containing:
            - type: Device category (smart_home, security, medical, etc.)
            - vendor: Manufacturer name from OUI lookup
            - model: Original device name/model string
            - privacy_risk: Risk score (1-10, higher = more risky)
            - flags: List of security/privacy flags

    Note:
        Even unknown devices receive basic classification with vendor info
        and undergo threat intelligence risk assessment.
    """
    # Clean MAC address for OUI lookup (remove colons, uppercase, first 6 chars)
    mac_clean = mac.replace(":", "").upper()[:6]

    # Lookup vendor using Organizationally Unique Identifier (OUI)
    vendor = DB["OUI"].get(mac_clean, "Unknown")

    # Convert device name to lowercase for case-insensitive matching
    name_lower = name.lower()

    # Iterate through known device signatures for brand matching
    for brand, profile in DB["SIGNATURES"].items():
        # Check if brand appears in device name or vendor string
        if brand in name_lower or brand in vendor.lower():
            # Create classification dictionary with profile data
            classification = {
                "type": profile["type"],          # Device category
                "vendor": vendor,                 # Hardware manufacturer
                "model": name,                    # Device model/name
                "privacy_risk": profile["risk"],  # Base risk score from database
                "flags": profile["flags"]         # Security/privacy flags
            }

            # Apply dynamic risk scoring based on current threat intelligence
            # This may adjust the base risk score based on recent vulnerabilities,
            # exploit patterns, or other threat data
            classification["privacy_risk"] = threat_intel.calculate_dynamic_risk(classification)

            return classification

    # Fallback classification for unrecognized devices
    # Still provides vendor info and applies threat intelligence assessment
    classification = {
        "type": "unknown",      # Unidentified device type
        "vendor": vendor,       # Vendor from MAC OUI (may be "Unknown")
        "privacy_risk": 1,      # Low base risk for unknown devices
        "flags": []             # No specific flags
    }

    # Apply threat intelligence even for unknown devices
    classification["privacy_risk"] = threat_intel.calculate_dynamic_risk(classification)

    return classification