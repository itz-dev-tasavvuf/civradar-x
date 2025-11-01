import json
import os
from ..intel.threat_intelligence import ThreatIntelligence

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, '..', 'data', 'iot_signatures.json')

with open(DB_PATH) as f:
    DB = json.load(f)

# Initialize threat intelligence
threat_intel = ThreatIntelligence()

def classify_device(name, mac, services=None):
    mac_clean = mac.replace(":", "").upper()[:6]
    vendor = DB["OUI"].get(mac_clean, "Unknown")
    name_lower = name.lower()

    for brand, profile in DB["SIGNATURES"].items():
        if brand in name_lower or brand in vendor.lower():
            classification = {
                "type": profile["type"],
                "vendor": vendor,
                "model": name,
                "privacy_risk": profile["risk"],
                "flags": profile["flags"]
            }
            # Apply dynamic risk scoring
            classification["privacy_risk"] = threat_intel.calculate_dynamic_risk(classification)
            return classification

    # For unknown devices, still apply basic classification
    classification = {"type": "unknown", "vendor": vendor, "privacy_risk": 1, "flags": []}
    classification["privacy_risk"] = threat_intel.calculate_dynamic_risk(classification)
    return classification