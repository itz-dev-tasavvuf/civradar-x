import json
import os
from typing import Dict, List, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(BASE_DIR, 'data', 'iot_signatures.json')

class ThreatIntelligence:
    def __init__(self):
        with open(DB_PATH) as f:
            self.db = json.load(f)

        # Vendor reputation scores (lower is better, 1-5 scale)
        self.vendor_reputation = {
            "google": 2, "apple": 2, "microsoft": 2,
            "amazon": 3, "xiaomi": 4, "tuya": 5,
            "ring": 4, "nest": 3, "arlo": 4,
            "fitbit": 3, "tile": 3, "garmin": 3,
            "samsung": 3, "philips": 3, "cisco": 4,
            "netgear": 4, "tplink": 4, "lifx": 3,
            "wyze": 4, "logitech": 3, "sonos": 3,
            "ecobee": 3, "smartthings": 4, "roku": 3,
            "chromecast": 3, "alexa": 3, "siri": 3,
            "google_home": 3, "facebook_portal": 5,
            "amazon_echo": 3, "owlet": 5, "nest_cam": 4,
            "blink": 4, "simpli": 4, "august": 4,
            "kwikset": 4, "schlage": 4, "ring_alarm": 5,
            "adt": 4, "vivint": 4, "simplisafe": 4,
            "canary": 5, "dropcam": 5, "logi_circle": 4,
            "eufy": 4, "uniden": 4, "summer_infant": 4,
            "vtech": 4, "motorola": 4, "levana": 4,
            "infant_optics": 4, "hello_baby": 4, "snuza": 4,
            "owlet_sock": 5, "lumi": 4, "ikea_tradfri": 3,
            "osram": 3, "cree": 3, "ge": 3, "sylvania": 3,
            "tp-link_kasa": 4, "wemo": 3, "sengled": 3,
            "meross": 4, "gosund": 4, "koogeek": 4,
            "aoycocr": 4, "minoston": 4, "atom": 4,
            "fe": 4, "smartlife": 4, "broadlink": 4,
            "xiaomi_mi": 4, "yeelight": 3, "aqara": 4,
            "ewelink": 4, "sonoff": 4, "shelly": 3,
            "tasmota": 2, "esphome": 2, "home_assistant": 2,
            "openhab": 2, "domoticz": 2, "jeedom": 2,
            "fibaro": 4, "vera": 3, "hubitat": 2,
            "smartthings_hub": 4, "echo_dot": 3,
            "google_nest_mini": 3, "homepod": 3, "cortana": 3,
            "bixby": 3, "alexa_guard": 4, "google_assistant": 3,
            "siri_home": 3, "facebook_messenger": 4, "zoom": 3,
            "skype": 3, "teams": 3, "webex": 3, "hangouts": 3,
            "facetime": 3, "whatsapp": 3, "telegram": 3,
            "signal": 2, "discord": 3, "slack": 3,
            "snapchat": 4, "instagram": 4, "tiktok": 4,
            "twitter": 4, "facebook": 4, "linkedin": 4,
            "pinterest": 4, "reddit": 4, "tumblr": 4,
            "flickr": 4, "vimeo": 4, "youtube": 4, "twitch": 4,
            "netflix": 3, "hulu": 3, "amazon_prime": 3,
            "disney_plus": 3, "hbo_max": 3, "spotify": 3,
            "pandora": 3, "apple_music": 3, "tidal": 3,
            "deezer": 3, "soundcloud": 3, "lastfm": 3,
            "shazam": 3, "google_maps": 4, "apple_maps": 4,
            "waze": 4, "uber": 4, "lyft": 4, "didi": 4,
            "grab": 4, "ola": 4, "careem": 4, "bolt": 4,
            "yandex_taxi": 4, "booking": 3, "airbnb": 3,
            "expedia": 3, "tripadvisor": 3, "kayak": 3,
            "priceline": 3, "hotels": 3, "agoda": 3,
            "trivago": 3, "orbitz": 3, "travelocity": 3,
            "cheapoair": 3, "momondo": 3, "skyscanner": 3,
            "rome2rio": 3, "viator": 3, "getyourguide": 3,
            "klook": 3, "wego": 3, "zomato": 3, "swiggy": 3,
            "ubereats": 3, "doordash": 3, "grubhub": 3,
            "postmates": 3, "seamless": 3, "eat24": 3,
            "foodpanda": 3, "deliveroo": 3, "just_eat": 3,
            "takeaway": 3, "dominos": 3, "pizzahut": 3,
            "papajohns": 3, "kfc": 3, "mcdonalds": 3,
            "burger_king": 3, "subway": 3, "starbucks": 3,
            "dunkin": 3, "tim_hortons": 3, "costa_coffee": 3,
            "nespresso": 3, "keurig": 3, "nescafe": 3,
            "instant_pot": 2, "breville": 2, "kitchenaid": 2,
            "cuisinart": 2, "wolf_gourmet": 2, "all_clad": 2,
            "calphalon": 2, "le_creuset": 2, "staub": 2,
            "lodge": 2, "vitamix": 2, "blendtec": 2,
            "oster": 2, "hamilton_beach": 2, "black_decker": 2,
            "dewalt": 2, "bosch": 2, "makita": 2, "ryobi": 2,
            "milwaukee": 2, "ridgid": 2, "craftsman": 2,
            "kobalt": 2, "husqvarna": 2, "stihl": 2,
            "echo": 3, "nest_thermostat": 3, "hue_bridge": 3,
            "smartthings_hub": 4, "vera_edge": 3,
            "hubitat_elevation": 2, "openhab_hub": 2,
            "home_assistant_hub": 2, "domoticz_hub": 2,
            "jeedom_hub": 2, "fibaro_home_center": 4,
            "control4": 3, "lutron": 2, "leviton": 2,
            "schneider_electric": 2, "abb": 2, "siemens": 2,
            "honeywell": 3, "ecobee_thermostat": 3,
            "nest_protect": 3, "first_alert": 2, "kidde": 2,
            "briggs": 2, "usii": 2, "x_sense": 2,
            "google_nest_protect": 3, "ring_alarm_protect": 4,
            "simpli_safe_protect": 3, "adt_protect": 4,
            "vivint_protect": 4, "alarm_com": 4, "frontpoint": 4,
            "protect_america": 4, "link_interactive": 4,
            "brinks": 4, "monitronics": 4, "guardian": 4,
            "cops": 4, "alliance": 4, "vector": 4,
            "resideo": 4, "alarmnet": 4, "total_connect": 4,
            "myq": 3, "chamberlain": 3, "liftmaster": 3,
            "craftsman_garage": 3, "genie": 3, "overhead_door": 3,
            "wayne_dalton": 3, "clopay": 3, "amarr": 3,
            "raynor": 3, "hormann": 3, "garador": 3,
            "secur": 3, "somfy": 2, "hunter_douglas": 2,
            "lutron_blind": 2, "serena": 2, "graber": 2,
            "kirsch": 2, "springs_window_fashions": 2,
            "bali": 2, "levolor": 2, "newell": 2,
            "comfortex": 2, "select_blinds": 2, "blindster": 2,
            "smith_noble": 2, "rolla": 2, "mecho": 2,
            "diy_blinds": 2, "smart_blinds": 2,
            "motorized_blinds": 2, "automatic_blinds": 2,
            "remote_blinds": 2, "wifi_blinds": 2,
            "zigbee_blinds": 2, "z_wave_blinds": 2,
            "infrared_blinds": 2, "bluetooth_blinds": 2,
            "manual_blinds": 1, "dumb_blinds": 1,
            "traditional_blinds": 1, "venetian_blinds": 1,
            "vertical_blinds": 1, "roller_blinds": 1,
            "roman_blinds": 1, "panel_blinds": 1,
            "cellular_blinds": 1, "wood_blinds": 1,
            "faux_wood_blinds": 1, "aluminum_blinds": 1,
            "mini_blinds": 1, "micro_blinds": 1
        }

        # Protocol-specific risk multipliers
        self.protocol_risks = {
            "wifi": 1.0,
            "ble": 0.8,
            "zigbee": 0.7,
            "z-wave": 0.7,
            "mdns": 0.9,
            "arp": 0.6,
            "unknown": 1.0
        }

    def calculate_dynamic_risk(self, device: Dict[str, Any]) -> int:
        """
        Calculate dynamic risk score based on multiple factors.
        Returns risk score from 1-5.
        """
        base_risk = device.get('privacy_risk', 1)
        flags = device.get('flags', [])
        vendor = device.get('vendor', '').lower()
        protocols = device.get('protocols', [])

        risk_score = base_risk

        # Mic/Camera presence
        if 'camera' in flags:
            risk_score += 1
        if 'mic' in flags:
            risk_score += 0.5

        # Cloud connectivity
        if 'cloud' in flags:
            risk_score += 0.5

        # Default credentials
        if 'default_credentials' in flags:
            risk_score += 1

        # Health data
        if 'health_data' in flags:
            risk_score += 1

        # Location tracking
        if 'location' in flags:
            risk_score += 0.5

        # Always listening
        if 'always_listening' in flags:
            risk_score += 0.5

        # Social tracking
        if 'social_tracking' in flags:
            risk_score += 0.5

        # Recording capability
        if 'recording' in flags:
            risk_score += 1

        # Multiple devices control
        if 'multiple_devices' in flags:
            risk_score += 0.5

        # Vendor reputation adjustment
        vendor_rep = self.vendor_reputation.get(vendor, 3)
        risk_score += (vendor_rep - 3) * 0.2  # Adjust by reputation

        # Protocol-specific risks
        protocol_risk = max([self.protocol_risks.get(p, 1.0) for p in protocols]) if protocols else 1.0
        risk_score *= protocol_risk

        # Confidence boost for multiple protocols
        confidence = device.get('confidence', 1)
        if confidence > 1:
            risk_score += min(0.5, confidence * 0.1)

        # Clamp to 1-5 range
        return max(1, min(5, round(risk_score)))

    def match_signature(self, name: str, mac: str) -> Optional[Dict[str, Any]]:
        """
        Match device against signatures database.
        """
        mac_clean = mac.replace(":", "").upper()[:6]
        vendor = self.db["OUI"].get(mac_clean, "Unknown")
        name_lower = name.lower()

        for brand, profile in self.db["SIGNATURES"].items():
            if brand in name_lower or brand in vendor.lower():
                return {
                    "type": profile["type"],
                    "vendor": vendor,
                    "model": name,
                    "privacy_risk": profile["risk"],
                    "flags": profile["flags"]
                }
        return None

    def get_vendor_reputation(self, vendor: str) -> int:
        """Get vendor reputation score."""
        return self.vendor_reputation.get(vendor.lower(), 3)

    def get_protocol_risk(self, protocol: str) -> float:
        """Get protocol-specific risk multiplier."""
        return self.protocol_risks.get(protocol, 1.0)