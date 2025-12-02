# src/attack_mcp/config.py
import os

# --- CONFIGURATION (Uncomment the pair you want to use) ---

# 1. ENTERPRISE ATT&CK (Default)
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.1.json"
ATTACK_DOMAIN = "enterprise-attack"

# 2. MOBILE ATT&CK
# ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-18.1.json"
# ATTACK_DOMAIN = "mobile-attack"

# 3. ICS ATT&CK
# ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-18.1.json"
# ATTACK_DOMAIN = "ics-attack"


# --- NAVIGATOR SETTINGS ---
DEFAULT_NAVIGATOR_VERSION = "4.8.0"
DEFAULT_LAYER_VERSION = "4.4"
