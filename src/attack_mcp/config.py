import os

# =============================================================================
# 1. MITRE ATT&CK DATA SOURCE (Select One Matrix)
# =============================================================================

# --- OPTION A: ENTERPRISE ATT&CK (v18.1) ---
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.1/enterprise-attack/enterprise-attack.json"
ATTACK_DOMAIN = "enterprise-attack"

# --- OPTION B: MOBILE ATT&CK (v18.1) ---
# ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.1/mobile-attack/mobile-attack.json"
# ATTACK_DOMAIN = "mobile-attack"

# --- OPTION C: ICS ATT&CK (v18.1) ---
# ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.1/ics-attack/ics-attack.json"
# ATTACK_DOMAIN = "ics-attack"


# =============================================================================
# 2. SECURITY & INTEGRITY
# =============================================================================

# SHA256 Hash of the STIX JSON file.
# METHOD 1 (Dev): Set to None. The server will download the file and PRINT the hash.
# METHOD 2 (Prod): Copy the printed hash here to enforce strict integrity checking.
ATTACK_STIX_HASH = None 
# Example: "0d1c347a4d584cf7e11ef46556c33b7689341443bf86299188d46c307274323b"

# Directory where generated Navigator layers will be saved.
# This prevents Path Traversal attacks by isolating writes to this folder.
OUTPUT_DIR = os.path.join(os.getcwd(), "outputs")


# =============================================================================
# 3. NAVIGATOR SETTINGS
# =============================================================================
DEFAULT_NAVIGATOR_VERSION = "4.8.0"
DEFAULT_LAYER_VERSION = "4.4"
