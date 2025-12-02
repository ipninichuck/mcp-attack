import requests
import networkx as nx
import hashlib
import logging
from ..config import ATTACK_STIX_URL, ATTACK_STIX_HASH
from ..logger import logger

class AttackGraph:
    def __init__(self):
        self.G = nx.DiGraph()
        self.attack_id_index = {}
        self.initialized = False

    def build(self):
        """Downloads STIX data (with security checks) and builds the graph."""
        if self.initialized:
            return
            
        logger.info(f"Downloading ATT&CK Data", extra={"props": {"url": ATTACK_STIX_URL}})
        
        # SECURITY 1: Timeouts
        # Prevent the server from hanging indefinitely if the connection stalls.
        try:
            response = requests.get(ATTACK_STIX_URL, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error("Download failed", exc_info=True)
            raise RuntimeError(f"Failed to download ATT&CK data: {e}")

        # SECURITY 2: Supply Chain Integrity (Hash Verification)
        # We verify the raw bytes before processing to ensure no tampering.
        file_content = response.content
        computed_hash = hashlib.sha256(file_content).hexdigest()

        if ATTACK_STIX_HASH:
            # Production Mode: Strict enforcement
            if computed_hash != ATTACK_STIX_HASH:
                error_msg = (
                    f"SECURITY ALERT: Hash Mismatch! "
                    f"Expected: {ATTACK_STIX_HASH} | Received: {computed_hash}"
                )
                logger.critical(error_msg)
                raise ValueError(error_msg)
        else:
            # Dev Mode: Trust On First Use (TOFU)
            logger.warning(
                f"Supply Chain Verification Disabled", 
                extra={"props": {"detected_hash": computed_hash, "action": "Add this hash to config.py"}}
            )

        # Parse JSON and build graph
        data =
