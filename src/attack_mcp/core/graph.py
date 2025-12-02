import requests
import networkx as nx
import logging
import hashlib
from ..config import ATTACK_STIX_URL, ATTACK_STIX_HASH

logger = logging.getLogger(__name__)

class AttackGraph:
    def __init__(self):
        self.G = nx.DiGraph()
        self.attack_id_index = {}
        self.initialized = False

    def build(self):
        """Downloads STIX data (with security checks) and builds the graph."""
        if self.initialized:
            return
            
        print(f"⏳ Downloading ATT&CK Data from: {ATTACK_STIX_URL} ...")
        
        # SECURITY 1: Timeouts
        # Prevent the server from hanging indefinitely if the connection stalls.
        try:
            response = requests.get(ATTACK_STIX_URL, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to download ATT&CK data: {e}")

        # SECURITY 2: Supply Chain Integrity (Hash Verification)
        # We verify the raw bytes before processing to ensure no tampering.
        file_content = response.content
        computed_hash = hashlib.sha256(file_content).hexdigest()

        if ATTACK_STIX_HASH:
            # Production Mode: Strict enforcement
            if computed_hash != ATTACK_STIX_HASH:
                raise ValueError(
                    f"🚨 SECURITY ALERT: Hash Mismatch!\n"
                    f"Expected: {ATTACK_STIX_HASH}\n"
                    f"Received: {computed_hash}\n"
                    f"The file may have been tampered with or corrupted. Aborting."
                )
        else:
            # Dev Mode: Trust On First Use (TOFU)
            print("-" * 60)
            print(f"⚠️  SECURITY NOTICE: Supply Chain Verification Disabled")
            print(f"   Detected Hash: {computed_hash}")
            print(f"   Action: Copy this hash into 'config.py' to secure your server.")
            print("-" * 60)

        # Parse JSON and build graph
        data = response.json()
        all_objects = data.get('objects', [])

        print("🏗️  Building NetworkX Graph...")
        
        # --- PASS 1: NODES ---
        for obj in all_objects:
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue
            
            obj_type = obj['type']
            if obj_type == 'relationship':
                continue

            stix_id = obj['id']
            attack_id = self._extract_attack_id(obj)

            attrs = {
                "type": obj_type,
                "name": obj.get('name', 'Unknown'),
                "description": (obj.get('description', '')[:500] + "...") if obj.get('description') else "No description.",
                "attack_id": attack_id,
                "kill_chain_phases": obj.get('kill_chain_phases', []),
                "raw": obj 
            }
            self.G.add_node(stix_id, **attrs)

            if attack_id:
                self.attack_id_index[attack_id.upper()] = stix_id

        # --- PASS 2: EDGES ---
        for obj in all_objects:
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue

            obj_type = obj['type']

            if obj_type == 'relationship':
                source = obj.get('source_ref')
                target = obj.get('target_ref')
                if source in self.G and target in self.G:
                    self.G.add_edge(source, target, relationship_type=obj.get('relationship_type'))

            elif obj_type == 'x-mitre-detection-strategy':
                source = obj['id']
                for ref_id in obj.get('x_mitre_analytic_refs', []):
                    if ref_id in self.G:
                        self.G.add_edge(source, ref_id, relationship_type='references_analytic')

            elif obj_type == 'x-mitre-analytic':
                source = obj['id']
                for ref_id in obj.get('x_mitre_data_component_refs', []):
                    if ref_id in self.G:
                        self.G.add_edge(source, ref_id, relationship_type='references_data_component')
                
                # Log Source Refs
                for ref in obj.get('x_mitre_log_source_references', []):
                    dc_id = ref.get('x_mitre_data_component_ref')
                    if dc_id and dc_id in self.G:
                        self.G.add_edge(source, dc_id, relationship_type='references_data_component')

        self.initialized = True
        print(f"✅ Graph Ready: {self.G.number_of_nodes()} Nodes, {self.G.number_of_edges()} Edges.")

    def _extract_attack_id(self, obj):
        if 'external_references' in obj:
            for ref in obj['external_references']:
                if ref.get('source_name') == 'mitre-attack':
                    return ref.get('external_id')
        return None

    def get_node_by_id_or_name(self, query: str):
        """Helper to resolve STIX ID from ATT&CK ID or Name."""
        q_clean = query.strip().upper()
        # Try ID first
        if q_clean in self.attack_id_index:
            return self.attack_id_index[q_clean]
        
        # Fallback to Name
        q_lower = query.strip().lower()
        for node_id, attrs in self.G.nodes(data=True):
            if attrs.get('name', '').lower() == q_lower:
                return node_id
        return None

# Singleton instance
knowledge_base = AttackGraph()
