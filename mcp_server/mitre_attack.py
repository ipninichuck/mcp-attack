import os
import json
import requests
from typing import List, Dict, Any
from stix2 import MemoryStore, Filter

MITRE_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ATTACK_BUNDLE_PATH = os.getenv("ATTACK_BUNDLE_PATH", "data/enterprise-attack.json")

def download_bundle(bundle_path: str = ATTACK_BUNDLE_PATH, bundle_url: str = MITRE_BUNDLE_URL):
    os.makedirs(os.path.dirname(bundle_path), exist_ok=True)
    print(f"Downloading the MITRE ATT&CK bundle from {bundle_url} ...")
    resp = requests.get(bundle_url)
    resp.raise_for_status()
    with open(bundle_path, "wb") as f:
        f.write(resp.content)
    print(f"Downloaded and saved MITRE ATT&CK bundle to {bundle_path}.")

def stix_to_dict(stix_obj: Any) -> Dict:
    """Deeply converts a stix2 object to a dictionary by serializing and reloading."""
    if not stix_obj:
        return stix_obj
    return json.loads(stix_obj.serialize())

class MitreAttack:
    def __init__(self, bundle_path: str = ATTACK_BUNDLE_PATH):
        self.bundle_path = bundle_path
        self.store = None
        self.load_bundle()

    def load_bundle(self):
        if not os.path.isfile(self.bundle_path):
            print("MITRE ATT&CK bundle not found, downloading latest...")
            try:
                download_bundle(self.bundle_path, MITRE_BUNDLE_URL)
            except Exception as e:
                raise FileNotFoundError(f"Could not download MITRE ATT&CK bundle: {e}")
        with open(self.bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.store = MemoryStore(stix_data=bundle["objects"])
        print(f"Loaded MITRE ATT&CK bundle from {self.bundle_path}.")

    def update_bundle(self):
        """Force download and reload the latest bundle."""
        print("Updating MITRE ATT&CK bundle...")
        download_bundle(self.bundle_path, MITRE_BUNDLE_URL)
        self.load_bundle()
        print("MITRE ATT&CK bundle updated.")

    def get_bundle_version(self) -> str:
        """
        Retrieves the modification date of the MITRE ATT&CK Identity object in the bundle.
        """
        attack_identity = self.store.query([
            Filter("type", "=", "identity"),
            Filter("name", "=", "MITRE ATT&CK")
        ])
        if attack_identity:
            return attack_identity[0].get("modified", "Unknown")
        return "Unknown"

    def find_technique(self, id_or_name: str):
        """
        Finds a technique by its external ID or name.
        Note: Iterates for external_id because direct filtering is complex.
        """
        all_techniques = self.store.query([Filter("type", "=", "attack-pattern")])

        # Try by external_id (e.g., T1059) by iterating
        for tech in all_techniques:
            if tech.get('external_references'):
                for ext_ref in tech['external_references']:
                    if ext_ref.get('source_name') == 'mitre-attack' and ext_ref.get('external_id') == id_or_name:
                        return tech

        # Try by name (case-insensitive)
        for tech in all_techniques:
            if tech.get("name", "").lower() == id_or_name.lower():
                return tech

        return None

    def get_related_objects(self, technique_obj) -> List[Dict[str, Any]]:
        related_objects = []
        technique_id = technique_obj["id"]

        source_rels = self.store.query([
            Filter("type", "=", "relationship"),
            Filter("source_ref", "=", technique_id)
        ])
        target_rels = self.store.query([
            Filter("type", "=", "relationship"),
            Filter("target_ref", "=", technique_id)
        ])

        all_rels = {rel['id']: rel for rel in source_rels + target_rels}
        relationships = [stix_to_dict(r) for r in all_rels.values()]

        seen_ids = {technique_id}
        for rel in relationships:
            for ref in ["source_ref", "target_ref"]:
                obj_id = rel.get(ref)
                if obj_id and obj_id not in seen_ids:
                    obj = self.store.get(obj_id)
                    if obj:
                        related_objects.append(stix_to_dict(obj))
                        seen_ids.add(obj_id)
        return relationships + related_objects

    def lookup(self, id_or_name: str) -> Dict[str, Any]:
        technique = self.find_technique(id_or_name)
        if not technique:
            return {"error": f"No technique found for '{id_or_name}'"}
        related = self.get_related_objects(technique)
        return {
            "technique": stix_to_dict(technique),
            "related_objects": related
        }

    def get_technique_detail(self, id_or_name: str, detail: str) -> Dict[str, Any]:
        """
        Retrieves a specific detail from a technique object.
        """
        technique = self.find_technique(id_or_name)
        if not technique:
            return {"error": f"No technique found for '{id_or_name}'"}

        detail_map = {
            "description": "description",
            "platforms": "x_mitre_platforms",
            "data_sources": "x_mitre_data_sources"
        }

        field_name = detail_map.get(detail)
        if not field_name:
            return {"error": f"Invalid detail requested: {detail}. Supported details are: {list(detail_map.keys())}"}

        value = stix_to_dict(technique).get(field_name)
        if value is None:
            return {"error": f"Detail '{detail}' not found in technique object."}

        return {detail: value}

# Singleton loader for FastAPI
mitre_attack = MitreAttack()
