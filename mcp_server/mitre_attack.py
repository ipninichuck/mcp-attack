import os
import json
import requests
from typing import List, Dict, Any
from stix2 import MemoryStore

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

    def find_technique(self, id_or_name: str):
        # Try by external_id (e.g., T1059)
        results = self.store.query([
            {"type": "attack-pattern", "external_references.external_id": id_or_name}
        ])
        if not results:
            # Try by name (case-insensitive)
            results = self.store.query([
                {"type": "attack-pattern", "name": id_or_name}
            ])
            if not results:
                # Try lower-case name for fuzziness
                for obj in self.store.query([{"type": "attack-pattern"}]):
                    if obj.get("name", "").lower() == id_or_name.lower():
                        results = [obj]
                        break
        return results[0] if results else None

    def get_related_objects(self, technique_obj) -> List[Dict[str, Any]]:
        related_objects = []
        technique_id = technique_obj["id"]
        # Find all relationships where this technique is source or target
        relationships = self.store.query([
            {"type": "relationship",
             "$or": [
                 {"source_ref": technique_id},
                 {"target_ref": technique_id}
             ]}
        ])
        seen_ids = {technique_id}
        for rel in relationships:
            for ref in ["source_ref", "target_ref"]:
                obj_id = rel.get(ref)
                if obj_id and obj_id not in seen_ids:
                    obj = self.store.get(obj_id)
                    if obj:
                        related_objects.append(obj)
                        seen_ids.add(obj_id)
        return relationships + related_objects

    def lookup(self, id_or_name: str) -> Dict[str, Any]:
        technique = self.find_technique(id_or_name)
        if not technique:
            return {"error": f"No technique found for '{id_or_name}'"}
        related = self.get_related_objects(technique)
        return {
            "technique": technique,
            "related_objects": related
        }

# Singleton loader for FastAPI
mitre_attack = MitreAttack()
