import json
import collections
import os
import re
from mcp.server.fastmcp import Context
from ..server import mcp
from ..core.graph import knowledge_base
from ..config import DEFAULT_NAVIGATOR_VERSION, DEFAULT_LAYER_VERSION, ATTACK_DOMAIN, OUTPUT_DIR

@mcp.tool()
def search_knowledge_base(query: str) -> str:
    """Search for ANY object in ATT&CK (Campaigns, Malware, Techniques)."""
    
    # SECURITY: Input Length Check (Prevent ReDoS or Memory Exhaustion)
    if len(query) > 100:
        return json.dumps({"error": "Query too long. Please limit search to 100 characters."})

    # Ensure graph is built
    if not knowledge_base.initialized: knowledge_base.build()
    
    G = knowledge_base.G
    q = query.strip()
    results = []

    # Direct ID lookup
    stix_id = knowledge_base.get_node_by_id_or_name(q)
    if stix_id:
        res = G.nodes[stix_id].copy()
        res['id'] = res.pop('attack_id', None)
        res.pop('raw', None)
        results.append(res)
    else:
        # Fuzzy Name search
        q_lower = q.lower()
        for node_id, attrs in G.nodes(data=True):
            if q_lower in attrs.get('name', '').lower():
                res = attrs.copy()
                res['id'] = res.get('attack_id')
                res.pop('raw', None)
                results.append(res)
                if len(results) >= 5: break

    return json.dumps(results)

@mcp.tool()
def explore_relationships(attack_id_or_name: str, depth: int = 2) -> str:
    """Traverses the ATT&CK graph up to a specified depth."""
    
    # SECURITY: Cap depth to prevent accidental large graph dumps
    if depth > 4:
        return json.dumps({"error": "Depth limited to maximum 4."})

    if not knowledge_base.initialized: knowledge_base.build()
    G = knowledge_base.G

    start_node = knowledge_base.get_node_by_id_or_name(attack_id_or_name)
    if not start_node:
        return "Entity not found."

    results = []
    visited = {start_node}
    queue = collections.deque([(start_node, 0)])

    while queue:
        curr_id, dist = queue.popleft()
        if dist >= depth: continue

        # Filter noise types if we moved away from start
        if curr_id != start_node:
            if G.nodes[curr_id]['type'] in ['attack-pattern', 'malware', 'tool']:
                continue

        # Outgoing
        for neighbor in G.successors(curr_id):
            if neighbor not in visited:
                edge_data = G.get_edge_data(curr_id, neighbor)
                results.append({
                    "name": G.nodes[neighbor]['name'],
                    "type": G.nodes[neighbor]['type'],
                    "relationship": edge_data.get('relationship_type', 'connected'),
                    "direction": "outgoing",
                    "distance": dist + 1
                })
                visited.add(neighbor)
                queue.append((neighbor, dist + 1))
        
        # Incoming
        for neighbor in G.predecessors(curr_id):
            if neighbor not in visited:
                edge_data = G.get_edge_data(neighbor, curr_id)
                results.append({
                    "name": G.nodes[neighbor]['name'],
                    "type": G.nodes[neighbor]['type'],
                    "relationship": edge_data.get('relationship_type', 'connected'),
                    "direction": "incoming",
                    "distance": dist + 1
                })
                visited.add(neighbor)
                queue.append((neighbor, dist + 1))

    return json.dumps(results[:1000])

@mcp.tool()
def list_techniques_in_tactic(tactic_name: str) -> str:
    """Lists all techniques associated with a given ATT&CK tactic name."""
    if not knowledge_base.initialized: knowledge_base.build()
    G = knowledge_base.G
    
    q_clean = tactic_name.strip().lower()
    results = []
    for _, attrs in G.nodes(data=True):
        if attrs['type'] == 'attack-pattern':
            for phase in attrs.get('kill_chain_phases', []):
                if q_clean in phase.get('phase_name', '').replace('-', ' '):
                    results.append({
                        "name": attrs['name'],
                        "id": attrs.get('attack_id')
                    })
                    break
    return json.dumps(results)

@mcp.tool()
def generate_navigator_layer(technique_ids: list[str], filename: str) -> str:
    """Generates a Navigator Layer JSON file."""
    if not knowledge_base.initialized: knowledge_base.build()
    
    try:
        # SECURITY: Path Traversal Prevention
        
        # 1. Strip directory paths (forcing filename to be just a name, not a path)
        safe_filename = os.path.basename(filename)
        
        # 2. Whitelist allowed characters (Alphanumeric, underscore, dash, dot)
        # This prevents shell injection or control characters
        safe_filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '', safe_filename)
        
        # 3. Enforce extension
        if not safe_filename.endswith(".json"): 
            safe_filename += ".json"
            
        # 4. Ensure Output Directory exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # 5. Construct full safe path
        output_path = os.path.join(OUTPUT_DIR, safe_filename)
        
        layer_dict = {
            "name": "MCP Generated Layer",
            "versions": {"attack": "18", "navigator": DEFAULT_NAVIGATOR_VERSION, "layer": DEFAULT_LAYER_VERSION},
            "domain": ATTACK_DOMAIN, # Configured in config.py
            "techniques": []
        }
        
        count = 0
        for t_id in technique_ids:
            tid_clean = t_id.strip().upper()
            stix_id = knowledge_base.attack_id_index.get(tid_clean)
            
            if stix_id:
                layer_dict["techniques"].append({
                    "techniqueID": tid_clean, 
                    "score": 1, 
                    "color": "#ff6666",
                    "comment": knowledge_base.G.nodes[stix_id]['name']
                })
                count += 1
                
        with open(output_path, 'w') as f: 
            json.dump(layer_dict, f, indent=4)
            
        return f"SUCCESS: Layer created at `{output_path}` with {count} techniques."
    except Exception as e: 
        return f"Error creating layer: {str(e)}"

@mcp.tool()
def get_entity_details(entity_id: str) -> str:
    """Retrieves detailed information (Mitigations, Detections, Software) for a given ID."""
    if not knowledge_base.initialized: knowledge_base.build()
    G = knowledge_base.G

    stix_id = knowledge_base.get_node_by_id_or_name(entity_id)
    if not stix_id:
        return json.dumps({"error": f"ID or Name '{entity_id}' not found."})

    node = G.nodes[stix_id]
    response = {
        "id": entity_id,
        "name": node['name'],
        "type": node['type'],
        "description": node['description']
    }

    # CASE 1: Technique Logic
    if node['type'] == 'attack-pattern':
        mitigations = []
        detections = []
        
        # Mitigations
        for src, _, attrs in G.in_edges(stix_id, data=True):
            if attrs.get('relationship_type') == 'mitigates':
                src_node = G.nodes[src]
                if src_node['type'] == 'course-of-action':
                    mitigations.append(src_node['name'])
        
        # Detections (Strategy -> Analytic -> Data Component)
        for strat_id, _, attrs in G.in_edges(stix_id, data=True):
             if attrs.get('relationship_type') == 'detects':
                strat_node = G.nodes[strat_id]
                if strat_node['type'] == 'x-mitre-detection-strategy':
                    strategy_info = {
                        "strategy_name": strat_node['name'],
                        "analytics": []
                    }
                    for analytic_id in G.successors(strat_id):
                        ana_node = G.nodes[analytic_id]
                        edge_sa = G.get_edge_data(strat_id, analytic_id)
                        if ana_node['type'] == 'x-mitre-analytic' and edge_sa.get('relationship_type') == 'references_analytic':
                            raw_analytic = ana_node.get('raw', {})
                            log_sources = []
                            # Parse Log Source Refs
                            if 'x_mitre_log_source_references' in raw_analytic:
                                for ref in raw_analytic['x_mitre_log_source_references']:
                                    dc_ref = ref.get('x_mitre_data_component_ref')
                                    dc_name = "Unknown"
                                    if dc_ref and dc_ref in G:
                                        dc_name = G.nodes[dc_ref]['name']
                                    log_sources.append({
                                        "data_component": dc_name,
                                        "log_source": ref.get('name')
                                    })
                            strategy_info["analytics"].append({
                                "analytic_name": ana_node['name'],
                                "log_sources": log_sources
                            })
                    detections.append(strategy_info)

        response["mitigations"] = mitigations
        response["detections"] = detections

    # CASE 2: Intrusion Set Logic
    elif node['type'] == 'intrusion-set':
        software = []
        unique_software = set()

        # Direct Software use
        for neighbor in G.successors(stix_id):
            edge_data = G.get_edge_data(stix_id, neighbor)
            if edge_data.get('relationship_type') == 'uses':
                tgt_node = G.nodes[neighbor]
                if tgt_node['type'] in ['malware', 'tool']:
                    if tgt_node['name'] not in unique_software:
                        software.append({"name": tgt_node['name'], "type": tgt_node['type'], "relation": "direct"})
                        unique_software.add(tgt_node['name'])
        
        response['software'] = software

    return json.dumps(response)
