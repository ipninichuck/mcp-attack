
````markdown
# MITRE ATT&CK MCP Server

A Model Context Protocol (MCP) server that provides a graph-based interface for the [MITRE ATT&CK® Framework](https://attack.mitre.org/).

This server ingests the STIX 2.1 data for ATT&CK, builds an in-memory NetworkX graph, and exposes tools for Large Language Models to search, traverse relationships, and generate ATT&CK Navigator layers.

## 🚀 Features

* **Knowledge Graph:** Queries a structured graph of Techniques, Groups, Mitigation, and Data Components.
* **Deep Relationship Traversal:** Trace links from Techniques → Detection Strategies → Analytics → Data Components.
* **Navigator Integration:** Generate valid `layer.json` files on the fly based on conversation context.
* **Fast Execution:** Uses `uv` for dependency management and caching.

## 🛠️ Tools Available

The following tools are exposed to the MCP client:

| Tool Name | Description |
| :--- | :--- |
| `search_knowledge_base` | Search for any ATT&CK object (Technique, Group, Software) by ID (e.g., T1059) or fuzzy name match. |
| `explore_relationships` | Traverse the graph from a starting entity up to a specified depth (default: 2). Useful for finding "What groups use this software?" or "How do I detect this?" |
| `get_entity_details` | Retrieves deep context for an entity. For Techniques, it returns Mitigations and Detection Analytics. For Groups, it aggregates used Software/Malware. |
| `list_techniques_in_tactic` | Lists all techniques belonging to a specific Tactic (e.g., "Persistence", "Discovery"). |
| `generate_navigator_layer` | Creates a MITRE ATT&CK Navigator JSON layer highlighting specific techniques with a score and color. |

## 📦 Installation & Setup

### Prerequisites
* **Python 3.11+**
* **[uv](https://github.com/astral-sh/uv)** (Modern Python package manager)

### 1. Clone and Sync
Navigate to the project directory and install dependencies. `uv` will automatically create a virtual environment and install the exact versions defined in `uv.lock`.

```bash
cd attack-mcp-server
uv sync
````

### 2\. Verify Installation

Run the server entry point to ensure the graph builds correctly.

```bash
uv run python -m attack_mcp.main
```

*Note: The first run will download the ATT\&CK STIX data. Subsequent runs will be faster.*

## ⚙️ Configuration (Switching Matrices)

By default, this server loads the **Enterprise ATT\&CK** matrix. You can switch to **Mobile** or **ICS** by editing the configuration file.

1.  Open `src/attack_mcp/config.py`.
2.  Update the `ATTACK_STIX_URL` and `ATTACK_DOMAIN` variables.

**Example Configuration for Mobile:**

```python
# src/attack_mcp/config.py

# Mobile ATT&CK
ATTACK_STIX_URL = "[https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json)"
ATTACK_DOMAIN = "mobile-attack"
```

**Example Configuration for ICS:**

```python
# src/attack_mcp/config.py

# ICS ATT&CK
ATTACK_STIX_URL = "[https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json)"
ATTACK_DOMAIN = "ics-attack"
```

## 📂 Project Structure

```text
attack-mcp-server/
├── pyproject.toml       # Dependencies & Project Config
├── uv.lock              # Lockfile for reproducible builds
├── src/
│   └── attack_mcp/
│       ├── main.py      # Entry point
│       ├── server.py    # MCP Server Initialization
│       ├── config.py    # Configuration constants (Edit this to change Matrix)
│       ├── core/        # Logic for STIX/NetworkX
│       └── resources/   # Tool Definitions
```

## 📝 License

This project uses public data from [MITRE ATT\&CK®](https://attack.mitre.org/), which is subject to the [MITRE Terms of Use](https://attack.mitre.org/resources/terms-of-use/).

```
```
