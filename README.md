
````markdown
# MITRE ATT&CK MCP Server

A Model Context Protocol (MCP) server that provides a graph-based interface for the [MITRE ATT&CK® Framework](https://attack.mitre.org/).

This server ingests the STIX 2.1 data for ATT&CK, builds an in-memory NetworkX graph, and exposes tools for Large Language Models to search, traverse relationships, and generate ATT&CK Navigator layers.

## 🚀 Features

* **Knowledge Graph:** Queries a structured graph of Techniques, Groups, Mitigation, and Data Components.
* **Deep Relationship Traversal:** Trace links from Techniques → Detection Strategies → Analytics → Data Components.
* **Navigator Integration:** Generate valid `layer.json` files on the fly based on conversation context.
* **Secure Supply Chain:** Verifies the SHA256 hash of MITRE data to prevent tampering.
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

*Note: The first run will download the ATT\&CK STIX data.*

## ⚙️ Configuration

The file `src/attack_mcp/config.py` controls which Matrix is loaded and manages security settings.

### Switching Matrices

By default, the server loads **Enterprise ATT\&CK**. To switch to **Mobile** or **ICS**, open `config.py` and comment/uncomment the appropriate block:

```python
# Example: Switch to Mobile
# ATTACK_STIX_URL = ".../enterprise-attack.json"  <-- Comment this out
# ATTACK_DOMAIN = "enterprise-attack"

ATTACK_STIX_URL = ".../mobile-attack.json"        <-- Uncomment this
ATTACK_DOMAIN = "mobile-attack"
```

## 🔒 Security Best Practices

### 1\. Supply Chain Integrity (Hash Verification)

To prevent tampering or data corruption, you should "pin" the hash of the STIX file.

1.  **Dev Mode (Trust On First Use):**
    Set `ATTACK_STIX_HASH = None` in `config.py`. Run the server. It will print the detected SHA256 hash of the downloaded file to the console.

2.  **Secure Mode:**
    Copy that hash and paste it into `config.py`:

    ```python
    ATTACK_STIX_HASH = "59b2..." # Paste actual hash here
    ```

    Now, the server will strictly validate the file integrity on every launch.

### 2\. File System Safety

All generated files (e.g., Navigator Layers) are restricted to the `outputs/` directory. The server cleans filenames to prevent Path Traversal attacks (e.g., `../../etc/passwd`).

## 📂 Project Structure

```text
attack-mcp-server/
├── pyproject.toml       # Dependencies & Project Config
├── uv.lock              # Lockfile for reproducible builds
├── src/
│   └── attack_mcp/
│       ├── main.py      # Entry point
│       ├── server.py    # MCP Server Initialization
│       ├── config.py    # Matrix Selection & Security Config
│       ├── core/        # Logic for STIX/NetworkX
│       └── resources/   # Tool Definitions
```

## 📝 License

This project uses public data from [MITRE ATT\&CK®](https://attack.mitre.org/), which is subject to the [MITRE Terms of Use](https://attack.mitre.org/resources/terms-of-use/).

```
```
