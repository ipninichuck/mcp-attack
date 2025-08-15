# MCP Attack Server

This project provides a robust and extensible server that implements the Model Context Protocol (MCP). It acts as a bridge between a large language model and external knowledge sources, allowing the model to query for real-time information. This server comes pre-configured with a powerful MITRE ATT&CK lookup capability, enabling your model to access and integrate up-to-date cybersecurity threat information.

## Key Capabilities

*   **Model Context Protocol (MCP) Server:** A fully implemented FastAPI server that adheres to the JSON-RPC 2.0 based Model Context Protocol.
*   **Extensible Handler System:** Easily add new capabilities and data sources for your model to query.
*   **Built-in MITRE ATT&CK Integration:** Out-of-the-box support for looking up MITRE ATT&CK techniques, tactics, and associated metadata.
*   **Automatic Data Updates:** The server will automatically download and stay current with the latest MITRE ATT&CK data.
*   **Simple Configuration:** Easily configure the server's host, port, and other settings.

## Quickstart

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the server

```bash
python -m mcp_server
```

The server will start on `127.0.0.1:8000` by default.

### 3. Test the endpoint

You can send a POST request to:

```
POST http://127.0.0.1:8000/mcp/v1/message
Content-Type: application/json

{
  "example": "payload"
}
```

### 4. Configuration

Edit `mcp_server/config.py` to change the default host and port.

## Project Structure

```
mcp_server/
    __init__.py
    config.py
    handlers.py
    mitre_attack.py
    main.py
    __main__.py
requirements.txt
README.md
```

- `handlers.py` — defines API endpoints.
- `main.py` — FastAPI app initialization.
- `config.py` — server configuration.
- `mitre_attack.py` — MITRE ATT&CK STIX handling and lookup.
- `__main__.py` — entrypoint, runs the server.
- `requirements.txt` — Python dependencies.

## MITRE ATT&CK Lookup

### Data Setup

On server startup, the server checks for the MITRE ATT&CK Enterprise STIX bundle in `data/enterprise-attack.json` (by default):

- If the file does **not** exist, it downloads the latest version from MITRE's official GitHub.
- If the file **does** exist, it uses the cached file.
- You can customize the bundle path with the `ATTACK_BUNDLE_PATH` environment variable.

### API Usage

**Technique Lookup Endpoint:**  
```
GET /mitre/technique/{id_or_name}
```

**Returns:**  
- The ATT&CK technique object for the given ID or name
- All related objects (mitigations, software, groups, etc.) per STIX relationships

**Bundle Update Endpoint:**  
```
POST /mitre/update_bundle
```
- Forces the server to download the latest ATT&CK bundle and reload it in memory.

**Example Request:**  
```
GET /mitre/technique/T1059
POST /mitre/update_bundle
```

**Example Response:**  
```json
{
  "technique": { ... },
  "related_objects": [ ... ]
}
```

## Customization

- Add new endpoints in `handlers.py` or new modules.
- Update logic for MCP handling as per Anthropic spec where marked with `TODO`.

## License

MIT (add your license here)
