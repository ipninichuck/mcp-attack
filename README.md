# MCP Attack Server

A starter Python FastAPI server for handling Anthropic MCP (Model Context Protocol) requests.

## Features

- FastAPI app structure for easy extension
- Configurable host/port
- Example MCP endpoint at `/mcp/v1/message`
- MITRE ATT&CK lookup endpoint with auto-download/update

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

### 3. MCP API Usage

The server provides a Model Context Protocol (MCP) endpoint at `/mcp/v1/message`. This endpoint uses the JSON-RPC 2.0 protocol for communication.

You can interact with it by sending `POST` requests with a JSON-RPC payload.

#### Available Methods

The server supports the following methods, which can be discovered by calling the `initialize` method.

##### `initialize`

Discovers the capabilities of the server.
- **Params:** None
- **Example Request:**
    ```bash
    curl -X POST http://127.0.0.1:8000/mcp/v1/message -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0", "method": "initialize", "id": "init-1"
    }'
    ```

##### `mitre/getTechnique`

Retrieves a full technique object and all its related STIX objects.
- **Params:** `{"id_or_name": "<technique_id_or_name>"}`
- **Example Request:**
    ```bash
    curl -X POST http://127.0.0.1:8000/mcp/v1/message -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0", "method": "mitre/getTechnique", "params": {"id_or_name": "T1059"}, "id": "get-tech-1"
    }'
    ```

##### `mitre/getTechniqueDetail`

Retrieves a specific detail from a technique object.
- **Params:** `{"id_or_name": "<technique_id>", "detail": "<detail_name>"}`
- **Supported Details:** `description`, `platforms`, `data_sources`
- **Example Request:**
    ```bash
    curl -X POST http://127.0.0.1:8000/mcp/v1/message -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0", "method": "mitre/getTechniqueDetail", "params": {"id_or_name": "T1059", "detail": "platforms"}, "id": "get-detail-1"
    }'
    ```

##### `mitre/getVersion`

Returns the version of the currently loaded ATT&CK data bundle (based on its modification date).
- **Params:** None
- **Example Request:**
    ```bash
    curl -X POST http://127.0.0.1:8000/mcp/v1/message -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0", "method": "mitre/getVersion", "id": "get-version-1"
    }'
    ```

##### `mitre/updateBundle`

Triggers a redownload of the ATT&CK data bundle from the source.
- **Params:** None
- **Example Request:**
    ```bash
    curl -X POST http://127.0.0.1:8000/mcp/v1/message -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0", "method": "mitre/updateBundle", "id": "update-1"
    }'
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

## Legacy REST API

The server also maintains a simple REST-style API for direct lookups.

**Technique Lookup Endpoint:**  
```
GET /mitre/technique/{id_or_name}
```

**Bundle Update Endpoint:**  
```
POST /mitre/update_bundle
```

## Customization

## License

MIT (add your license here)
