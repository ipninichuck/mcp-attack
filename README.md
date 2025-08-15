# MCP Attack Server

This project provides a robust and extensible server that implements the Model Context Protocol (MCP). It acts as a bridge between a large language model and external knowledge sources, allowing the model to query for real-time information. This server comes pre-configured with a powerful MITRE ATT&CK lookup capability, enabling your model to access and integrate up-to-date cybersecurity threat information.

## Key Capabilities

*   **Model Context Protocol (MCP) Server:** A fully implemented FastAPI server that adheres to the JSON-RPC 2.0 based Model Context Protocol.
*   **Extensible Handler System:** Easily add new capabilities and data sources for your model to query.
*   **Built-in MITRE ATT&CK Integration:** Out-of-the-box support for looking up MITRE ATT&CK techniques, tactics, and associated metadata.
*   **Automatic Data Updates:** The server will automatically download and stay current with the latest MITRE ATT&CK data.
*   **Simple Configuration:** Easily configure the server's host, port, and other settings.

## Quickstart

### 1. Install and Run with pipx

This project is designed to be run with `pipx`. `pipx` is a tool for installing and running Python applications in isolated environments.

If you don't have `pipx` installed, you can install it via pip:
```bash
pip install --user pipx
pipx ensurepath
```
(You may need to restart your shell for the `pipx` command to be available.)

Once `pipx` is set up, you can run the server directly from this repository:

```bash
pipx run .
```

This command temporarily installs the package in an isolated environment and runs the `mcp-server` command.

Alternatively, you can install the package globally (for your user):

```bash
pipx install .
```

And then run it anytime with:
```bash
mcp-server
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
setup.py
requirements.txt
README.md
```

- `handlers.py` — defines API endpoints.
- `main.py` — FastAPI app initialization and `run()` entrypoint for the `mcp-server` command.
- `config.py` — server configuration.
- `mitre_attack.py` — MITRE ATT&CK STIX handling and lookup.
- `setup.py` — defines the package and `mcp-server` command.
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
