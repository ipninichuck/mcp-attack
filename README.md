# MCP Attack Server

A starter Python FastAPI server for handling Anthropic MCP (Message Control Protocol) requests.

## Features

- FastAPI app structure for easy extension
- Configurable host/port
- Example MCP endpoint at `/mcp/v1/message`

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
    main.py
    __main__.py
requirements.txt
README.md
```

- `handlers.py` — defines API endpoints.
- `main.py` — FastAPI app initialization.
- `config.py` — server configuration.
- `__main__.py` — entrypoint, runs the server.
- `requirements.txt` — Python dependencies.

## Customization

- Add new endpoints in `handlers.py` or new modules.
- Update logic for MCP handling as per Anthropic spec where marked with `TODO`.

## License

MIT (add your license here)