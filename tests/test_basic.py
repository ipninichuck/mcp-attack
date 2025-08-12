from fastapi.testclient import TestClient
from mcp_server.main import app
from unittest.mock import patch
from mcp_server.mitre_attack import mitre_attack

# The module-level singleton `mitre_attack` is already loaded by the time tests run.
# We need to force it to use our fake bundle by changing its path and reloading.
mitre_attack.bundle_path = "tests/fake-enterprise-attack.json"
mitre_attack.load_bundle()

client = TestClient(app)

def test_mcp_message_notification():
    """Tests the MCP endpoint with a JSON-RPC notification (no id), which expects no content in response."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "notification_method"
    }
    response = client.post("/mcp/v1/message", json=request_payload)

    assert response.status_code == 204
    assert response.content == b""

def test_mcp_method_not_found():
    """Tests that calling a non-existent MCP method returns the correct JSON-RPC error."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "nonexistent/method",
        "id": "err-test-1"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "err-test-1"
    assert "error" in response_data
    assert response_data["error"]["code"] == -32601 # Method not found

def test_mcp_mitre_get_technique_invalid_params():
    """Tests 'mitre/getTechnique' with invalid parameters."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "mitre/getTechnique",
        "params": ["T1059"], # Incorrect type, should be an object
        "id": "err-test-2"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "err-test-2"
    assert "error" in response_data
    assert response_data["error"]["code"] == -32602 # Invalid params

def test_mcp_mitre_get_technique_success():
    """Tests the 'mitre/getTechnique' MCP method for a technique that is found."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "mitre/getTechnique",
        "params": {"id_or_name": "T9999"},
        "id": "test-id-456"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "test-id-456"
    assert "result" in response_data
    assert response_data["result"]["technique"]["name"] == "Fake Technique"

def test_mcp_mitre_get_technique_not_found():
    """Tests the 'mitre/getTechnique' MCP method for a technique that is NOT found."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "mitre/getTechnique",
        "params": {"id_or_name": "T0000"},
        "id": "test-id-457"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "test-id-457"
    assert "error" in response_data
    assert response_data["error"]["code"] == -32000

def test_mcp_initialize():
    """Tests the 'initialize' MCP method."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": "init-test-1"
    }
    response = client.post("/mcp/v1/message", json=request_payload)

    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "init-test-1"
    assert "result" in response_data

    result = response_data["result"]
    assert result["serverInfo"]["name"] == "MCP ATT&CK Server"
    assert len(result["methods"]) == 4

    method_names = {method["name"] for method in result["methods"]}
    assert "mitre/getTechnique" in method_names
    assert "mitre/getVersion" in method_names
    assert "mitre/updateBundle" in method_names
    assert "mitre/getTechniqueDetail" in method_names

def test_mcp_get_version():
    """Tests the 'mitre/getVersion' MCP method."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "mitre/getVersion",
        "id": "version-test-1"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "version-test-1"
    assert response_data["result"]["version"] == "Unknown"

@patch("mcp_server.mitre_attack.mitre_attack.update_bundle")
def test_mcp_update_bundle(mock_update_bundle):
    """Tests the 'mitre/updateBundle' MCP method."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "mitre/updateBundle",
        "id": "update-test-1"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "update-test-1"
    assert response_data["result"]["status"] == "success"

    mock_update_bundle.assert_called_once()

def test_mcp_get_technique_detail_success():
    """Tests 'mitre/getTechniqueDetail' for a valid detail."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "mitre/getTechniqueDetail",
        "params": {"id_or_name": "T9999", "detail": "data_sources"},
        "id": "detail-test-1"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "detail-test-1"
    assert "result" in response_data
    assert response_data["result"]["data_sources"] == [
        "Command: Command Execution",
        "Process: Process Creation"
    ]

def test_mcp_get_technique_detail_invalid_detail():
    """Tests 'mitre/getTechniqueDetail' for an invalid detail."""
    request_payload = {
        "jsonrpc": "2.0",
        "method": "mitre/getTechniqueDetail",
        "params": {"id_or_name": "T9999", "detail": "invalid_detail"},
        "id": "detail-test-2"
    }
    response = client.post("/mcp/v1/message", json=request_payload)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == "detail-test-2"
    assert "error" in response_data
    assert response_data["error"]["code"] == -32002

def test_mitre_technique_lookup_not_found():
    """Tests that the original MITRE technique endpoint returns a 404 for a non-existent technique."""
    response = client.get("/mitre/technique/T0000") # Use a different ID to not collide with fake data
    assert response.status_code == 404
    response_data = response.json()
    assert "detail" in response_data
    assert "No technique found" in response_data["detail"]