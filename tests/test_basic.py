from fastapi.testclient import TestClient
from mcp_server.main import app

client = TestClient(app)

def test_mcp_message():
    response = client.post("/mcp/v1/message", json={"input": "test"})
    assert response.status_code == 200
    assert "message" in response.json()