import uvicorn
from mcp_server.main import app
from mcp_server.config import settings

if __name__ == "__main__":
    uvicorn.run(app, host=settings.host, port=settings.port)