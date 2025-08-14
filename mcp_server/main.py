from fastapi import FastAPI
from mcp_server.handlers import router

app = FastAPI(title="MCP Attack Server")

app.include_router(router)

def run():
    """Run the MCP server."""
    import uvicorn
    from mcp_server.config import settings
    uvicorn.run(app, host=settings.host, port=settings.port)