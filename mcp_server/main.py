from fastapi import FastAPI
from mcp_server.handlers import router

app = FastAPI(title="MCP Attack Server")

app.include_router(router)