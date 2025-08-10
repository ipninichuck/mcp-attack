from fastapi import APIRouter

router = APIRouter()

@router.post("/mcp/v1/message")
async def handle_mcp_message(request: dict):
    """
    Handle incoming MCP requests. Stub for actual logic.
    """
    # TODO: Implement MCP logic per Anthropic spec
    return {"message": "MCP request received", "request": request}