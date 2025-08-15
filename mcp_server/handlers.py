from fastapi import APIRouter, HTTPException, Response
from mcp_server.mitre_attack import mitre_attack
from pydantic import BaseModel
from typing import Any, Optional, Union

router = APIRouter()

# --- MCP Endpoint and Models ---

# Pydantic models for JSON-RPC 2.0, as per MCP specification
class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Union[dict, list]] = None
    id: Optional[Union[str, int]] = None

class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[dict] = None
    id: Union[str, int, None]

@router.post("/mcp/v1/message", response_model=JsonRpcResponse, response_model_exclude_none=True)
async def mcp_message(request: JsonRpcRequest):
    """
    Handles MCP requests, which follow the JSON-RPC 2.0 protocol.
    Dispatches requests to appropriate handlers based on the method.
    """
    if request.id is None:
        # This is a notification. Per spec, we don't respond.
        # A real implementation might log the notification or trigger a background task.
        return Response(status_code=204)

    # --- Method Dispatch for Requests with an ID ---
    if request.method == "initialize":
        # Return server capabilities for discovery
        capabilities = {
            "serverInfo": {
                "name": "MCP ATT&CK Server"
            },
            "methods": [
                {
                    "name": "mitre/getTechnique",
                    "description": "Looks up a MITRE ATT&CK technique by its ID (e.g., 'T1059') or name. Returns a detailed object for the technique and all related objects.",
                    "paramsSchema": {
                        "type": "object",
                        "properties": {
                            "id_or_name": {
                                "type": "string",
                                "description": "The ID or name of the technique to look up."
                            }
                        },
                        "required": ["id_or_name"]
                    }
                },
                {
                    "name": "mitre/getVersion",
                    "description": "Returns the modification date of the loaded MITRE ATT&CK bundle, which serves as its version.",
                    "paramsSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "mitre/updateBundle",
                    "description": "Triggers a redownload of the MITRE ATT&CK bundle from the source.",
                    "paramsSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "mitre/getTechniqueDetail",
                    "description": "Retrieves a specific detail for a given technique. Supported details: 'description', 'platforms', 'data_sources'.",
                    "paramsSchema": {
                        "type": "object",
                        "properties": {
                            "id_or_name": {
                                "type": "string",
                                "description": "The ID or name of the technique to look up."
                            },
                            "detail": {
                                "type": "string",
                                "description": "The specific detail to retrieve."
                            }
                        },
                        "required": ["id_or_name", "detail"]
                    }
                }
            ]
        }
        return JsonRpcResponse(id=request.id, result=capabilities)

    elif request.method == "mitre/getTechnique":
        # Validate params
        if not isinstance(request.params, dict) or "id_or_name" not in request.params:
            return JsonRpcResponse(
                id=request.id,
                error={"code": -32602, "message": "Invalid params: 'params' must be an object with 'id_or_name'."}
            )

        id_or_name = request.params["id_or_name"]
        result = mitre_attack.lookup(id_or_name)

        if "error" in result:
            # Technique not found, return a custom JSON-RPC error
            return JsonRpcResponse(
                id=request.id,
                error={"code": -32000, "message": "Technique not found", "data": result["error"]}
            )
        else:
            # Technique found, return the result
            return JsonRpcResponse(
                id=request.id,
                result=result
            )

    elif request.method == "mitre/getVersion":
        version = mitre_attack.get_bundle_version()
        return JsonRpcResponse(id=request.id, result={"version": version})

    elif request.method == "mitre/updateBundle":
        try:
            mitre_attack.update_bundle()
            return JsonRpcResponse(id=request.id, result={"status": "success", "message": "MITRE ATT&CK bundle updated."})
        except Exception as e:
            return JsonRpcResponse(
                id=request.id,
                error={"code": -32001, "message": "Failed to update bundle", "data": str(e)}
            )

    elif request.method == "mitre/getTechniqueDetail":
        # Validate params
        if not isinstance(request.params, dict) or "id_or_name" not in request.params or "detail" not in request.params:
            return JsonRpcResponse(
                id=request.id,
                error={"code": -32602, "message": "Invalid params: 'params' must be an object with 'id_or_name' and 'detail'."}
            )

        id_or_name = request.params["id_or_name"]
        detail = request.params["detail"]
        result = mitre_attack.get_technique_detail(id_or_name, detail)

        if "error" in result:
            # Detail not found, or technique not found
            return JsonRpcResponse(
                id=request.id,
                error={"code": -32002, "message": "Could not retrieve detail", "data": result["error"]}
            )
        else:
            # Detail found, return the result
            return JsonRpcResponse(
                id=request.id,
                result=result
            )
    else:
        # Method not found
        return JsonRpcResponse(
            id=request.id,
            error={"code": -32601, "message": f"Method not found: {request.method}"}
        )

@router.get("/mitre/technique/{id_or_name}")
async def mitre_technique_lookup(id_or_name: str):
    """
    Look up a MITRE ATT&CK technique by ID or name and return the technique object
    and all related objects per the STIX structure.
    """
    result = mitre_attack.lookup(id_or_name)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.post("/mitre/update_bundle")
async def mitre_update_bundle():
    """
    Force update (download) the latest MITRE ATT&CK bundle and reload in memory.
    """
    try:
        mitre_attack.update_bundle()
        return {"status": "success", "message": "MITRE ATT&CK bundle updated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ATT&CK bundle: {e}")
