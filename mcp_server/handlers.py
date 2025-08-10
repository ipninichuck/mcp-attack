from fastapi import APIRouter, HTTPException
from mcp_server.mitre_attack import mitre_attack

router = APIRouter()

# ... your existing endpoints ...

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
