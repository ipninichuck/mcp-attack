from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class Reference(BaseModel):
    source_name: str
    external_id: Optional[str] = None

class EntitySummary(BaseModel):
    id: str = Field(..., description="The ATT&CK ID (e.g., T1059)")
    name: str
    type: str
    description: str = Field(..., description="Truncated description")

class Technique(EntitySummary):
    platforms: List[str] = []
    tactics: List[str] = []

class Mitigation(BaseModel):
    id: str
    name: str
    description: Optional[str] = None

class Analytic(BaseModel):
    name: str
    source: str
    logic: str

class EntityFull(EntitySummary):
    """The 'Heavy' object returned only when detailed=True"""
    mitigations: List[Mitigation] = []
    analytics: List[Analytic] = []
    software: List[str] = []
    full_description: str

class ToolResponse(BaseModel):
    """Standard wrapper for all tool responses"""
    count: int
    data: List[Any]
    next_cursor: Optional[int] = None
