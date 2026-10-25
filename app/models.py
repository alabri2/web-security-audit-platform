from pydantic import BaseModel
from typing import Optional, List, Literal, Dict, Any

class ScanRequest(BaseModel):
    url: str
    mode: Literal["normal", "advanced"] = "normal"
    target_mode: Literal["auto", "manual"] = "auto"
    target_type: Optional[Literal["generic", "api", "wordpress"]] = None
    authorized: bool = False

class ScanResponse(BaseModel):
    scan_id: str
    status: str

class FindingOut(BaseModel):
    id: int
    asset: Optional[str] = None
    tool: str
    severity: str
    title: str
    description: str

class ScanDetails(BaseModel):
    id: str
    target: str
    mode: str
    status: str
    score: Optional[int] = None
    security_level: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    findings: List[FindingOut] = []
    extra: Dict[str, Any] = {}
