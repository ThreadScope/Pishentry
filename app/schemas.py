from typing import Dict, List, Optional
from pydantic import BaseModel, HttpUrl

class ScanRequest(BaseModel):
    url: str

class ScanResult(BaseModel):
    url: str
    s_lex: float
    s_dom: Optional[float] = None
    s_vis: Optional[float] = None
    matched_brand: Optional[str] = None
    s_phish: float
    shap_contributions: Dict[str, float]
    confidence: str  # "full" or "reduced"
    screenshot_url: Optional[str] = None
    matched_brand_screenshot_url: Optional[str] = None
    latency_ms: float

class BrandInfo(BaseModel):
    brand_id: str
    display_name: str
    canonical_domains: List[str]
    screenshot_path: str
    logo_path: str
    dom_snapshot_path: str
    embedding_cache_id: str

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    brands_loaded: int
