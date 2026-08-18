from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
  url: str

class TLSTelemetry(BaseModel):
  has_tls: bool
  issuer: Optional[str] = None
  subject: Optional[str] = None
  san_list: List[str] = []
  valid_from: Optional[str] = None
  valid_to: Optional[str] = None
  days_to_expiry: Optional[int] = None
  is_self_signed: bool = False
  is_free_ca: bool = False
  resolved_ip: Optional[str] = None
  error_detail: Optional[str] = None

class OfficialBrandPortal(BaseModel):
  brand_id: str
  display_name: str
  official_login_url: str
  canonical_domains: List[str]
  brand_color: str
  official_cert_issuer: str
  security_advice: str
  logo_url: str
  screenshot_url: str

class VisualForensicsDetail(BaseModel):
  resnet_feature_sim: float = 0.0
  layout_dhash_sim: float = 0.0
  color_histogram_sim: float = 0.0
  diff_heatmap_url: Optional[str] = None
  anomaly_score: float = 0.0
  official_portal: Optional[OfficialBrandPortal] = None

class AiTMTelemetry(BaseModel):
  is_aitm_suspect: bool = False
  confidence_level: str = "NONE"
  mitre_attack_id: str = "N/A"
  target_brand: Optional[str] = None
  reasons: List[str] = []
  risk_score_boost: float = 0.0

class CloakingTelemetry(BaseModel):
  is_cloaked: bool = False
  interstitial_type: Optional[str] = None
  evasion_techniques: List[str] = []
  is_bot_wall: bool = False
  advisory: Optional[str] = None

class QuishingTelemetry(BaseModel):
  has_qr_code: bool = False
  confidence: float = 0.0
  decoded_url: Optional[str] = None
  is_quishing_suspect: bool = False
  mitre_attack_id: str = "N/A"
  details: List[str] = []

class CustomBrandRegistrationRequest(BaseModel):
  brand_id: str
  display_name: str
  canonical_domains: List[str]
  official_login_url: Optional[str] = None
  brand_color: Optional[str] = "#0284c7"
  official_cert_issuer: Optional[str] = "DigiCert / Corporate CA"
  security_advice: Optional[str] = "Verify official corporate domain."

class RuleExportRequest(BaseModel):
  scan_result: Dict[str, Any]

class SigmaRuleResponse(BaseModel):
  sigma_yaml: str

class YARARuleResponse(BaseModel):
  yara_rule: str

class SemanticAlignmentTelemetry(BaseModel):
  is_discrepancy_detected: bool = False
  domain_intent_brand: Optional[str] = None
  rendered_content_brand: Optional[str] = None
  discrepancy_type: str = "MATCH"
  alignment_score: float = 1.0
  mitre_attack_id: str = "N/A"
  reasons: List[str] = []
  forensic_summary: str = "Aligned"

class FormActionAuditDetail(BaseModel):
  form_id: Optional[str] = None
  form_name: Optional[str] = None
  action_url: str
  method: str
  target_domain: str
  is_external_mismatch: bool = False
  input_fields: List[str] = []
  has_password_field: bool = False

class DOMDeepForensicsTelemetry(BaseModel):
  total_dom_nodes: int = 0
  form_count: int = 0
  password_input_count: int = 0
  form_actions: List[FormActionAuditDetail] = []
  has_form_action_mismatch: bool = False
  suspicious_external_scripts: List[str] = []
  has_iframe_overlay: bool = False
  structural_node_diff_ratio: float = 1.0
  mitre_attack_id: str = "N/A"
  forensic_highlights: List[str] = []
  is_formless_harvesting: bool = False
  has_zero_font_obfuscation: bool = False
  exfiltration_endpoints: List[str] = []
  has_shadow_dom_nodes: bool = False


class PhishpediaTelemetry(BaseModel):
  brand_intention: Optional[str] = None
  brand_display_name: Optional[str] = None
  brand_confidence: float = 0.0
  registered_domain: str
  canonical_domains: List[str] = []
  is_consistent: bool = True
  phishing_decision: bool = False
  visual_explanation: str
  mitre_attack_id: str = "T1566.002"

class CertStreamEventSchema(BaseModel):
  domain: str
  san_list: List[str] = []
  issuer: str
  timestamp: float
  matched_target_brand: Optional[str] = None
  risk_level: str = "HIGH"
  is_zero_day: bool = True
  heuristic_triggers: List[str] = []

class RedirectTraceTelemetry(BaseModel):
  original_url: str
  final_url: str
  total_hops: int = 1
  is_multi_hop: bool = False
  is_shortened: bool = False
  evasion_risk_boost: float = 0.0

class PhishingKitTelemetry(BaseModel):
  is_kit_detected: bool = False
  kit_name: Optional[str] = None
  kit_family: Optional[str] = None
  confidence: float = 0.0
  detected_indicators: List[str] = []
  is_telegram_exfiltration: bool = False
  telegram_bot_endpoints: List[str] = []
  mitre_attack_id: str = "T1020"

class TakedownPackageResponse(BaseModel):
  target_url: str
  target_domain: str
  registrar_abuse_email: str
  hosting_abuse_email: str
  subject_line: str
  body_text: str
  rfc2142_notice: str
  evidence_summary: Dict[str, Any]

class ScanResult(BaseModel):
  url: str
  s_lex: float
  s_dom: Optional[float] = None
  s_vis: Optional[float] = None
  matched_brand: Optional[str] = None
  s_phish: float
  shap_contributions: Dict[str, float]
  confidence: str # "full" or "reduced"
  screenshot_url: Optional[str] = None
  matched_brand_screenshot_url: Optional[str] = None
  tls_telemetry: Optional[TLSTelemetry] = None
  visual_forensics: Optional[VisualForensicsDetail] = None
  aitm_telemetry: Optional[AiTMTelemetry] = None
  cloaking_telemetry: Optional[CloakingTelemetry] = None
  quishing_telemetry: Optional[QuishingTelemetry] = None
  semantic_alignment: Optional[SemanticAlignmentTelemetry] = None
  dom_forensics: Optional[DOMDeepForensicsTelemetry] = None
  phishpedia_consistency: Optional[PhishpediaTelemetry] = None
  redirect_trace: Optional[RedirectTraceTelemetry] = None
  kit_fingerprint: Optional[PhishingKitTelemetry] = None
  latency_ms: float






class WebhookAlertRequest(BaseModel):
  webhook_url: str
  scan_result: ScanResult
  custom_title: Optional[str] = " PhishSentry Critical SOC Alert"

class WebhookAlertResponse(BaseModel):
  success: bool
  message: str


class BatchScanRequest(BaseModel):
  urls: List[str] = Field(..., min_length=1, max_length=100)
  max_concurrency: int = Field(default=5, ge=1, le=10)

class BatchScanResult(BaseModel):
  total_requested: int
  scanned_count: int
  phishing_count: int
  suspicious_count: int
  safe_count: int
  results: List[ScanResult]
  total_latency_ms: float

class BrandInfo(BaseModel):
  brand_id: str
  display_name: str
  official_login_url: Optional[str] = None
  canonical_domains: List[str]
  brand_color: Optional[str] = "#0284c7"
  official_cert_issuer: Optional[str] = None
  security_advice: Optional[str] = None
  screenshot_path: str
  logo_path: str
  dom_snapshot_path: str
  embedding_cache_id: str

class HealthResponse(BaseModel):
  status: str
  model_loaded: bool
  brands_loaded: int

class STIXExportRequest(BaseModel):
  scan_results: List[ScanResult]
  author: Optional[str] = "PhishSentry AI SOC"


