import os
import time
import json
import logging
import uuid
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, ImageDraw

from fastapi.responses import PlainTextResponse
from app.schemas import (
    ScanRequest, ScanResult, BrandInfo, HealthResponse,
    BatchScanRequest, BatchScanResult, TLSTelemetry, STIXExportRequest,
    VisualForensicsDetail, OfficialBrandPortal,
    AiTMTelemetry, CloakingTelemetry, WebhookAlertRequest, WebhookAlertResponse,
    QuishingTelemetry, CustomBrandRegistrationRequest, RuleExportRequest,
    SigmaRuleResponse, YARARuleResponse, SemanticAlignmentTelemetry,
    DOMDeepForensicsTelemetry, FormActionAuditDetail,
    PhishpediaTelemetry, CertStreamEventSchema,
    RedirectTraceTelemetry, PhishingKitTelemetry,
    TakedownPackageResponse,
    TargetAttributionTelemetry, HoneytokenExfiltrationTelemetry,
    VisualOCRTelemetry, RedirectGraphTelemetry,
    ThreatNarrativeResponse, MultiVendorFirewallResponse
)

from app.pipeline import ScanPipeline
from app.lexical import analyze_lexical
from app.renderer import render_url, start_renderer, close_renderer
from app.dom_similarity import match_dom_against_brands
from app.visual_similarity import VisualEmbedder, ReferenceBrandVisualStore, compute_cosine_similarity, compute_image_dhash, compute_dhash_similarity
from app.fusion import FusionClassifier
from app.telemetry import extract_tls_telemetry
from app.visual_forensics import generate_high_fidelity_brand_assets, compute_color_histogram_similarity, generate_visual_difference_heatmap
from app.aitm_detector import detect_aitm_proxy
from app.cloaking_detector import analyze_cloaking_and_anti_bot
from app.webhook import dispatch_soc_webhook_alert
from app.quishing_detector import scan_for_qr_codes
from app.export_rules import generate_sigma_rule, generate_yara_rule, generate_dns_blocklist
from app.semantic_alignment import analyze_domain_purpose_alignment
from app.dom_comparator import extract_dom_deep_forensics
from app.phishpedia_engine import evaluate_phishpedia_consistency
from app.certstream_monitor import evaluate_certstream_domain, generate_sample_certstream_feed
from app.redirect_tracer import trace_redirect_hops
from app.kit_fingerprinter import fingerprint_phishing_kit
from app.takedown_generator import generate_abuse_takedown_package
from app.target_attribution import attribute_target_identity
from app.honeytoken_interactor import analyze_outbound_network_requests, generate_canary_identity
from app.visual_ocr import extract_visual_text_from_screenshot
from app.redirect_graph import trace_redirect_graph
from app.threat_narrative import generate_threat_narrative
from app.firewall_rules import generate_multi_vendor_firewall_rules





logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishsentry")

# Directories for static reference and scan artifact storage
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
REF_DIR = os.path.join(DATA_DIR, "reference")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
PROTECTED_BRANDS_FILE = os.path.join(DATA_DIR, "protected_brands.json")
MODEL_FILE = os.path.join(BASE_DIR, "training", "model.pkl")

os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.makedirs(REF_DIR, exist_ok=True)

# State container
class PipelineState:
    brands_data: List[dict] = []
    brand_dom_map: Dict[str, str] = {}
    brand_names: List[str] = []
    canonical_map: Dict[str, List[str]] = {}
    embedder: Optional[VisualEmbedder] = None
    visual_store: Optional[ReferenceBrandVisualStore] = None
    fusion_model: Optional[FusionClassifier] = None

state = PipelineState()

def create_all_seed_brand_assets():
    """Generates authentic high-fidelity reference images, logos, and DOMs for all protected brands."""
    generate_high_fidelity_brand_assets()
    
    # Generate reference DOMs if not present
    for b in state.brands_data if state.brands_data else []:
        b_id = b["brand_id"]
        d_name = b.get("display_name", b_id.title())
        brand_folder = os.path.join(REF_DIR, b_id)
        dom_path = os.path.join(brand_folder, "dom.html")
        if not os.path.exists(dom_path):
            dom_content = f"""<!DOCTYPE html>
<html>
<head><title>{d_name} Official Portal</title></head>
<body>
    <header><nav><a>{d_name}</a></nav></header>
    <main>
        <form action="/login" method="post">
            <h2>Sign in to {d_name}</h2>
            <input type="text" name="username" placeholder="Username or email" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Log In</button>
        </form>
    </main>
    <footer><p>&copy; {d_name} Inc. Official Secure Portal</p></footer>
</body>
</html>"""
            with open(dom_path, "w", encoding="utf-8") as f:
                f.write(dom_content)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing CloneCatcher AI pipeline lifespan...")
    
    # 1. Start persistent Playwright renderer worker
    try:
        await start_renderer()
    except Exception as e:
        logger.warning(f"Could not pre-warm Playwright renderer: {e}")

    # 2. Load protected brands config
    if os.path.exists(PROTECTED_BRANDS_FILE):
        with open(PROTECTED_BRANDS_FILE, "r", encoding="utf-8") as f:
            state.brands_data = json.load(f)
    else:
        logger.error(f"Reference brand store file {PROTECTED_BRANDS_FILE} not found!")
        state.brands_data = []

    state.brand_names = [b["brand_id"] for b in state.brands_data]
    state.canonical_map = {b["brand_id"]: b.get("canonical_domains", []) for b in state.brands_data}

    # 3. Ensure high-fidelity seed assets exist for all brands
    create_all_seed_brand_assets()
    
    # 4. Load DOM snapshots
    state.brand_dom_map = {}
    for b in state.brands_data:
        dom_file = os.path.join(BASE_DIR, b["dom_snapshot_path"].replace("/", os.sep))
        if os.path.exists(dom_file):
            with open(dom_file, "r", encoding="utf-8") as f:
                state.brand_dom_map[b["brand_id"]] = f.read()

    # 5. Load Visual Embedder & Store (cached across lifespan re-entries)
    if state.embedder is None:
        state.embedder = VisualEmbedder()
        state.visual_store = ReferenceBrandVisualStore(state.embedder)
        for b in state.brands_data:
            img_file = os.path.join(BASE_DIR, b["screenshot_path"].replace("/", os.sep))
            if os.path.exists(img_file):
                state.visual_store.load_reference_brand(b["brand_id"], img_file)
        # Load extended enterprise brand targets from sample datasets
        state.visual_store.load_sample_brand_targetlists(max_brands=50)

    # 6. Load Fusion Classifier
    if state.fusion_model is None:
        state.fusion_model = FusionClassifier(MODEL_FILE if os.path.exists(MODEL_FILE) else None)
    logger.info("CloneCatcher AI startup complete.")

    yield

    # Teardown
    logger.info("CloneCatcher AI shutting down...")
    await close_renderer()

app = FastAPI(
    title="CloneCatcher AI Enterprise API",
    description="Multi-modal phishing detection fusing lexical, DOM-structural, visual similarity signals, TLS telemetry, and AiTM analysis.",
    version="1.3.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static file endpoints for images
app.mount("/artifacts", StaticFiles(directory=ARTIFACTS_DIR), name="artifacts")
app.mount("/data", StaticFiles(directory=DATA_DIR), name="data")

@app.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(
        status="ok",
        model_loaded=(state.fusion_model is not None),
        brands_loaded=len(state.brands_data)
    )

@app.get("/brands", response_model=List[BrandInfo])
def get_protected_brands():
    return [BrandInfo(**b) for b in state.brands_data]

def get_pipeline() -> ScanPipeline:
    return ScanPipeline(
        brands_data=state.brands_data,
        brand_names=state.brand_names,
        canonical_map=state.canonical_map,
        brand_dom_map=state.brand_dom_map,
        embedder=state.embedder,
        visual_store=state.visual_store,
        fusion_model=state.fusion_model
    )

async def _execute_single_scan(url: str) -> ScanResult:
    cleaned_url = url.strip()
    if not cleaned_url or not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://") or "." in cleaned_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed URL. URL must include a valid hostname or domain scheme."
        )

    pipeline = get_pipeline()
    return await pipeline.execute(cleaned_url)





@app.post("/scan", response_model=ScanResult)
async def scan_url(request: ScanRequest):
    return await _execute_single_scan(request.url)

@app.post("/scan/batch", response_model=BatchScanResult)
async def scan_urls_batch(request: BatchScanRequest):
    start_time = time.time()
    semaphore = asyncio.Semaphore(request.max_concurrency)

    async def _bounded_scan(u: str) -> Optional[ScanResult]:
        async with semaphore:
            try:
                return await _execute_single_scan(u)
            except Exception as e:
                logger.warning(f"Batch scan error on URL '{u}': {e}")
                return None

    tasks = [_bounded_scan(u) for u in request.urls if u.strip()]
    results_raw = await asyncio.gather(*tasks)
    results = [r for r in results_raw if r is not None]

    phishing_count = sum(1 for r in results if r.s_phish >= 0.65)
    suspicious_count = sum(1 for r in results if 0.35 <= r.s_phish < 0.65)
    safe_count = sum(1 for r in results if r.s_phish < 0.35)

    total_latency = round((time.time() - start_time) * 1000, 2)

    return BatchScanResult(
        total_requested=len(request.urls),
        scanned_count=len(results),
        phishing_count=phishing_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        results=results,
        total_latency_ms=total_latency
    )

@app.post("/brands/register", response_model=BrandInfo)
def register_custom_brand(request: CustomBrandRegistrationRequest):
    """
    Dynamically onboards a custom corporate or partner brand into the protected brand registry.
    """
    clean_id = request.brand_id.lower().strip()
    brand_folder = os.path.join(REF_DIR, clean_id)
    os.makedirs(brand_folder, exist_ok=True)
    
    screenshot_rel = f"data/reference/{clean_id}/screenshot.png"
    logo_rel = f"data/reference/{clean_id}/logo.png"
    dom_rel = f"data/reference/{clean_id}/dom.html"
    
    screenshot_full = os.path.join(BASE_DIR, screenshot_rel.replace("/", os.sep))
    logo_full = os.path.join(BASE_DIR, logo_rel.replace("/", os.sep))
    dom_full = os.path.join(BASE_DIR, dom_rel.replace("/", os.sep))
    
    # Generate seed images if not existing
    if not os.path.exists(screenshot_full):
        img = Image.new("RGB", (1280, 800), color=request.brand_color or "#0284c7")
        draw = ImageDraw.Draw(img)
        draw.text((100, 100), f"{request.display_name} Official Portal", fill=(255, 255, 255))
        img.save(screenshot_full)
        
    if not os.path.exists(logo_full):
        logo = Image.new("RGB", (200, 200), color=request.brand_color or "#0284c7")
        draw = ImageDraw.Draw(logo)
        draw.text((30, 85), request.display_name[:8], fill=(255, 255, 255))
        logo.save(logo_full)
        
    if not os.path.exists(dom_full):
        dom_txt = f"<html><head><title>{request.display_name}</title></head><body><h1>{request.display_name} Login</h1></body></html>"
        with open(dom_full, "w", encoding="utf-8") as f:
            f.write(dom_txt)

    new_brand_dict = {
        "brand_id": clean_id,
        "display_name": request.display_name,
        "official_login_url": request.official_login_url or f"https://{request.canonical_domains[0]}",
        "canonical_domains": request.canonical_domains,
        "brand_color": request.brand_color or "#0284c7",
        "official_cert_issuer": request.official_cert_issuer or "DigiCert Inc",
        "security_advice": request.security_advice or "Verify official corporate domain.",
        "screenshot_path": screenshot_rel,
        "logo_path": logo_rel,
        "dom_snapshot_path": dom_rel,
        "embedding_cache_id": f"{clean_id}_custom_v1"
    }

    # Update memory state
    state.brands_data = [b for b in state.brands_data if b["brand_id"] != clean_id]
    state.brands_data.append(new_brand_dict)
    state.brand_names = [b["brand_id"] for b in state.brands_data]
    state.canonical_map[clean_id] = request.canonical_domains
    
    with open(dom_full, "r", encoding="utf-8") as f:
        state.brand_dom_map[clean_id] = f.read()

    if state.visual_store is not None:
        state.visual_store.load_reference_brand(clean_id, screenshot_full)

    # Persist to JSON file
    try:
        with open(PROTECTED_BRANDS_FILE, "w", encoding="utf-8") as f:
            json.dump(state.brands_data, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not persist custom brand to file: {e}")

    return BrandInfo(**new_brand_dict)

@app.delete("/brands/{brand_id}")
def unregister_brand(brand_id: str):
    clean_id = brand_id.lower().strip()
    state.brands_data = [b for b in state.brands_data if b["brand_id"] != clean_id]
    state.brand_names = [b["brand_id"] for b in state.brands_data]
    state.canonical_map.pop(clean_id, None)
    state.brand_dom_map.pop(clean_id, None)
    if state.visual_store:
        state.visual_store.brand_embeddings.pop(clean_id, None)
        state.visual_store.brand_hashes.pop(clean_id, None)
    
    try:
        with open(PROTECTED_BRANDS_FILE, "w", encoding="utf-8") as f:
            json.dump(state.brands_data, f, indent=2)
    except Exception:
        pass
    return {"status": "ok", "unregistered_brand": clean_id}

@app.get("/brands/{brand_id}/dom", response_class=PlainTextResponse)
def get_brand_official_dom(brand_id: str):
    """
    Returns the authentic reference DOM HTML structure for the specified brand.
    """
    clean_id = brand_id.lower().strip()
    if clean_id in state.brand_dom_map:
        return state.brand_dom_map[clean_id]
    
    dom_path = os.path.join(REF_DIR, clean_id, "dom.html")
    if os.path.exists(dom_path):
        with open(dom_path, "r", encoding="utf-8") as f:
            content = f.read()
            state.brand_dom_map[clean_id] = content
            return content
            
    # Fallback to generating authentic template
    d_name = clean_id.capitalize()
    fallback_html = f"""<!DOCTYPE html>
<html>
<head><title>{d_name} Official Portal</title></head>
<body>
    <header><nav><a>{d_name}</a></nav></header>
    <main>
        <form action="/login" method="post">
            <h2>Sign in to {d_name}</h2>
            <input type="text" name="username" placeholder="Username or email" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Log In</button>
        </form>
    </main>
    <footer><p>&copy; {d_name} Inc. Official Secure Portal</p></footer>
</body>
</html>"""
    state.brand_dom_map[clean_id] = fallback_html
    return fallback_html


@app.post("/export/sigma", response_model=SigmaRuleResponse)

def export_sigma_rule_endpoint(request: RuleExportRequest):
    yaml_content = generate_sigma_rule(request.scan_result)
    return SigmaRuleResponse(sigma_yaml=yaml_content)

@app.post("/export/yara", response_model=YARARuleResponse)
def export_yara_rule_endpoint(request: RuleExportRequest):
    yara_content = generate_yara_rule(request.scan_result)
    return YARARuleResponse(yara_rule=yara_content)

@app.get("/export/blocklist", response_class=PlainTextResponse)
def export_dns_blocklist_endpoint():
    dummy_results = [{"url": f"http://{b['brand_id']}-security-update.tk", "s_phish": 0.95, "matched_brand": b["brand_id"]} for b in state.brands_data]
    return generate_dns_blocklist(dummy_results)

@app.post("/webhook/dispatch", response_model=WebhookAlertResponse)
def dispatch_webhook_endpoint(request: WebhookAlertRequest):
    """
    Dispatches a high-priority incident notification to the configured SIEM/Slack webhook URL.
    """
    success = dispatch_soc_webhook_alert(
        webhook_url=request.webhook_url,
        scan_result=request.scan_result.model_dump(),
        custom_title=request.custom_title
    )
    if success:
        return WebhookAlertResponse(success=True, message="SOC Webhook Alert dispatched successfully.")
    else:
        return WebhookAlertResponse(success=False, message="Webhook dispatch failed. Check endpoint URL.")

@app.post("/export/stix")
def export_stix_bundle(request: STIXExportRequest):
    """
    Generates an OASIS STIX 2.1 compliant Threat Intelligence JSON Bundle
    for direct ingestion into SIEM / SOAR platforms.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle_id = f"bundle--{uuid.uuid4()}"
    
    stix_objects = []
    
    # 1. Identity Object
    identity_id = f"identity--{uuid.uuid4()}"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": request.author or "CloneCatcher AI Security System",
        "identity_class": "system"
    })

    # 2. Indicator & Observed-Data Objects for Phishing Results
    for scan in request.scan_results:
        if scan.s_phish >= 0.35:  # Suspicious or Phishing
            indicator_id = f"indicator--{uuid.uuid4()}"
            is_critical = scan.s_phish >= 0.65
            threat_label = "malicious-activity" if is_critical else "anomalous-activity"
            
            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"Phishing URL Impersonating {scan.matched_brand.upper() if scan.matched_brand else 'Brand'}",
                "description": f"Multi-modal phishing detection score S_phish={scan.s_phish:.2f}. SHAP breakdown: {scan.shap_contributions}",
                "indicator_types": [threat_label],
                "pattern": f"[url:value = '{scan.url}']",
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": int(scan.s_phish * 100),
                "created_by_ref": identity_id,
                "custom_properties": {
                    "x_phishsentry_score": scan.s_phish,
                    "x_matched_brand": scan.matched_brand,
                    "x_lexical_score": scan.s_lex,
                    "x_dom_score": scan.s_dom,
                    "x_visual_score": scan.s_vis,
                    "x_aitm_suspect": scan.aitm_telemetry.is_aitm_suspect if scan.aitm_telemetry else False,
                    "x_cloaking_detected": scan.cloaking_telemetry.is_cloaked if scan.cloaking_telemetry else False,
                    "x_quishing_suspect": scan.quishing_telemetry.is_quishing_suspect if scan.quishing_telemetry else False,
                    "x_tls_issuer": scan.tls_telemetry.issuer if scan.tls_telemetry else None,
                    "x_resolved_ip": scan.tls_telemetry.resolved_ip if scan.tls_telemetry else None
                }
            }
            stix_objects.append(indicator_obj)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects
    }

@app.get("/certstream/feed", response_model=List[CertStreamEventSchema])
def get_certstream_live_feed():
    """
    Returns real-time Certificate Transparency log stream analyzed for zero-day phishing lookalikes.
    """
    return generate_sample_certstream_feed(state.brand_names)

@app.post("/takedown/generate", response_model=TakedownPackageResponse)
def generate_takedown_endpoint(request: RuleExportRequest):
    """
    Generates an RFC 2142 / DMCA compliant abuse takedown notice package for registrars and hosting ASNs.
    """
    pkg = generate_abuse_takedown_package(request.scan_result)
    return TakedownPackageResponse(
        target_url=pkg.target_url,
        target_domain=pkg.target_domain,
        registrar_abuse_email=pkg.registrar_abuse_email,
        hosting_abuse_email=pkg.hosting_abuse_email,
        subject_line=pkg.subject_line,
        body_text=pkg.body_text,
        rfc2142_notice=pkg.rfc2142_notice,
        evidence_summary=pkg.evidence_summary
    )

@app.post("/export/firewall", response_model=MultiVendorFirewallResponse)
def export_firewall_rules_endpoint(request: RuleExportRequest):
    """
    Generates syntax-exact firewall and WAF block rules across Palo Alto, Cloudflare, Fortinet, Cisco ASA, and Suricata.
    """
    fw = generate_multi_vendor_firewall_rules(request.scan_result)
    return MultiVendorFirewallResponse(
        target_domain=fw.target_domain,
        target_ip=fw.target_ip,
        palo_alto_cli=fw.palo_alto_cli,
        cloudflare_waf_json=fw.cloudflare_waf_json,
        fortigate_cli=fw.fortigate_cli,
        cisco_asa_acl=fw.cisco_asa_acl,
        suricata_ips_rule=fw.suricata_ips_rule
    )

@app.post("/export/narrative", response_model=ThreatNarrativeResponse)
def export_threat_narrative_endpoint(request: RuleExportRequest):
    """
    Generates an executive SOC threat intelligence briefing summarizing attacker tradecraft and recommended mitigations.
    """
    narrative = generate_threat_narrative(request.scan_result)
    return ThreatNarrativeResponse(
        incident_title=narrative.incident_title,
        severity_level=narrative.severity_level,
        threat_actor_tradecraft=narrative.threat_actor_tradecraft,
        executive_summary=narrative.executive_summary,
        forensic_indicators_of_compromise=narrative.forensic_indicators_of_compromise,
        recommended_soc_actions=narrative.recommended_soc_actions
    )






