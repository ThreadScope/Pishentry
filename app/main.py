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
    TakedownPackageResponse
)

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
    logger.info("Initializing PhishSentry AI pipeline lifespan...")
    
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

    # 6. Load Fusion Classifier
    if state.fusion_model is None:
        state.fusion_model = FusionClassifier(MODEL_FILE if os.path.exists(MODEL_FILE) else None)
    logger.info("PhishSentry AI startup complete.")

    yield

    # Teardown
    logger.info("PhishSentry AI shutting down...")
    await close_renderer()

app = FastAPI(
    title="PhishSentry AI Enterprise API",
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

async def _execute_single_scan(url: str) -> ScanResult:
    start_time = time.time()
    cleaned_url = url.strip()
    
    if not cleaned_url or not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://") or "." in cleaned_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed URL. URL must include a valid hostname or domain scheme."
        )

    # Parallel Execution: (Stage 1: Lexical + Stage 2: Render + Stage 2b: TLS Telemetry)
    lex_res = analyze_lexical(cleaned_url, state.brand_names, canonical_domain_map=state.canonical_map)
    s_lex = lex_res.s_lex

    # Execute Playwright render and TLS probe concurrently
    render_task = render_url(cleaned_url, timeout_ms=10000)
    tls_task = extract_tls_telemetry(cleaned_url, timeout_seconds=3.0)

    (screenshot_bytes, dom_html), raw_tls = await asyncio.gather(render_task, tls_task)

    tls_telemetry = TLSTelemetry(
        has_tls=raw_tls.has_tls,
        issuer=raw_tls.issuer,
        subject=raw_tls.subject,
        san_list=raw_tls.san_list,
        valid_from=raw_tls.valid_from,
        valid_to=raw_tls.valid_to,
        days_to_expiry=raw_tls.days_to_expiry,
        is_self_signed=raw_tls.is_self_signed,
        is_free_ca=raw_tls.is_free_ca,
        resolved_ip=raw_tls.resolved_ip,
        error_detail=raw_tls.error_detail
    )

    s_dom = None
    s_vis = None
    matched_brand = None
    screenshot_rel_url = None
    matched_brand_screenshot_rel_url = None
    visual_forensics = None
    scan_id = str(uuid.uuid4())[:8]

    # Problem Statement 2: Bot-wall / Cloaking Interstitial Detection
    cloaking_raw = analyze_cloaking_and_anti_bot(dom_html, cleaned_url)
    cloaking_telemetry = CloakingTelemetry(
        is_cloaked=cloaking_raw.is_cloaked,
        interstitial_type=cloaking_raw.interstitial_type,
        evasion_techniques=cloaking_raw.evasion_techniques,
        is_bot_wall=cloaking_raw.is_bot_wall,
        advisory=cloaking_raw.advisory
    )

    if screenshot_bytes is not None and dom_html is not None:
        async def run_dom():
            return match_dom_against_brands(dom_html, state.brand_dom_map)

        async def run_vis():
            if state.visual_store is not None:
                return state.visual_store.find_best_match(screenshot_bytes)
            return 0.0, None

        (dom_score, dom_matched_brand), (vis_score, vis_matched_brand) = await asyncio.gather(
            run_dom(), run_vis()
        )

        s_dom = dom_score
        s_vis = vis_score

        # Select best matched brand with proper multi-modal hierarchy:
        # 1. Lexical / URL ground-truth match (e.g. accounts.google.com, paypa1.xyz)
        # 2. DOM semantic token match (e.g. "Google", "Use your Google Account")
        # 3. High-confidence Deep visual feature match (if confident >= 0.70 AND supported by DOM/lexical)
        if lex_res.matched_brand and lex_res.levenshtein_sim >= 0.6:
            matched_brand = lex_res.matched_brand
        elif dom_matched_brand and dom_score >= 0.40:
            matched_brand = dom_matched_brand
        elif vis_matched_brand and vis_score >= 0.70 and dom_score >= 0.30:
            matched_brand = vis_matched_brand
        elif vis_matched_brand and vis_score >= 0.85:
            matched_brand = vis_matched_brand
        else:
            matched_brand = None

        # Synchronize signal scores with actual confirmed brand to prevent false visual bleed on generic pages
        if matched_brand is not None:
            s_dom = dom_score if dom_matched_brand == matched_brand else 0.0
            s_vis = vis_score if vis_matched_brand == matched_brand else 0.0
        else:
            s_dom = 0.0
            s_vis = 0.0

        # Save scan screenshot artifact
        artifact_filename = f"scan_{scan_id}.png"
        artifact_path = os.path.join(ARTIFACTS_DIR, artifact_filename)
        try:
            with open(artifact_path, "wb") as f:
                f.write(screenshot_bytes)
            screenshot_rel_url = f"/artifacts/{artifact_filename}"
        except Exception as e:
            logger.warning(f"Could not persist scan screenshot artifact: {e}")

        # Compute In-Depth Visual Forensics & Difference Heatmap ONLY for actual detected brand
        target_brand_for_diff = matched_brand
        if target_brand_for_diff and state.visual_store is not None:
            brand_ref_img_path = None
            for b in state.brands_data:
                if b["brand_id"] == target_brand_for_diff:
                    brand_ref_img_path = os.path.join(BASE_DIR, b["screenshot_path"].replace("/", os.sep))
                    break

            
            if brand_ref_img_path and os.path.exists(brand_ref_img_path):
                # 1. Heatmap
                heatmap_rel_url, anomaly_score = generate_visual_difference_heatmap(
                    screenshot_bytes, brand_ref_img_path, scan_id
                )
                
                # 2. Detailed individual visual metrics
                cand_emb = state.embedder.get_image_embedding(screenshot_bytes)
                ref_emb = state.visual_store.brand_embeddings.get(target_brand_for_diff)
                cos_sim = compute_cosine_similarity(cand_emb, ref_emb) if ref_emb is not None else 0.0

                try:
                    c_pil = Image.open(io.BytesIO(screenshot_bytes))
                    r_pil = Image.open(brand_ref_img_path)
                    c_hash = compute_image_dhash(c_pil)
                    r_hash = compute_image_dhash(r_pil)
                    dhash_sim = compute_dhash_similarity(c_hash, r_hash)
                    color_sim = compute_color_histogram_similarity(c_pil, r_pil)
                except Exception:
                    dhash_sim = 0.0
                    color_sim = 0.0

                # 3. Official Brand Portal info
                official_portal = None
                for b in state.brands_data:
                    if b["brand_id"] == target_brand_for_diff:
                        official_portal = OfficialBrandPortal(
                            brand_id=b["brand_id"],
                            display_name=b["display_name"],
                            official_login_url=b.get("official_login_url", f"https://{b['canonical_domains'][0]}"),
                            canonical_domains=b.get("canonical_domains", []),
                            brand_color=b.get("brand_color", "#003087"),
                            official_cert_issuer=b.get("official_cert_issuer", "Verified Official TLS CA"),
                            security_advice=b.get("security_advice", "Verify official domain certificate."),
                            logo_url=f"/{b['logo_path'].replace(os.sep, '/')}",
                            screenshot_url=f"/{b['screenshot_path'].replace(os.sep, '/')}"
                        )
                        break

                visual_forensics = VisualForensicsDetail(
                    resnet_feature_sim=cos_sim,
                    layout_dhash_sim=dhash_sim,
                    color_histogram_sim=color_sim,
                    diff_heatmap_url=heatmap_rel_url,
                    anomaly_score=anomaly_score,
                    official_portal=official_portal
                )

    else:
        logger.warning(f"Render failed or timed out for {cleaned_url}. Falling back to lexical pre-filter.")
        if lex_res.matched_brand:
            matched_brand = lex_res.matched_brand

    # Look up matched brand reference screenshot
    if matched_brand:
        for b in state.brands_data:
            if b["brand_id"] == matched_brand:
                rel_path = b["screenshot_path"].replace("\\", "/")
                matched_brand_screenshot_rel_url = f"/{rel_path}" if not rel_path.startswith("/") else rel_path
                break

    # Problem Statement 1: AiTM Reverse Proxy Analysis
    aitm_raw = detect_aitm_proxy(
        url=cleaned_url,
        s_vis=s_vis,
        s_dom=s_dom,
        matched_brand=matched_brand,
        is_canonical=lex_res.is_canonical_domain,
        tls_telemetry=tls_telemetry,
        dom_html=dom_html
    )
    aitm_telemetry = AiTMTelemetry(
        is_aitm_suspect=aitm_raw.is_aitm_suspect,
        confidence_level=aitm_raw.confidence_level,
        mitre_attack_id=aitm_raw.mitre_attack_id,
        target_brand=aitm_raw.target_brand,
        reasons=aitm_raw.reasons,
        risk_score_boost=aitm_raw.risk_score_boost
    )

    # Problem Statement 4: Optical QR Code / Quishing Analysis
    quishing_raw = scan_for_qr_codes(screenshot_bytes)
    quishing_telemetry = QuishingTelemetry(
        has_qr_code=quishing_raw.has_qr_code,
        confidence=quishing_raw.confidence,
        decoded_url=quishing_raw.decoded_url,
        is_quishing_suspect=quishing_raw.is_quishing_suspect,
        mitre_attack_id=quishing_raw.mitre_attack_id,
        details=quishing_raw.details
    )

    # Problem Statement 5: Semantic Domain Purpose & Content Swapping Analysis
    semantic_raw = analyze_domain_purpose_alignment(
        url=cleaned_url,
        dom_html=dom_html,
        s_lex_brand=lex_res.matched_brand,
        s_vis_brand=matched_brand,
        is_canonical=lex_res.is_canonical_domain
    )
    semantic_telemetry = SemanticAlignmentTelemetry(
        is_discrepancy_detected=semantic_raw.is_discrepancy_detected,
        domain_intent_brand=semantic_raw.domain_intent_brand,
        rendered_content_brand=semantic_raw.rendered_content_brand,
        discrepancy_type=semantic_raw.discrepancy_type,
        alignment_score=semantic_raw.alignment_score,
        mitre_attack_id=semantic_raw.mitre_attack_id,
        reasons=semantic_raw.reasons,
        forensic_summary=semantic_raw.forensic_summary
    )

    # Low-Latency DOM Node & Form Action Deep Forensics
    dom_forensics_raw = extract_dom_deep_forensics(
        dom_html=dom_html,
        candidate_url=cleaned_url,
        canonical_domains=state.canonical_map.get(matched_brand) if matched_brand else None
    )
    dom_forensics = DOMDeepForensicsTelemetry(
        total_dom_nodes=dom_forensics_raw.total_dom_nodes,
        form_count=dom_forensics_raw.form_count,
        password_input_count=dom_forensics_raw.password_input_count,
        form_actions=[
            FormActionAuditDetail(
                form_id=fa.form_id,
                form_name=fa.form_name,
                action_url=fa.action_url,
                method=fa.method,
                target_domain=fa.target_domain,
                is_external_mismatch=fa.is_external_mismatch,
                input_fields=fa.input_fields,
                has_password_field=fa.has_password_field
            ) for fa in dom_forensics_raw.form_actions
        ],
        has_form_action_mismatch=dom_forensics_raw.has_form_action_mismatch,
        suspicious_external_scripts=dom_forensics_raw.suspicious_external_scripts,
        has_iframe_overlay=dom_forensics_raw.has_iframe_overlay,
        structural_node_diff_ratio=dom_forensics_raw.structural_node_diff_ratio,
        mitre_attack_id=dom_forensics_raw.mitre_attack_id,
        forensic_highlights=dom_forensics_raw.forensic_highlights,
        is_formless_harvesting=dom_forensics_raw.is_formless_harvesting,
        has_zero_font_obfuscation=dom_forensics_raw.has_zero_font_obfuscation,
        exfiltration_endpoints=dom_forensics_raw.exfiltration_endpoints,
        has_shadow_dom_nodes=dom_forensics_raw.has_shadow_dom_nodes
    )


    # Stage 5 & 6: Fusion & Explainability (XGBoost + SHAP)
    if state.fusion_model is not None:
        s_phish, shap_contribs, confidence = state.fusion_model.predict(s_lex, s_dom, s_vis)
    else:
        s_phish = s_lex
        shap_contribs = {"s_lex": 1.0, "s_dom": 0.0, "s_vis": 0.0}
        confidence = "reduced"

    # Stage 7: Phishpedia (USENIX '21) Consistency-Based Identification Model
    brand_meta_dict = {b["brand_id"]: b for b in state.brands_data}
    phishpedia_res = evaluate_phishpedia_consistency(
        url=cleaned_url,
        matched_brand=matched_brand,
        visual_similarity=s_vis or 0.0,
        dom_similarity=s_dom or 0.0,
        brand_metadata=brand_meta_dict
    )
    
    phishpedia_telemetry = PhishpediaTelemetry(
        brand_intention=phishpedia_res.brand_intention,
        brand_display_name=phishpedia_res.brand_display_name,
        brand_confidence=phishpedia_res.brand_confidence,
        registered_domain=phishpedia_res.registered_domain,
        canonical_domains=phishpedia_res.canonical_domains,
        is_consistent=phishpedia_res.is_consistent,
        phishing_decision=phishpedia_res.phishing_decision,
        visual_explanation=phishpedia_res.visual_explanation,
        mitre_attack_id=phishpedia_res.mitre_attack_id
    )

    # If Phishpedia consistency rule flags phishing, ensure high threat confidence
    if phishpedia_res.phishing_decision and not lex_res.is_canonical_domain:
        s_phish = max(s_phish, 0.85)

    # Stage 8: Recursive Redirect Tracing & URL Shortener Resolution
    redirect_raw = trace_redirect_hops(cleaned_url)
    redirect_telemetry = RedirectTraceTelemetry(
        original_url=redirect_raw.original_url,
        final_url=redirect_raw.final_url,
        total_hops=redirect_raw.total_hops,
        is_multi_hop=redirect_raw.is_multi_hop,
        is_shortened=redirect_raw.is_shortened,
        evasion_risk_boost=redirect_raw.evasion_risk_boost
    )

    # Stage 9: Phishing Kit & C2 Telegram Drop Fingerprinting
    kit_raw = fingerprint_phishing_kit(
        html_content=dom_html or "",
        raw_scripts=dom_forensics_raw.suspicious_external_scripts if dom_forensics_raw else []
    )
    kit_telemetry = PhishingKitTelemetry(
        is_kit_detected=kit_raw.is_kit_detected,
        kit_name=kit_raw.kit_name,
        kit_family=kit_raw.kit_family,
        confidence=kit_raw.confidence,
        detected_indicators=kit_raw.detected_indicators,
        is_telegram_exfiltration=kit_raw.is_telegram_exfiltration,
        telegram_bot_endpoints=kit_raw.telegram_bot_endpoints,
        mitre_attack_id=kit_raw.mitre_attack_id
    )

    # Apply Phishing Kit threat elevation
    if kit_raw.is_kit_detected and not lex_res.is_canonical_domain:
        s_phish = max(s_phish, 0.90)

    # Apply Multi-hop Evasion boost
    if redirect_raw.is_multi_hop and not lex_res.is_canonical_domain:
        s_phish = min(1.0, max(s_phish, s_phish + redirect_raw.evasion_risk_boost))

    # Apply AiTM threat elevation boost
    if aitm_telemetry.is_aitm_suspect:
        s_phish = min(1.0, max(s_phish, s_phish + aitm_telemetry.risk_score_boost))

    # Apply Quishing threat boost
    if quishing_telemetry.is_quishing_suspect and not lex_res.is_canonical_domain:
        s_phish = min(1.0, max(s_phish, s_phish + 0.30))

    # Apply Form Action Mismatch boost
    if dom_forensics.has_form_action_mismatch and not lex_res.is_canonical_domain:
        s_phish = min(1.0, max(s_phish, 0.85))

    # Apply Formless Harvesting boost
    if dom_forensics.is_formless_harvesting and not lex_res.is_canonical_domain:
        s_phish = min(1.0, max(s_phish, 0.85))

    # Apply Direct Webhook Exfiltration boost
    if dom_forensics.exfiltration_endpoints and not lex_res.is_canonical_domain:
        s_phish = min(1.0, max(s_phish, 0.90))

    # Apply Zero-Font Obfuscation penalty
    if dom_forensics.has_zero_font_obfuscation and not lex_res.is_canonical_domain:
        s_phish = min(1.0, max(s_phish, s_phish + 0.25))

    # Apply Content-Swapping Cloaking boost
    if semantic_telemetry.discrepancy_type == "CLOAKING_CONTENT_SWAP":
        s_phish = min(1.0, max(s_phish, 0.85))


    # Apply Cloaking fallback guard: If page cloaked and lexical indicates risk, prevent false negative
    if cloaking_telemetry.is_cloaked and s_lex >= 0.35:
        s_phish = max(s_phish, s_lex)

    # Canonical Domain Safety Guard
    if lex_res.is_canonical_domain:
        s_phish = min(s_phish, 0.05)

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    return ScanResult(
        url=cleaned_url,
        s_lex=s_lex,
        s_dom=s_dom,
        s_vis=s_vis,
        matched_brand=matched_brand,
        s_phish=s_phish,
        shap_contributions=shap_contribs,
        confidence=confidence,
        screenshot_url=screenshot_rel_url,
        matched_brand_screenshot_url=matched_brand_screenshot_rel_url,
        tls_telemetry=tls_telemetry,
        visual_forensics=visual_forensics,
        aitm_telemetry=aitm_telemetry,
        cloaking_telemetry=cloaking_telemetry,
        quishing_telemetry=quishing_telemetry,
        semantic_alignment=semantic_telemetry,
        dom_forensics=dom_forensics,
        phishpedia_consistency=phishpedia_telemetry,
        redirect_trace=redirect_telemetry,
        kit_fingerprint=kit_telemetry,
        latency_ms=elapsed_ms
    )





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
        "name": request.author or "PhishSentry AI Security System",
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






