import os
import time
import json
import logging
import uuid
import asyncio
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, ImageDraw, ImageFont

from app.schemas import ScanRequest, ScanResult, BrandInfo, HealthResponse
from app.lexical import analyze_lexical
from app.renderer import render_url
from app.dom_similarity import match_dom_against_brands
from app.visual_similarity import VisualEmbedder, ReferenceBrandVisualStore
from app.fusion import FusionClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishsentry")

app = FastAPI(
    title="PhishSentry AI MVP API",
    description="Multi-modal phishing detection fusing lexical, DOM-structural, and visual similarity signals.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directories for static reference and scan artifact storage
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
REF_DIR = os.path.join(DATA_DIR, "reference")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
PROTECTED_BRANDS_FILE = os.path.join(DATA_DIR, "protected_brands.json")
MODEL_FILE = os.path.join(BASE_DIR, "training", "model.pkl")

os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.makedirs(REF_DIR, exist_ok=True)

# Mount static file endpoints for images
app.mount("/artifacts", StaticFiles(directory=ARTIFACTS_DIR), name="artifacts")
app.mount("/data", StaticFiles(directory=DATA_DIR), name="data")

# Global state instances
brands_data: List[dict] = []
brand_dom_map: dict = {}
brand_names: List[str] = []
embedder: Optional[VisualEmbedder] = None
visual_store: Optional[ReferenceBrandVisualStore] = None
fusion_model: Optional[FusionClassifier] = None

def create_seed_brand_assets():
    """Ensures reference images and DOM snapshots exist for seed brands."""
    brands = [
        ("paypal", "PayPal", "#003087", ["paypal.com", "www.paypal.com"]),
        ("google", "Google", "#4285F4", ["google.com", "accounts.google.com"]),
        ("github", "GitHub", "#24292e", ["github.com"])
    ]
    
    for brand_id, display_name, color, domains in brands:
        brand_folder = os.path.join(REF_DIR, brand_id)
        os.makedirs(brand_folder, exist_ok=True)
        
        screenshot_path = os.path.join(brand_folder, "screenshot.png")
        logo_path = os.path.join(brand_folder, "logo.png")
        dom_path = os.path.join(brand_folder, "dom.html")
        
        if not os.path.exists(screenshot_path):
            img = Image.new("RGB", (1280, 800), color=color)
            draw = ImageDraw.Draw(img)
            draw.text((100, 100), f"{display_name} Official Login Page", fill=(255, 255, 255))
            draw.rectangle([400, 300, 880, 550], fill=(255, 255, 255))
            draw.text((420, 320), f"Sign in to {display_name}", fill=(0, 0, 0))
            img.save(screenshot_path)
            
        if not os.path.exists(logo_path):
            logo = Image.new("RGB", (200, 200), color=color)
            draw = ImageDraw.Draw(logo)
            draw.text((30, 80), display_name, fill=(255, 255, 255))
            logo.save(logo_path)
            
        if not os.path.exists(dom_path):
            dom_content = f"""<!DOCTYPE html>
<html>
<head><title>{display_name} Login</title></head>
<body>
    <header><nav><a>{display_name}</a></nav></header>
    <main>
        <form action="/login" method="post">
            <h2>Sign in to {display_name}</h2>
            <input type="text" name="username" placeholder="Email or phone" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Log In</button>
        </form>
    </main>
    <footer><p>&copy; {display_name} Inc.</p></footer>
</body>
</html>"""
            with open(dom_path, "w", encoding="utf-8") as f:
                f.write(dom_content)

@app.on_event("startup")
def startup_event():
    global brands_data, brand_dom_map, brand_names, embedder, visual_store, fusion_model
    logger.info("Initializing PhishSentry AI MVP pipeline...")
    
    create_seed_brand_assets()
    
    if os.path.exists(PROTECTED_BRANDS_FILE):
        with open(PROTECTED_BRANDS_FILE, "r", encoding="utf-8") as f:
            brands_data = json.load(f)
    else:
        logger.error(f"Reference brand store file {PROTECTED_BRANDS_FILE} not found!")
        brands_data = []

    brand_names = [b["brand_id"] for b in brands_data]
    
    # Load DOM snapshots
    for b in brands_data:
        dom_file = os.path.join(BASE_DIR, b["dom_snapshot_path"].replace("/", os.sep))
        if os.path.exists(dom_file):
            with open(dom_file, "r", encoding="utf-8") as f:
                brand_dom_map[b["brand_id"]] = f.read()

    # Load Visual Embedder & Store
    embedder = VisualEmbedder()
    visual_store = ReferenceBrandVisualStore(embedder)
    for b in brands_data:
        img_file = os.path.join(BASE_DIR, b["screenshot_path"].replace("/", os.sep))
        if os.path.exists(img_file):
            visual_store.load_reference_brand(b["brand_id"], img_file)

    # Load Fusion Classifier
    fusion_model = FusionClassifier(MODEL_FILE if os.path.exists(MODEL_FILE) else None)
    logger.info("PhishSentry AI startup complete.")

@app.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(
        status="ok",
        model_loaded=(fusion_model is not None),
        brands_loaded=len(brands_data)
    )

@app.get("/brands", response_model=List[BrandInfo])
def get_protected_brands():
    return [BrandInfo(**b) for b in brands_data]

@app.post("/scan", response_model=ScanResult)
async def scan_url(request: ScanRequest):
    start_time = time.time()
    url = request.url.strip()
    
    if not url or not (url.startswith("http://") or url.startswith("https://") or "." in url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed URL. URL must include a valid hostname or domain scheme."
        )

    # Stage 1: Lexical Analysis (Instant, no network calls)
    lex_res = analyze_lexical(url, brand_names)
    s_lex = lex_res.s_lex

    # Stage 2: Render Page (Playwright with 10s hard timeout per FR-DOM-04)
    screenshot_bytes, dom_html = await render_url(url, timeout_ms=10000)

    s_dom = None
    s_vis = None
    matched_brand = None
    screenshot_rel_url = None
    matched_brand_screenshot_rel_url = None

    if screenshot_bytes is not None and dom_html is not None:
        # Stages 3 & 4: DOM and Visual modules run in parallel
        async def run_dom():
            return match_dom_against_brands(dom_html, brand_dom_map)

        async def run_vis():
            return visual_store.find_best_match(screenshot_bytes)

        (dom_score, dom_matched_brand), (vis_score, vis_matched_brand) = await asyncio.gather(
            run_dom(), run_vis()
        )

        s_dom = dom_score
        s_vis = vis_score

        # Select best matched brand between DOM and Visual
        if vis_score >= dom_score and vis_score > 0.3:
            matched_brand = vis_matched_brand
        elif dom_score > 0.3:
            matched_brand = dom_matched_brand
        elif lex_res.matched_brand and lex_res.levenshtein_sim >= 0.6:
            matched_brand = lex_res.matched_brand

        # Save scan screenshot artifact
        scan_id = str(uuid.uuid4())[:8]
        artifact_filename = f"scan_{scan_id}.png"
        artifact_path = os.path.join(ARTIFACTS_DIR, artifact_filename)
        with open(artifact_path, "wb") as f:
            f.write(screenshot_bytes)
        screenshot_rel_url = f"/artifacts/{artifact_filename}"
    else:
        # Render timeout / network failure path per System Design §2 & NFR-04
        logger.warning(f"Render failed or timed out for {url}. Falling back to lexical-only fusion.")
        if lex_res.matched_brand:
            matched_brand = lex_res.matched_brand

    # Look up matched brand reference screenshot if available
    if matched_brand:
        for b in brands_data:
            if b["brand_id"] == matched_brand:
                matched_brand_screenshot_rel_url = f"/{b['screenshot_path']}"
                break

    # Stage 5 & 6: Fusion & Explainability (XGBoost + SHAP)
    s_phish, shap_contribs, confidence = fusion_model.predict(s_lex, s_dom, s_vis)

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    return ScanResult(
        url=url,
        s_lex=s_lex,
        s_dom=s_dom,
        s_vis=s_vis,
        matched_brand=matched_brand,
        s_phish=s_phish,
        shap_contributions=shap_contribs,
        confidence=confidence,
        screenshot_url=screenshot_rel_url,
        matched_brand_screenshot_url=matched_brand_screenshot_rel_url,
        latency_ms=elapsed_ms
    )
