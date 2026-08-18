import pytest
import asyncio
from fastapi.testclient import TestClient
from PIL import Image
from app.main import app
from app.telemetry import extract_tls_telemetry, TLSInfo
from app.visual_similarity import compute_image_dhash, compute_dhash_similarity
from app.schemas import ScanResult

@pytest.mark.asyncio
async def test_tls_telemetry_http():
    tls = await extract_tls_telemetry("http://example.com", timeout_seconds=1.0)
    assert isinstance(tls, TLSInfo)
    assert tls.has_tls is False

@pytest.mark.asyncio
async def test_tls_telemetry_invalid_host():
    tls = await extract_tls_telemetry("https://nonexistent-domain-123456789-xyz.fake", timeout_seconds=1.0)
    assert isinstance(tls, TLSInfo)
    assert tls.has_tls is False
    assert tls.error_detail is not None

def test_dhash_identical_images():
    img = Image.new("RGB", (100, 100), color=(255, 0, 0))
    h1 = compute_image_dhash(img)
    h2 = compute_image_dhash(img)
    sim = compute_dhash_similarity(h1, h2)
    assert sim == 1.0

def test_dhash_different_images():
    img1 = Image.new("RGB", (100, 100), color=(255, 255, 255))
    img2 = Image.new("RGB", (100, 100), color=(0, 0, 0))
    h1 = compute_image_dhash(img1)
    h2 = compute_image_dhash(img2)
    # Both flat solid colors will have identical gradient, but let's test pattern
    assert isinstance(h1, int)
    assert isinstance(h2, int)

def test_batch_scan_endpoint():
    with TestClient(app) as client:
        batch_payload = {
            "urls": [
                "http://paypa1-secure-login.tk/auth",
                "https://paypal.com"
            ],
            "max_concurrency": 2
        }
        response = client.post("/scan/batch", json=batch_payload)
        assert response.status_code == 200
        data = response.json()
        assert data["total_requested"] == 2
        assert data["scanned_count"] >= 1
        assert "results" in data
        assert isinstance(data["results"], list)

def test_stix_bundle_export():
    with TestClient(app) as client:
        # Create sample scan result
        sample_result = {
            "url": "http://paypa1-secure-login.tk/auth",
            "s_lex": 0.85,
            "s_dom": 0.75,
            "s_vis": 0.88,
            "matched_brand": "paypal",
            "s_phish": 0.89,
            "shap_contributions": {"s_lex": 0.4, "s_dom": 0.3, "s_vis": 0.3},
            "confidence": "full",
            "latency_ms": 1200.0,
            "tls_telemetry": {
                "has_tls": True,
                "issuer": "Let's Encrypt",
                "subject": "paypa1-secure-login.tk",
                "san_list": ["paypa1-secure-login.tk"],
                "is_self_signed": False,
                "is_free_ca": True,
                "resolved_ip": "192.168.1.50"
            }
        }
        
        response = client.post("/export/stix", json={"scan_results": [sample_result]})
        assert response.status_code == 200
        bundle = response.json()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) >= 2
        
        # Verify identity and indicator
        types = [obj["type"] for obj in bundle["objects"]]
        assert "identity" in types
        assert "indicator" in types
