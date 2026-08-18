"""
tests/test_nextgen_demo_and_embeddings.py
==========================================
Unit tests for Next-Gen Visual Embeddings, Certificate Transparency Monitor,
and Automated Takedown Evidence Package Generator.
"""

import pytest
import numpy as np
from PIL import Image
from fastapi.testclient import TestClient

from app.main import app
from app.visual_embeddings import (
    extract_visual_embedding_from_image,
    compute_visual_embedding_cosine,
    BrandVisualEmbeddingIndex,
    EMBEDDING_DIM
)
from app.ct_monitor import CertificateTransparencyMonitor
from app.takedown_generator import generate_takedown_package

client = TestClient(app)


def test_visual_embedding_extraction_and_cosine():
    # 1. Create synthetic test images
    img1 = Image.new("RGB", (150, 150), color=(0, 112, 186)) # PayPal blue
    img2 = Image.new("RGB", (150, 150), color=(0, 112, 186))
    img3 = Image.new("RGB", (150, 150), color=(212, 5, 17))  # DHL red

    vec1 = extract_visual_embedding_from_image(img1)
    vec2 = extract_visual_embedding_from_image(img2)
    vec3 = extract_visual_embedding_from_image(img3)

    assert len(vec1) == EMBEDDING_DIM
    assert np.isclose(np.linalg.norm(vec1), 1.0, atol=1e-3)

    # Identical images must yield high cosine similarity
    sim_identical = compute_visual_embedding_cosine(vec1, vec2)
    assert sim_identical >= 0.95

    # Different images should have distinguishable cosine
    sim_diff = compute_visual_embedding_cosine(vec1, vec3)
    assert sim_diff < sim_identical


def test_visual_embedding_brand_index():
    index = BrandVisualEmbeddingIndex()
    img_sample = Image.new("RGB", (200, 200), color=(0, 164, 239))
    score, matched_brand = index.match(img_sample, threshold=0.10)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_ct_monitor_evaluation():
    monitor = CertificateTransparencyMonitor()
    
    # 1. Malicious lookalike test
    ev_malicious = monitor.evaluate_certificate(
        domain="paypal-security-auth-login.xyz",
        issuer="Let's Encrypt"
    )
    assert ev_malicious.matched_brand == "paypal"
    assert ev_malicious.risk_score >= 0.70
    assert ev_malicious.risk_verdict == "HIGH_RISK_PHISHING"
    assert len(ev_malicious.risk_factors) > 0

    # 2. Canonical official domain test
    ev_official = monitor.evaluate_certificate(
        domain="paypal.com",
        issuer="DigiCert Inc"
    )
    assert ev_official.risk_score <= 0.10
    assert ev_official.risk_verdict == "BENIGN_OFFICIAL"

    # 3. Stream retrieval
    recent = monitor.get_recent_events(limit=5)
    assert len(recent) > 0
    assert "domain" in recent[0]


def test_takedown_package_generation():
    pkg = generate_takedown_package(
        url="https://paypa1-security-check.xyz/login",
        brand_id="paypal",
        risk_score=0.98,
        s_lex=0.92,
        s_dom=0.95,
        s_vis=0.96,
        ip_address="198.51.100.42"
    )
    assert pkg["impersonated_brand"] == "Paypal"
    assert pkg["risk_score"] == 0.98
    assert "evidence_digest_sha256" in pkg
    assert len(pkg["evidence_digest_sha256"]) == 64
    assert "[URGENT ABUSE REPORT]" in pkg["abuse_email_subject"]
    assert "T1566.002" in pkg["abuse_email_body"]
    assert len(pkg["mitre_attack_techniques"]) == 3


def test_fastapi_ct_and_takedown_endpoints():
    # 1. CT recent events
    resp_ct = client.get("/api/v1/ct-stream/recent")
    assert resp_ct.status_code == 200
    assert "events" in resp_ct.json()

    # 2. CT check domain
    resp_check = client.post("/api/v1/ct-stream/check-domain?domain=secure-login-microsoft.online")
    assert resp_check.status_code == 200
    data = resp_check.json()
    assert data["matched_brand"] == "microsoft"

    # 3. Generate takedown
    resp_tkd = client.post("/api/v1/generate-takedown?url=https://sbi-kyc-update.tk&brand_id=sbi&risk_score=0.95")
    assert resp_tkd.status_code == 200
    assert "evidence_digest_sha256" in resp_tkd.json()
