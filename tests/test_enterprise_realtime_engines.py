"""
tests/test_enterprise_realtime_engines.py
==========================================
Comprehensive Unit Tests for:
1. Active Honeytoken & C2 Exfiltration Tracker
2. Fast-Flux DNS & ASN Shannon Diversity Tracker
3. MHTML & Cryptographic Merkle Root Evidence Archiver
"""

import io
import json
import zipfile
import pytest
from app.active_honeytoken_interactor import (
    generate_canary_credentials,
    classify_c2_endpoint,
    evaluate_active_honeytoken_interaction
)
from app.fastflux_tracker import (
    compute_ttl_anomaly_score,
    compute_asn_shannon_entropy,
    evaluate_fastflux_dns_risk
)
from app.evidence_archiver import (
    generate_mhtml_document,
    build_evidence_merkle_tree,
    compile_evidence_zip_package
)


def test_canary_deterministic_generation():
    url = "https://login.paypal.verify-secure-portal.com/auth"
    canary1 = generate_canary_credentials(url)
    canary2 = generate_canary_credentials(url)
    
    assert canary1["canary_id"] == canary2["canary_id"]
    assert "sec-canary-" in canary1["username"]
    assert "@corp-audit.internal" in canary1["username"]
    assert len(canary1["canary_id"]) == 12


def test_c2_endpoint_classification():
    # Telegram Bot API
    is_c2, fam, mitre = classify_c2_endpoint("https://api.telegram.org/bot123456:ABC-DEF/sendMessage?chat_id=9876&text=stolen")
    assert is_c2 is True
    assert "Telegram" in fam
    assert mitre == "T1020"

    # Discord Webhook
    is_c2, fam, mitre = classify_c2_endpoint("https://discord.com/api/webhooks/987654321/token_xyz")
    assert is_c2 is True
    assert "Discord" in fam

    # PHP Stealer Gate
    is_c2, fam, mitre = classify_c2_endpoint("https://attacker-gate.com/assets/drop.php")
    assert is_c2 is True
    assert "Credential Harvester" in fam

    # Benign asset
    is_c2, fam, mitre = classify_c2_endpoint("https://cdn.example.com/styles.css")
    assert is_c2 is False


def test_active_honeytoken_evaluation():
    fake_dom = '<form action="https://api.telegram.org/bot123/sendMessage"><input type="password" name="pwd"></form>'
    report = evaluate_active_honeytoken_interaction(
        url="https://secure-login-test.xyz",
        dom_html=fake_dom,
        outbound_requests=["https://api.telegram.org/bot123/sendMessage"]
    )
    assert report["form_located"] is True
    assert report["exfiltration_risk_score"] >= 0.80
    assert len(report["c2_detections"]) >= 1
    assert "T1020" in report["mitre_techniques"]


def test_ttl_anomaly_math():
    # TTL <= 60s should give maximum anomaly score 1.0
    assert compute_ttl_anomaly_score(30) == 1.0
    assert compute_ttl_anomaly_score(60) == 1.0
    # TTL = 180s should give 0.50
    assert compute_ttl_anomaly_score(180) == 0.50
    # TTL > 300s should give 0.0
    assert compute_ttl_anomaly_score(3600) == 0.0


def test_asn_shannon_entropy():
    # Homogeneous ASN list -> 0 entropy
    h, div = compute_asn_shannon_entropy(["AS13335", "AS13335", "AS13335"])
    assert h == 0.0
    assert div == 0.0

    # Diverse ASN list
    h, div = compute_asn_shannon_entropy(["AS13335", "AS204957", "AS44477", "AS200019"])
    assert h > 1.5
    assert div > 0.90


def test_fastflux_evaluation():
    rep = evaluate_fastflux_dns_risk(
        domain="fastflux-suspicious-node.top",
        simulated_ttl=45,
        resolved_ips=["185.220.101.5", "194.36.177.12", "45.142.122.8"]
    )
    assert rep["is_fast_flux_suspect"] is True
    assert rep["fast_flux_composite_index"] >= 0.60
    assert rep["ttl_anomaly_score"] == 1.0


def test_mhtml_generation():
    mhtml = generate_mhtml_document("https://example.com", "<html><body>Hello</body></html>")
    assert "Snapshot-Content-Location: https://example.com" in mhtml
    assert "multipart/related" in mhtml
    assert "<html><body>Hello</body></html>" in mhtml


def test_evidence_merkle_tree_and_zip():
    dom = "<html><body>Bank of America Login Clone</body></html>"
    scr = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    
    merkle = build_evidence_merkle_tree(dom_html=dom, screenshot_bytes=scr)
    assert len(merkle["merkle_root_sha256"]) == 64
    assert len(merkle["dom_html_sha256"]) == 64

    zip_bytes, fname, root_h = compile_evidence_zip_package(
        url="https://bankofamerica.secure-verify-auth.com",
        brand_id="bankofamerica",
        risk_score=0.98,
        dom_html=dom,
        screenshot_bytes=scr
    )
    assert fname.startswith("evidence_")
    assert fname.endswith(".zip")
    assert len(root_h) == 64

    # Verify ZIP structure
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        namelist = zf.namelist()
        assert "manifest.json" in namelist
        assert "snapshot.mhtml" in namelist
        assert "dom.html" in namelist
        assert "screenshot.png" in namelist
        assert "checksums.sha256" in namelist

        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["impersonated_brand"] == "Bankofamerica"
        assert manifest["ai_risk_score"] == 0.98
