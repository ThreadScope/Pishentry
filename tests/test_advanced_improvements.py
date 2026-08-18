import pytest
from PIL import Image, ImageDraw
import io
from app.quishing_detector import scan_for_qr_codes
from app.export_rules import generate_sigma_rule, generate_yara_rule, generate_dns_blocklist
from fastapi.testclient import TestClient
from app.main import app

def test_quishing_scanner_clean_image():
    # Plain white image should have no QR code
    img = Image.new("RGB", (200, 200), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    res = scan_for_qr_codes(buf.getvalue())
    assert res.is_quishing_suspect is False
    assert res.has_qr_code is False

def test_quishing_scanner_matrix_pattern():
    # High-contrast grid image simulating a QR matrix
    img = Image.new("RGB", (200, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    for x in range(0, 200, 20):
        for y in range(0, 200, 20):
            if (x + y) % 40 == 0:
                draw.rectangle([x, y, x+15, y+15], fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    res = scan_for_qr_codes(buf.getvalue())
    assert res.has_qr_code is True

def test_sigma_rule_generator():
    scan_result = {
        "url": "http://paypal-verification-account.tk/login",
        "matched_brand": "paypal",
        "s_phish": 0.96,
        "shap_contributions": {"s_lex": 0.5, "s_vis": 0.4}
    }
    sigma_yaml = generate_sigma_rule(scan_result)
    assert "paypal-verification-account.tk" in sigma_yaml
    assert "attack.t1566.002" in sigma_yaml
    assert "critical" in sigma_yaml

def test_yara_rule_generator():
    scan_result = {
        "url": "http://paypa1-update.xyz/auth",
        "matched_brand": "paypal",
        "s_phish": 0.92
    }
    yara_rule = generate_yara_rule(scan_result)
    assert "rule PhishSentry_" in yara_rule
    assert "paypa1-update.xyz" in yara_rule
    assert "$form_input" in yara_rule

def test_dns_blocklist_generator():
    scan_results = [
        {"url": "http://phish-site-1.tk", "s_phish": 0.91, "matched_brand": "google"},
        {"url": "http://safe-site.com", "s_phish": 0.05, "matched_brand": None}
    ]
    blocklist = generate_dns_blocklist(scan_results)
    assert "0.0.0.0 phish-site-1.tk" in blocklist
    assert "safe-site.com" not in blocklist

def test_dynamic_brand_registration_and_deletion():
    with TestClient(app) as client:
        # 1. Register new custom brand "okta"
        payload = {
            "brand_id": "okta_test",
            "display_name": "Okta Test Portal",
            "canonical_domains": ["okta.com", "login.okta.com"],
            "official_login_url": "https://login.okta.com",
            "brand_color": "#007dc1",
            "security_advice": "Verify Okta domain."
        }
        reg_resp = client.post("/brands/register", json=payload)
        assert reg_resp.status_code == 200
        bdata = reg_resp.json()
        assert bdata["brand_id"] == "okta_test"
        assert "okta.com" in bdata["canonical_domains"]

        # 2. Verify it appears in /brands endpoint
        list_resp = client.get("/brands")
        assert list_resp.status_code == 200
        brand_ids = [b["brand_id"] for b in list_resp.json()]
        assert "okta_test" in brand_ids

        # 3. Clean up / Unregister brand
        del_resp = client.delete("/brands/okta_test")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "ok"
