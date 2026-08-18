import pytest
from app.aitm_detector import detect_aitm_proxy
from app.cloaking_detector import analyze_cloaking_and_anti_bot
from app.lexical import analyze_lexical
from app.webhook import dispatch_soc_webhook_alert
from app.schemas import TLSTelemetry
from fastapi.testclient import TestClient
from app.main import app

def test_aitm_detection_evilginx_signature():
    tls = TLSTelemetry(
        has_tls=True,
        issuer="Let's Encrypt Authority X3",
        subject="login.microsoftonline.com.attacker.tk",
        is_free_ca=True,
        is_self_signed=False
    )
    res = detect_aitm_proxy(
        url="https://login.microsoftonline.com.attacker.tk/login",
        s_vis=0.88,
        s_dom=0.85,
        matched_brand="microsoft",
        is_canonical=False,
        tls_telemetry=tls,
        dom_html='<input type="password" name="passwd" />'
    )
    assert res.is_aitm_suspect is True
    assert res.confidence_level in ["HIGH", "CRITICAL"]
    assert "T1556" in res.mitre_attack_id
    assert res.risk_score_boost > 0.0

def test_aitm_canonical_safety():
    tls = TLSTelemetry(
        has_tls=True,
        issuer="Microsoft RSA TLS CA 01",
        subject="login.microsoftonline.com",
        is_free_ca=False
    )
    res = detect_aitm_proxy(
        url="https://login.microsoftonline.com",
        s_vis=0.99,
        s_dom=0.99,
        matched_brand="microsoft",
        is_canonical=True,
        tls_telemetry=tls
    )
    assert res.is_aitm_suspect is False
    assert res.risk_score_boost == 0.0

def test_cloaking_cloudflare_turnstile():
    turnstile_html = """
    <html>
    <head><title>Just a moment...</title></head>
    <body>
        <div id="cf-turnstile" data-sitekey="0x4AAAAAA"></div>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
    </body>
    </html>
    """
    res = analyze_cloaking_and_anti_bot(turnstile_html, "http://suspicious-site.tk")
    assert res.is_cloaked is True
    assert res.is_bot_wall is True
    assert res.interstitial_type is not None and "Turnstile" in res.interstitial_type

def test_subdomain_masquerading_lexical():
    lex = analyze_lexical(
        url="http://paypal.com.account-update-security.tk/login",
        brand_list=["paypal", "google", "microsoft"]
    )
    assert lex.s_lex >= 0.70
    assert lex.matched_brand == "paypal"
    assert lex.is_canonical_domain is False

def test_webhook_endpoint_validation():
    with TestClient(app) as client:
        # Invalid webhook url should gracefully fail
        payload = {
            "webhook_url": "invalid-url",
            "scan_result": {
                "url": "http://paypa1-phish.tk",
                "s_lex": 0.85,
                "s_phish": 0.89,
                "shap_contributions": {"s_lex": 1.0},
                "confidence": "full",
                "latency_ms": 500.0
            }
        }
        resp = client.post("/webhook/dispatch", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
