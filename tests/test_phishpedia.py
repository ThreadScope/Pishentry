import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.phishpedia_engine import evaluate_phishpedia_consistency
from app.certstream_monitor import evaluate_certstream_domain, generate_sample_certstream_feed

def test_phishpedia_consistency_legitimate():
    brands_meta = {
        "paypal": {"display_name": "PayPal", "canonical_domains": ["paypal.com", "paypal-community.com"]},
        "google": {"display_name": "Google", "canonical_domains": ["google.com", "accounts.google.com"]}
    }
    
    res = evaluate_phishpedia_consistency(
        url="https://accounts.google.com/signin/v2",
        matched_brand="google",
        visual_similarity=0.92,
        dom_similarity=0.88,
        brand_metadata=brands_meta
    )
    assert res.is_consistent is True
    assert res.phishing_decision is False
    assert res.brand_intention == "google"
    assert "CONSISTENT" in res.visual_explanation

def test_phishpedia_consistency_phishing():
    brands_meta = {
        "paypal": {"display_name": "PayPal", "canonical_domains": ["paypal.com", "paypal-community.com"]},
        "google": {"display_name": "Google", "canonical_domains": ["google.com", "accounts.google.com"]}
    }
    
    res = evaluate_phishpedia_consistency(
        url="http://accounts-goog1e-verify.xyz/signin",
        matched_brand="google",
        visual_similarity=0.89,
        dom_similarity=0.81,
        brand_metadata=brands_meta
    )
    assert res.is_consistent is False
    assert res.phishing_decision is True
    assert res.brand_intention == "google"
    assert "INCONSISTENT" in res.visual_explanation

def test_certstream_evaluation():
    brands = ["paypal", "google", "microsoft"]
    
    # 1. Suspicious lookalike
    ev = evaluate_certstream_domain(
        domain="paypa1-security-auth.xyz",
        san_list=["paypa1-security-auth.xyz"],
        issuer="Let's Encrypt",
        protected_brands=brands
    )
    assert ev is not None
    assert ev.matched_target_brand == "paypal"
    assert ev.is_zero_day is True
    
    # 2. Legitimate canonical cert
    ev_legit = evaluate_certstream_domain(
        domain="www.google.com",
        san_list=["google.com", "www.google.com"],
        issuer="GTS CA 1C3",
        protected_brands=brands
    )
    assert ev_legit is None

def test_certstream_feed_endpoint():
    with TestClient(app) as client:
        resp = client.get("/certstream/feed")
        assert resp.status_code == 200
        events = resp.json()
        assert isinstance(events, list)
        assert len(events) >= 1
        assert "domain" in events[0]
