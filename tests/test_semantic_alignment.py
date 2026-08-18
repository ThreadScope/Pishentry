import pytest
from app.semantic_alignment import analyze_domain_purpose_alignment

def test_semantic_cloaking_content_swapping():
    # Tested URL claims to be DHL tracking, but rendered DOM is a Google Search engine bait page
    url = "http://dhl-express-tracking-portal.tk/track"
    google_dom = """
    <html>
    <head><title>Google</title></head>
    <body>
        <a href="/about">About</a><a href="/store">Store</a><a href="/gmail">Gmail</a>
        <input type="text" title="Search" />
        <button>Google Search</button><button>I'm Feeling Lucky</button>
    </body>
    </html>
    """
    res = analyze_domain_purpose_alignment(
        url=url,
        dom_html=google_dom,
        s_lex_brand="dhl",
        s_vis_brand=None,
        is_canonical=False
    )
    assert res.is_discrepancy_detected is True
    assert res.discrepancy_type == "CLOAKING_CONTENT_SWAP"
    assert res.domain_intent_brand == "dhl"
    assert res.rendered_content_brand == "google"
    assert "T1027.006" in res.mitre_attack_id
    assert res.alignment_score < 0.50

def test_semantic_canonical_alignment():
    url = "https://www.google.com"
    google_dom = "<html><head><title>Google</title></head><body><button>Google Search</button></body></html>"
    res = analyze_domain_purpose_alignment(
        url=url,
        dom_html=google_dom,
        s_lex_brand="google",
        s_vis_brand="google",
        is_canonical=True
    )
    assert res.is_discrepancy_detected is False
    assert res.discrepancy_type == "MATCH"
    assert res.alignment_score == 1.0

def test_semantic_spoofed_brand_portal():
    url = "http://untrusted-host.tk/login"
    dom = "<html><body><h1>PayPal Login</h1><input type='password' /></body></html>"
    res = analyze_domain_purpose_alignment(
        url=url,
        dom_html=dom,
        s_lex_brand=None,
        s_vis_brand="paypal",
        is_canonical=False
    )
    assert res.is_discrepancy_detected is True
    assert res.discrepancy_type == "SPOOFED_PORTAL"
    assert res.rendered_content_brand == "paypal"
