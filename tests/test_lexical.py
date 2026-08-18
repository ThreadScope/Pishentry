import pytest
from app.lexical import analyze_lexical, compute_shannon_entropy, is_valid_ip_address

BRANDS = ["paypal", "google", "github", "microsoft", "amazon", "bankofamerica", "chase", "dhl"]
CANONICAL_MAP = {
    "paypal": ["paypal.com", "www.paypal.com"],
    "google": ["google.com", "accounts.google.com"],
    "github": ["github.com"]
}

def test_entropy():
    # Low entropy repeated char string
    assert compute_shannon_entropy("aaaaa") == 0.0
    # Higher entropy
    assert compute_shannon_entropy("paypal.com") > 0.0

def test_legitimate_paypal():
    res = analyze_lexical("https://paypal.com", BRANDS, canonical_domain_map=CANONICAL_MAP)
    assert res.matched_brand == "paypal"
    assert res.min_levenshtein_dist == 0
    assert res.is_punycode is False
    assert res.is_suspicious_tld is False
    assert res.is_canonical_domain is True
    # Legitimate paypal domain should have minimal risk score
    assert res.s_lex < 0.1

def test_legitimate_google_subdomain():
    res = analyze_lexical("https://accounts.google.com", BRANDS, canonical_domain_map=CANONICAL_MAP)
    assert res.matched_brand == "google"
    assert res.is_canonical_domain is True
    assert res.s_lex < 0.1

def test_phishing_paypa1():
    res = analyze_lexical("http://paypa1-secure.tk/login", BRANDS, canonical_domain_map=CANONICAL_MAP)
    assert res.matched_brand == "paypal"
    assert res.min_levenshtein_dist <= 2
    assert res.is_suspicious_tld is True
    assert res.has_hyphen is True
    assert res.is_canonical_domain is False
    # Should have high lexical risk score
    assert res.s_lex >= 0.5

def test_phishing_hyphenated_exact_brand():
    # Brand token embedded in spoofed domain body
    res = analyze_lexical("http://paypal-update-account.com/auth", BRANDS, canonical_domain_map=CANONICAL_MAP)
    assert res.matched_brand == "paypal"
    assert res.is_canonical_domain is False
    assert res.s_lex >= 0.55

def test_punycode():
    res = analyze_lexical("http://xn--80ak6aa92e.com", BRANDS, canonical_domain_map=CANONICAL_MAP)
    assert res.is_punycode is True
    assert res.s_lex >= 0.4

def test_long_subdomain():
    res = analyze_lexical("http://paypal.support.login.verify-identity.com", BRANDS, canonical_domain_map=CANONICAL_MAP)
    assert res.subdomain_count >= 2
    assert res.s_lex >= 0.4

def test_ip_address_with_port():
    res = analyze_lexical("http://192.168.1.1:8080/login", BRANDS, canonical_domain_map=CANONICAL_MAP)
    assert res.is_ip is True
    assert res.s_lex >= 0.55

def test_ip_address_helpers():
    assert is_valid_ip_address("192.168.1.1") is True
    assert is_valid_ip_address("10.0.0.1:8080") is True
    assert is_valid_ip_address("::1") is True
    assert is_valid_ip_address("paypal.com") is False

