import pytest
from app.lexical import analyze_lexical, compute_shannon_entropy

BRANDS = ["paypal", "google", "github", "microsoft", "amazon"]

def test_entropy():
    # Low entropy repeated char string
    assert compute_shannon_entropy("aaaaa") == 0.0
    # Higher entropy
    assert compute_shannon_entropy("paypal.com") > 0.0

def test_legitimate_paypal():
    res = analyze_lexical("https://paypal.com", BRANDS)
    assert res.matched_brand == "paypal"
    assert res.min_levenshtein_dist == 0
    assert res.is_punycode is False
    assert res.is_suspicious_tld is False
    # Legitimate paypal domain should have low risk score
    assert res.s_lex < 0.3

def test_phishing_paypa1():
    res = analyze_lexical("http://paypa1-secure.tk/login", BRANDS)
    assert res.matched_brand == "paypal"
    assert res.min_levenshtein_dist <= 2
    assert res.is_suspicious_tld is True
    assert res.has_hyphen is True
    # Should have high lexical risk score
    assert res.s_lex >= 0.5

def test_punycode():
    res = analyze_lexical("http://xn--80ak6aa92e.com", BRANDS)
    assert res.is_punycode is True
    assert res.s_lex >= 0.4
