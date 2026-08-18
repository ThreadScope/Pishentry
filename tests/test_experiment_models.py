"""
tests/test_experiment_models.py
================================
Comprehensive test suite for experiment-backed AI model integrations:
- StackModel 23-Feature Content-Based Extractor
- PhishZoo TF-IDF Content Tokenizer
- EMD Visual Signature Comparison Engine
- ISCX 79-Feature Ensemble (from app/iscx_features.py)
- Pipeline Integration (schema validation)
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock

# ========== StackModel Tests ==========

from app.stackmodel_features import (
    HTMLFeatureExtractor, URLFeatureExtractor,
    extract_stackmodel_23_features, _extract_domain_from_url
)


class TestStackModelURLFeatures:
    """Tests for the StackModel URL-based feature extraction."""

    def test_basic_url_extraction(self):
        result = extract_stackmodel_23_features("https://www.google.com", None)
        assert "url_len" in result
        assert "domain_len" in result
        assert "https" in result
        assert result["https"] == 1
        assert result["feature_count"] == 23

    def test_ip_address_detection(self):
        extractor = URLFeatureExtractor("http://192.168.1.1/login")
        assert extractor.domain_is_ip() == 1

    def test_domain_not_ip(self):
        extractor = URLFeatureExtractor("https://www.google.com")
        assert extractor.domain_is_ip() == 0

    def test_https_detection(self):
        extractor = URLFeatureExtractor("https://secure.example.com")
        assert extractor.has_https() == 1

    def test_http_detection(self):
        extractor = URLFeatureExtractor("http://insecure.example.com")
        assert extractor.has_https() == 0

    def test_sensitive_word_detection(self):
        extractor = URLFeatureExtractor("https://login.example.com/secure/banking")
        assert extractor.sensitive_word_present() == 1

    def test_no_sensitive_words(self):
        extractor = URLFeatureExtractor("https://www.example.com/about")
        assert extractor.sensitive_word_present() == 0

    def test_tld_in_domain(self):
        extractor = URLFeatureExtractor("http://com-login.example.xyz")
        features = extractor.extract_all_features()
        assert "tld_in_domain" in features

    def test_symbol_count(self):
        extractor = URLFeatureExtractor("http://user@evil-phish~site.com")
        count = extractor.symbol_count()
        assert count >= 3  # @, -, ~

    def test_dots_in_hostname(self):
        extractor = URLFeatureExtractor("http://a.b.c.d.example.com")
        assert extractor.num_dots_in_hostname() == 5

    def test_url_length(self):
        long_url = "https://very-long-domain.example.com/" + "a" * 100
        extractor = URLFeatureExtractor(long_url)
        assert extractor.url_length() > 100


class TestStackModelHTMLFeatures:
    """Tests for the StackModel HTML-based feature extraction."""

    SAMPLE_HTML = """
    <html>
    <head><title>Example Domain</title></head>
    <body>
        <a href="https://example.com/page1">Internal Link</a>
        <a href="https://external.com/page2">External Link</a>
        <a href="#">Empty Link</a>
        <a href="javascript:void(0)">JS Link</a>
        <form action="/login" method="POST">
            <input type="text" name="email">
            <input type="password" name="password">
        </form>
        <script>alert('test')</script>
        <div style="display:none">hidden content</div>
    </body>
    </html>
    """

    def test_html_feature_extraction(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(self.SAMPLE_HTML, "html.parser")
        extractor = HTMLFeatureExtractor(soup, "https://example.com")
        features = extractor.extract_all_features()

        assert "internal_link" in features
        assert "external_link" in features
        assert "empty_link" in features
        assert features["empty_link"] >= 2  # # and javascript:void(0)
        assert features["login_form"] == 1  # password field present
        assert features["alarm_window"] == 1  # alert() in script
        assert features["hidden"] == 1  # display:none div

    def test_internal_external_links(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(self.SAMPLE_HTML, "html.parser")
        extractor = HTMLFeatureExtractor(soup, "https://example.com")
        internal, external = extractor.internal_external_links()
        assert internal >= 1
        assert external >= 1

    def test_title_domain_check(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(self.SAMPLE_HTML, "html.parser")
        extractor = HTMLFeatureExtractor(soup, "https://example.com")
        assert extractor.title_contains_domain() == 1

    def test_redirect_detection(self):
        html_with_redirect = '<html><body><script>window.location="http://evil.com"</script>redirect</body></html>'
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_with_redirect, "html.parser")
        extractor = HTMLFeatureExtractor(soup, "https://example.com")
        assert extractor.redirect_present() == 1

    def test_no_login_form(self):
        html_no_form = '<html><body><p>Just text</p></body></html>'
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_no_form, "html.parser")
        extractor = HTMLFeatureExtractor(soup, "https://example.com")
        assert extractor.login_form_present() == 0


class TestStackModel23Features:
    """Integration tests for the complete 23-feature extractor."""

    def test_full_extraction_with_html(self):
        html = '<html><head><title>Test</title></head><body><a href="#">Link</a></body></html>'
        result = extract_stackmodel_23_features("https://test.com", html)
        assert result["feature_count"] == 23
        assert "stackmodel_risk_score" in result
        assert 0.0 <= result["stackmodel_risk_score"] <= 1.0

    def test_full_extraction_without_html(self):
        result = extract_stackmodel_23_features("https://test.com", None)
        assert result["feature_count"] == 23
        assert result["html_len"] == 0  # No HTML available

    def test_phishing_url_high_risk(self):
        phishing_url = "http://192.168.1.1/secure-login-banking/account"
        result = extract_stackmodel_23_features(phishing_url, None)
        assert result["stackmodel_risk_score"] > 0.3  # Has multiple URL risk signals

    def test_benign_url_low_risk(self):
        result = extract_stackmodel_23_features("https://www.google.com", None)
        assert result["stackmodel_risk_score"] < 0.5


# ========== PhishZoo Tests ==========

from app.phishzoo_tokenizer import (
    PhishZooTokenizer, analyze_content_brand_match
)


class TestPhishZooTokenizer:
    """Tests for the PhishZoo TF-IDF tokenizer."""

    def test_url_tokenization(self):
        tokenizer = PhishZooTokenizer(url="https://paypal.com/login/secure")
        tokens = tokenizer.get_combined_tokens()
        assert "paypal" in tokens.lower()

    def test_html_tokenization(self):
        html = '<html><body><h1>Sign in to your PayPal account</h1><p>Enter your password</p></body></html>'
        tokenizer = PhishZooTokenizer(html_content=html, url="https://example.com")
        tokens = tokenizer.get_combined_tokens()
        assert "paypal" in tokens.lower()
        assert "password" in tokens.lower()

    def test_script_removal(self):
        html = '<html><body><script>var x = "malicious";</script><p>Clean text</p></body></html>'
        tokenizer = PhishZooTokenizer(html_content=html, url="https://example.com")
        tokens = tokenizer.get_combined_tokens()
        assert "malicious" not in tokens.lower()

    def test_brand_matching_paypal(self):
        html = '<html><body><h1>PayPal Login</h1><p>Enter your payment details for billing</p></body></html>'
        result = analyze_content_brand_match("https://suspicious-site.com/paypal", html)
        assert result["detected_brand"] == "paypal"
        assert result["brand_confidence"] > 0.0

    def test_brand_matching_google(self):
        html = '<html><body><h1>Google Sign In</h1><p>Access your Gmail account</p></body></html>'
        result = analyze_content_brand_match("https://suspicious-site.com", html)
        assert result["detected_brand"] == "google"
        assert result["brand_confidence"] > 0.0

    def test_no_brand_detected(self):
        html = '<html><body><h1>Generic Page</h1><p>Nothing special here</p></body></html>'
        result = analyze_content_brand_match("https://example.com", html)
        assert result["detected_brand"] is None or result["brand_confidence"] == 0.0

    def test_empty_html(self):
        result = analyze_content_brand_match("https://example.com", "")
        assert "token_count" in result

    def test_url_only_brand_match(self):
        result = analyze_content_brand_match("https://paypal-login.example.com/secure", None)
        assert result["detected_brand"] == "paypal"

    def test_brand_confidence_ranges(self):
        result = analyze_content_brand_match("https://paypal.com/login", None)
        assert 0.0 <= result["brand_confidence"] <= 1.0

    def test_multiple_brand_keywords(self):
        html = '<html><body><p>PayPal payment invoice billing transaction</p></body></html>'
        result = analyze_content_brand_match("https://example.com", html)
        assert result["detected_brand"] == "paypal"
        assert result["brand_confidence"] >= 0.4  # Multiple keyword matches


# ========== EMD Visual Tests ==========

from app.emd_visual import (
    _get_color_signature, compute_emd_similarity, compare_screenshots_emd
)
from PIL import Image
import io


class TestEMDVisual:
    """Tests for the EMD visual signature comparison engine."""

    def _create_test_image(self, color=(255, 0, 0), size=(100, 100)):
        img = Image.new("RGBA", size, color)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def test_color_signature_extraction(self):
        img = Image.new("RGBA", (50, 50), (128, 64, 32, 255))
        sig, md = _get_color_signature(img)
        assert len(sig) > 0
        assert md > 0

    def test_identical_images_high_similarity(self):
        img_bytes = self._create_test_image((100, 150, 200))
        result = compare_screenshots_emd(img_bytes, img_bytes)
        assert result["emd_similarity"] >= 0.95

    def test_different_images_lower_similarity(self):
        red_img = self._create_test_image((255, 0, 0))
        blue_img = self._create_test_image((0, 0, 255))
        result = compare_screenshots_emd(red_img, blue_img)
        # Very different colors should yield lower similarity
        assert result["emd_similarity"] < 0.99

    def test_visual_clone_detection(self):
        img_bytes = self._create_test_image((100, 150, 200))
        result = compare_screenshots_emd(img_bytes, img_bytes)
        assert result["is_visual_clone"] is True

    def test_emd_threshold_present(self):
        img_bytes = self._create_test_image()
        result = compare_screenshots_emd(img_bytes, img_bytes)
        assert "emd_threshold" in result

    def test_empty_image_handling(self):
        result = compare_screenshots_emd(b"", b"")
        assert result["emd_similarity"] == 0.0

    def test_compute_emd_similarity_empty_signatures(self):
        sim = compute_emd_similarity([], [], 1.0, 1.0)
        assert sim == 0.0


# ========== ISCX Feature Integration Tests ==========

from app.iscx_features import extract_iscx_79_features, ISCXModelEnsemble


class TestISCXFeatures:
    """Tests for ISCX 79-dimensional feature extraction."""

    def test_79_dim_extraction(self):
        vec = extract_iscx_79_features("https://paypal-login.xyz/secure/account")
        assert len(vec) == 79

    def test_benign_url_features(self):
        vec = extract_iscx_79_features("https://www.google.com")
        assert len(vec) == 79
        assert vec[0] >= 0  # url_length is non-negative

    def test_ip_url_features(self):
        vec = extract_iscx_79_features("http://192.168.1.1/login")
        assert len(vec) == 79

    def test_ensemble_predict(self):
        ensemble = ISCXModelEnsemble()
        result = ensemble.predict("https://suspicious-phish.xyz/login")
        assert "lr_prob" in result
        assert "rf_prob" in result
        assert "svm_pred" in result
        assert "ensemble_score" in result
        assert 0.0 <= result["ensemble_score"] <= 1.0

    def test_ensemble_benign(self):
        ensemble = ISCXModelEnsemble()
        result = ensemble.predict("https://www.google.com")
        assert result["ensemble_score"] < 0.80  # Should be relatively low

    def test_feature_vector_dtype(self):
        vec = extract_iscx_79_features("https://example.com")
        assert isinstance(vec, np.ndarray)
        assert vec.dtype in [np.float64, np.float32, np.int64, np.int32, float]


# ========== Schema Integration Tests ==========

from app.schemas import (
    ISCXEnsembleTelemetry, StackModelTelemetry, PhishZooTelemetry, ScanResult
)


class TestSchemaIntegration:
    """Tests for new telemetry schema models."""

    def test_iscx_telemetry_defaults(self):
        t = ISCXEnsembleTelemetry()
        assert t.logistic_regression_score == 0.0
        assert t.feature_vector_dim == 79

    def test_stackmodel_telemetry_defaults(self):
        t = StackModelTelemetry()
        assert t.stackmodel_risk_score == 0.0
        assert t.brand_domain == 1

    def test_phishzoo_telemetry_defaults(self):
        t = PhishZooTelemetry()
        assert t.detected_brand is None
        assert t.brand_confidence == 0.0

    def test_scan_result_with_experiment_telemetry(self):
        result = ScanResult(
            url="https://test.com",
            s_lex=0.5,
            s_phish=0.8,
            shap_contributions={"s_lex": 0.4, "s_dom": 0.3, "s_vis": 0.3},
            confidence="full",
            latency_ms=100.0,
            iscx_ensemble=ISCXEnsembleTelemetry(ensemble_phish_score=0.75),
            stackmodel_features=StackModelTelemetry(stackmodel_risk_score=0.6),
            phishzoo_analysis=PhishZooTelemetry(detected_brand="paypal", brand_confidence=0.8)
        )
        assert result.iscx_ensemble is not None
        assert result.iscx_ensemble.ensemble_phish_score == 0.75
        assert result.stackmodel_features is not None
        assert result.stackmodel_features.stackmodel_risk_score == 0.6
        assert result.phishzoo_analysis is not None
        assert result.phishzoo_analysis.detected_brand == "paypal"

    def test_scan_result_without_experiment_telemetry(self):
        """Backward compatibility: new fields are optional."""
        result = ScanResult(
            url="https://test.com",
            s_lex=0.1,
            s_phish=0.1,
            shap_contributions={"s_lex": 1.0, "s_dom": 0.0, "s_vis": 0.0},
            confidence="full",
            latency_ms=50.0
        )
        assert result.iscx_ensemble is None
        assert result.stackmodel_features is None
        assert result.phishzoo_analysis is None


# ========== Domain Utility Tests ==========

class TestDomainExtraction:
    """Tests for URL domain extraction utility."""

    def test_extract_domain(self):
        assert _extract_domain_from_url("https://www.example.com/path") == "www.example.com"

    def test_extract_domain_with_port(self):
        assert _extract_domain_from_url("http://example.com:8080/page") == "example.com"

    def test_extract_domain_no_scheme(self):
        assert _extract_domain_from_url("example.com") == "example.com"

    def test_extract_domain_ip(self):
        assert _extract_domain_from_url("http://192.168.1.1/login") == "192.168.1.1"
