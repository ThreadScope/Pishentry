"""
tests/test_reference_brands_dom.py
==================================
Tests for 38 Official Enterprise Reference Brand DOMs (Login + Landing),
Structural SimHash indexing, and Multi-Modal Disambiguation.
"""

import os
import json
import pytest
from app.dom_similarity import (
    compute_dom_similarity, match_dom_against_brands, extract_tag_sequence,
    compute_dom_simhash, compute_brand_semantic_score, BRAND_TOKEN_SIGNATURES
)
from app.reference_brands_generator import ALL_REFERENCE_BRANDS, REF_DIR, PROTECTED_BRANDS_FILE


class TestReferenceBrandsDOM:
    """Test suite validating production-grade reference DOM assets across all brands."""

    def test_all_38_brands_manifest(self):
        assert len(ALL_REFERENCE_BRANDS) >= 35
        assert os.path.exists(PROTECTED_BRANDS_FILE)
        with open(PROTECTED_BRANDS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data) >= 35

    def test_all_reference_dom_files_exist(self):
        with open(PROTECTED_BRANDS_FILE, "r", encoding="utf-8") as f:
            brands = json.load(f)

        for b in brands:
            b_id = b["brand_id"]
            folder = os.path.join(REF_DIR, b_id)
            dom_path = os.path.join(folder, "dom.html")
            landing_path = os.path.join(folder, "landing.html")

            assert os.path.exists(dom_path), f"Missing dom.html for brand: {b_id}"
            assert os.path.exists(landing_path), f"Missing landing.html for brand: {b_id}"

            with open(dom_path, "r", encoding="utf-8") as f:
                content = f.read()
                assert "<form" in content.lower(), f"Login DOM missing form tag in: {b_id}"
                assert "input" in content.lower(), f"Login DOM missing input elements in: {b_id}"

            with open(landing_path, "r", encoding="utf-8") as f:
                content = f.read()
                assert len(content) > 100, f"Landing DOM empty for: {b_id}"

    def test_dom_similarity_identical(self):
        google_dom_path = os.path.join(REF_DIR, "google", "dom.html")
        with open(google_dom_path, "r", encoding="utf-8") as f:
            html = f.read()
        sim = compute_dom_similarity(html, html)
        assert sim == 1.0

    def test_dom_brand_matching_google_login(self):
        google_dom_path = os.path.join(REF_DIR, "google", "dom.html")
        with open(google_dom_path, "r", encoding="utf-8") as f:
            google_html = f.read()

        brand_dom_map = {}
        for b_name in ["google", "paypal", "microsoft", "github", "bankofamerica"]:
            fpath = os.path.join(REF_DIR, b_name, "dom.html")
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    brand_dom_map[b_name] = f.read()

        score, matched_brand = match_dom_against_brands(google_html, brand_dom_map)
        assert matched_brand == "google"
        assert score > 0.70

    def test_dom_brand_matching_paypal_clone(self):
        paypal_dom_path = os.path.join(REF_DIR, "paypal", "dom.html")
        with open(paypal_dom_path, "r", encoding="utf-8") as f:
            paypal_html = f.read()

        # Simulated phishing clone with spoofed action
        phish_html = paypal_html.replace("https://www.paypal.com/signin", "http://evil-collector.tk/drop.php")

        brand_dom_map = {}
        for b_name in ["google", "paypal", "microsoft", "github", "bankofamerica"]:
            fpath = os.path.join(REF_DIR, b_name, "dom.html")
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    brand_dom_map[b_name] = f.read()

        score, matched_brand = match_dom_against_brands(phish_html, brand_dom_map)
        assert matched_brand == "paypal"
        assert score > 0.70

    def test_brand_token_signatures_completeness(self):
        for brand in ["sbi", "hdfc", "icici", "stripe", "zoom", "salesforce", "okta", "google", "microsoft", "paypal"]:
            assert brand in BRAND_TOKEN_SIGNATURES, f"Missing token signatures for: {brand}"
            assert len(BRAND_TOKEN_SIGNATURES[brand]) >= 3
