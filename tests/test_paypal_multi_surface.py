"""
tests/test_paypal_multi_surface.py
==================================
Unit Tests for Multi-Surface PayPal AI Perception:
- Canonical Sign-In Card (Screenshot 4)
- Account Selection / Onboarding (Screenshot 1)
- Sign-Up Entry (Screenshot 3)
- WAF Interstitial Challenge (Screenshot 2)
- 256-D Perceptual Visual Embedding Top Match against authentic reference
"""

import os
import pytest
from app.dom_similarity import compute_dom_similarity, match_dom_against_brands
from app.visual_embeddings import BrandVisualEmbeddingIndex

REF_PAYPAL_DIR = os.path.join("data", "reference", "paypal")


def get_reference_brand_map():
    brand_map = {}
    ref_root = os.path.join("data", "reference")
    for b in os.listdir(ref_root):
        dom_p = os.path.join(ref_root, b, "dom.html")
        if os.path.exists(dom_p):
            with open(dom_p, "r", encoding="utf-8") as f:
                brand_map[b] = f.read()
    return brand_map


def test_paypal_canonical_signin_dom():
    dom_path = os.path.join(REF_PAYPAL_DIR, "dom.html")
    assert os.path.exists(dom_path)
    with open(dom_path, "r", encoding="utf-8") as f:
        dom_content = f.read()

    brand_map = get_reference_brand_map()
    score, matched = match_dom_against_brands(dom_content, brand_map)
    assert matched == "paypal"
    assert score >= 0.70


def test_paypal_landing_account_selection_dom():
    dom_path = os.path.join(REF_PAYPAL_DIR, "landing.html")
    assert os.path.exists(dom_path)
    with open(dom_path, "r", encoding="utf-8") as f:
        dom_content = f.read()

    brand_map = get_reference_brand_map()
    score, matched = match_dom_against_brands(dom_content, brand_map)
    assert matched == "paypal"
    assert score >= 0.60


def test_paypal_signup_dom():
    dom_path = os.path.join(REF_PAYPAL_DIR, "signup.html")
    assert os.path.exists(dom_path)
    with open(dom_path, "r", encoding="utf-8") as f:
        dom_content = f.read()

    brand_map = get_reference_brand_map()
    score, matched = match_dom_against_brands(dom_content, brand_map)
    assert matched == "paypal"
    assert score >= 0.60


def test_paypal_waf_interstitial_dom():
    dom_path = os.path.join(REF_PAYPAL_DIR, "interstitial_waf.html")
    assert os.path.exists(dom_path)
    with open(dom_path, "r", encoding="utf-8") as f:
        dom_content = f.read()

    brand_map = get_reference_brand_map()
    score, matched = match_dom_against_brands(dom_content, brand_map)
    assert matched == "paypal"
    assert "You have been blocked" in dom_content
    assert "security challenge" in dom_content


def test_paypal_real_screenshot_visual_embedding_index():
    scr_path = os.path.join(REF_PAYPAL_DIR, "screenshot.png")
    assert os.path.exists(scr_path)

    index = BrandVisualEmbeddingIndex()
    sim, matched = index.match(scr_path, threshold=0.50)
    assert matched == "paypal"
    assert sim >= 0.90
