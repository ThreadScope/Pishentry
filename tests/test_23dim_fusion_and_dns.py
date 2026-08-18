import os
import pytest
import numpy as np
from app.fusion import FusionClassifier, extract_fusion_feature_vector, FEATURE_NAMES
from app.fastflux_tracker import evaluate_fastflux_dns_risk
from app.lexical import analyze_lexical

def test_feature_vector_dimension():
    assert len(FEATURE_NAMES) == 23
    assert "s_dns" in FEATURE_NAMES
    assert "dns_ttl_anomaly" in FEATURE_NAMES
    assert "dns_asn_entropy" in FEATURE_NAMES
    assert "dns_bulletproof_risk" in FEATURE_NAMES

def test_extract_fusion_feature_vector_with_fastflux():
    ff_data = {
        "fast_flux_composite_index": 0.85,
        "ttl_anomaly_score": 1.0,
        "asn_diversity_score": 0.72,
        "max_asn_reputation_risk": 0.90
    }
    vec, unavail, conf = extract_fusion_feature_vector(
        url="https://paypa1-security-check.com/signin",
        s_lex=0.88,
        s_dom=0.75,
        s_vis=0.82,
        fastflux_data=ff_data
    )
    assert len(vec) == 23
    assert unavail == 0
    assert conf == "full"
    assert vec[19] == 0.85 # s_dns
    assert vec[20] == 1.0  # dns_ttl_anomaly
    assert vec[21] == 0.72 # dns_asn_entropy
    assert vec[22] == 0.90 # dns_bulletproof_risk

def test_extract_fusion_feature_canonical_domain():
    vec, unavail, conf = extract_fusion_feature_vector(
        url="https://www.paypal.com/signin",
        s_lex=0.01,
        s_dom=0.95,
        s_vis=0.98,
        brand_list=["paypal"],
        canonical_map={"paypal": ["paypal.com"]}
    )
    assert len(vec) == 23
    assert vec[12] == 1.0 # is_canonical_domain
    assert vec[18] == 0.0 # brand_impersonation_risk should be 0 for canonical
    assert vec[19] <= 0.05 # s_dns low for canonical

def test_fusion_model_prediction_and_shap():
    classifier = FusionClassifier()
    assert classifier.model is not None

    ff_phish = {
        "fast_flux_composite_index": 0.88,
        "ttl_anomaly_score": 1.0,
        "asn_diversity_score": 0.75,
        "max_asn_reputation_risk": 0.85
    }
    prob, shap_dict, conf = classifier.predict(
        s_lex=0.92,
        s_dom=0.85,
        s_vis=0.90,
        s_dns=0.88,
        url="http://paypal-verification-account.online/login",
        fastflux_data=ff_phish
    )
    assert prob >= 0.85
    assert conf == "full"
    assert "s_lex" in shap_dict
    assert "s_dom" in shap_dict
    assert "s_vis" in shap_dict
    assert "s_dns" in shap_dict
    assert sum(shap_dict.values()) > 0.95

def test_detailed_feature_importance():
    classifier = FusionClassifier()
    ff_data = {
        "fast_flux_composite_index": 0.78,
        "ttl_anomaly_score": 1.0,
        "asn_diversity_score": 0.65,
        "max_asn_reputation_risk": 0.80
    }
    vec, _, _ = extract_fusion_feature_vector(
        url="http://security-update-chase.com/verify",
        s_lex=0.85,
        s_dom=0.70,
        s_vis=0.75,
        fastflux_data=ff_data
    )
    importances = classifier.get_detailed_feature_importance(vec)
    assert isinstance(importances, list)
    assert len(importances) == 23
    # Sorted by absolute SHAP importance
    for item in importances:
        assert "feature_name" in item
        assert "shap_importance" in item
        assert "direction" in item
