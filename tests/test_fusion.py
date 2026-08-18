import pytest
from app.fusion import FusionClassifier

def test_fusion_high_risk():
    fusion = FusionClassifier()
    s_phish, shap_dict, conf = fusion.predict(s_lex=0.85, s_dom=0.80, s_vis=0.92)
    assert s_phish >= 0.70
    assert conf == "full"
    assert "s_lex" in shap_dict
    assert "s_vis" in shap_dict
    assert "s_dom" in shap_dict
    # Attribution values should sum close to 1.0
    total_shap = sum(shap_dict.values())
    assert pytest.approx(total_shap, 0.05) == 1.0

def test_fusion_low_risk():
    fusion = FusionClassifier()
    s_phish, shap_dict, conf = fusion.predict(s_lex=0.02, s_dom=0.10, s_vis=0.05)
    assert s_phish < 0.45
    assert conf == "full"

def test_fusion_reduced_confidence_fallback():
    fusion = FusionClassifier()
    # When rendering times out (s_dom=None, s_vis=None)
    s_phish, shap_dict, conf = fusion.predict(s_lex=0.80, s_dom=None, s_vis=None)
    assert conf == "reduced"
    assert s_phish > 0.40  # Should still reflect high lexical risk
    assert "s_lex" in shap_dict

