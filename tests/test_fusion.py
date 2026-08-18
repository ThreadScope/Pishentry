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


def test_iscx_79_feature_vector_extraction():
    from app.iscx_features import extract_iscx_79_features, FEATURE_NAMES_79
    url = "http://paypal-security-update.xyz/login?id=99283"
    df = extract_iscx_79_features(url, as_df=True)
    assert df.shape == (1, 79)
    assert list(df.columns) == FEATURE_NAMES_79
    assert df["urlLen"].iloc[0] == len(url)
    assert df["Entropy_URL"].iloc[0] > 3.0
    assert df["URL_sensitiveWord"].iloc[0] >= 1


def test_iscx_model_ensemble_prediction():
    from app.iscx_features import ISCXModelEnsemble
    ensemble = ISCXModelEnsemble(samples_dir="samples")
    res = ensemble.evaluate_url("http://paypal-security-update.xyz/login?id=99283")
    assert "logistic_regression_score" in res
    assert "random_forest_score" in res
    assert "svm_decision" in res
    assert "ensemble_phish_score" in res
    assert res["feature_vector_dim"] == 79


