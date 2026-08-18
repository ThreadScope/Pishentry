import os
import json
import pytest
import numpy as np
from app.fusion import FusionClassifier, extract_fusion_feature_vector, FEATURE_NAMES
from app.visual_similarity import VisualEmbedder, ReferenceBrandVisualStore
from app.lexical import analyze_lexical

def test_dataset_json_integrity():
    dataset_path = os.path.join("training", "dataset.json")
    assert os.path.exists(dataset_path), "dataset.json must exist in training/"
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) >= 1000, f"Expected large dataset, got {len(data)} items"
    
    labels = [d["label"] for d in data]
    phish_count = sum(1 for l in labels if l == 1)
    benign_count = sum(1 for l in labels if l == 0)
    assert phish_count > 0 and benign_count > 0, "Dataset must have both classes"
    assert abs(phish_count - benign_count) / len(data) < 0.1, "Dataset should be reasonably balanced"

def test_feature_vector_dimension():
    vec, unavail, conf = extract_fusion_feature_vector(
        url="http://paypa1-secure-login.tk/auth",
        s_lex=0.85,
        s_dom=0.80,
        s_vis=0.90
    )
    assert len(vec) == 23
    assert len(FEATURE_NAMES) == 23
    assert unavail == 0
    assert conf == "full"

def test_trained_model_high_risk_phishing():
    fusion = FusionClassifier("training/model.pkl")
    s_phish, shap_dict, conf = fusion.predict(
        s_lex=0.88,
        s_dom=0.75,
        s_vis=0.92,
        url="http://paypa1-secure-login.tk/auth"
    )
    assert s_phish >= 0.70, f"Expected high risk >= 0.70, got {s_phish}"
    assert conf == "full"
    assert "s_lex" in shap_dict
    assert "s_vis" in shap_dict
    assert "s_dom" in shap_dict
    assert pytest.approx(sum(shap_dict.values()), 0.05) == 1.0

def test_trained_model_canonical_legitimate():
    fusion = FusionClassifier("training/model.pkl")
    s_phish, shap_dict, conf = fusion.predict(
        s_lex=0.02,
        s_dom=0.05,
        s_vis=0.05,
        url="https://paypal.com/signin"
    )
    assert s_phish < 0.35, f"Expected low risk < 0.35, got {s_phish}"
    assert conf == "full"

def test_sample_brand_targetlist_indexing():
    embedder = VisualEmbedder()
    store = ReferenceBrandVisualStore(embedder)
    store.load_sample_brand_targetlists(max_brands=10)
    assert len(store.brand_embeddings) > 0, "Visual store should load reference brands from sample targetlists"
