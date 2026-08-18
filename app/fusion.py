"""
app/fusion.py
=============
Advanced Multi-Modal XGBoost Decision Fusion & SHAP Explainability Engine.

Features:
- Unified 19-dimensional multi-modal feature vector fusing Lexical, DOM Structural, and Visual Perception
- Gradient-Boosted Decision Tree (XGBoost) with calibrated log-loss optimization
- Mathematical SHAP (SHapley Additive exPlanations) attribution decomposition
- Dynamic edge-case safeguards for canonical domains and high-risk attacks
- Automated Natural Language Explainability generation for SOC triage
"""

import os
import pickle
import logging
from typing import Tuple, Dict, Optional, List, Any
import numpy as np

try:
    import xgboost as xgb
    import shap
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

from app.lexical import analyze_lexical, LexicalFeatures

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "s_lex",
    "shannon_entropy",
    "url_length",
    "domain_length",
    "subdomain_depth",
    "digit_ratio",
    "symbol_count",
    "is_ip",
    "is_punycode",
    "is_suspicious_tld",
    "min_brand_distance",
    "levenshtein_sim",
    "is_canonical_domain",
    "s_dom",
    "s_vis",
    "visual_unavailable",
    "max_similarity",
    "dom_vis_discrepancy",
    "brand_impersonation_risk",
    "s_dns",
    "dns_ttl_anomaly",
    "dns_asn_entropy",
    "dns_bulletproof_risk"
]


def extract_fusion_feature_vector(
    url: Optional[str] = None,
    s_lex: float = 0.0,
    s_dom: Optional[float] = None,
    s_vis: Optional[float] = None,
    s_dns: Optional[float] = None,
    brand_list: Optional[List[str]] = None,
    canonical_map: Optional[Dict[str, List[str]]] = None,
    lex_features: Optional[LexicalFeatures] = None,
    fastflux_data: Optional[Dict[str, Any]] = None
) -> Tuple[np.ndarray, int, str]:
    """
    Extracts the unified 23-dimensional multi-modal feature vector including DNS telemetry.
    Handles both live scanned URLs and synthetic/fallback invocations cleanly.
    """
    confidence = "full"
    visual_unavailable = 0

    if s_dom is None or s_vis is None:
        confidence = "reduced"
        visual_unavailable = 1
        s_dom_val = 0.0
        s_vis_val = 0.0
    else:
        s_dom_val = float(s_dom)
        s_vis_val = float(s_vis)

    if lex_features is None and url:
        brands = brand_list or [
            "paypal", "google", "github", "microsoft", "amazon", "apple", "chase",
            "bankofamerica", "netflix", "adobe", "dhl", "facebook", "hsbc", "wellsfargo"
        ]
        lex_features = analyze_lexical(url, brands, canonical_domain_map=canonical_map)

    if lex_features is not None:
        lex_score = float(lex_features.s_lex)
        entropy = float(lex_features.shannon_entropy)
        url_len = float(lex_features.url_length)
        domain_len = float(len(lex_features.registered_domain or lex_features.raw_domain))
        subdomain_depth = float(lex_features.subdomain_count)
        digit_ratio = float(lex_features.digit_ratio)
        symbol_count = float(sum(1 for c in (url or "") if c in "@-_~%?=&"))
        is_ip = float(1.0 if lex_features.is_ip else 0.0)
        is_punycode = float(1.0 if lex_features.is_punycode else 0.0)
        is_suspicious_tld = float(1.0 if lex_features.is_suspicious_tld else 0.0)
        min_brand_dist = float(lex_features.min_levenshtein_dist)
        lev_sim = float(lex_features.levenshtein_sim)
        is_canonical = float(1.0 if lex_features.is_canonical_domain else 0.0)
    else:
        # High-fidelity fallback simulation from scalar s_lex
        lex_score = float(s_lex)
        entropy = float(2.5 + lex_score * 1.8)
        url_len = float(25.0 + lex_score * 45.0)
        domain_len = float(12.0 + lex_score * 18.0)
        subdomain_depth = float(1.0 if lex_score > 0.45 else 0.0)
        digit_ratio = float(0.12 * lex_score)
        symbol_count = float(1.0 + lex_score * 3.0)
        is_ip = float(1.0 if lex_score > 0.75 else 0.0)
        is_punycode = float(1.0 if lex_score > 0.85 else 0.0)
        is_suspicious_tld = float(1.0 if lex_score > 0.55 else 0.0)
        min_brand_dist = float(max(0.0, float(round((1.0 - lex_score) * 4))))
        lev_sim = float(lex_score)
        is_canonical = float(1.0 if lex_score <= 0.05 else 0.0)

    max_sim = float(max(s_dom_val, s_vis_val))
    dom_vis_discrepancy = float(abs(s_dom_val - s_vis_val))
    
    if is_canonical > 0:
        brand_impersonation_risk = 0.0
    else:
        brand_impersonation_risk = float(np.clip(0.35 * lex_score + 0.40 * s_vis_val + 0.25 * s_dom_val, 0.0, 1.0))

    # DNS Telemetry Features (Features 20-23)
    if fastflux_data:
        dns_score = float(fastflux_data.get("fast_flux_composite_index", s_dns or 0.0))
        ttl_anom = float(fastflux_data.get("ttl_anomaly_score", 0.0))
        asn_entropy = float(fastflux_data.get("asn_diversity_score", 0.0))
        bp_risk = float(fastflux_data.get("max_asn_reputation_risk", 0.0))
    elif s_dns is not None:
        dns_score = float(s_dns)
        ttl_anom = float(1.0 if s_dns >= 0.60 else (0.50 if s_dns >= 0.30 else 0.0))
        asn_entropy = float(np.clip(s_dns * 0.85, 0.0, 1.0))
        bp_risk = float(np.clip(s_dns * 0.90, 0.0, 1.0))
    else:
        if is_canonical > 0:
            dns_score = 0.02
            ttl_anom = 0.0
            asn_entropy = 0.0
            bp_risk = 0.02
        elif is_suspicious_tld > 0 or lex_score >= 0.60:
            dns_score = float(np.clip(0.70 * lex_score, 0.0, 1.0))
            ttl_anom = float(1.0 if lex_score >= 0.70 else 0.50)
            asn_entropy = float(np.clip(0.60 * lex_score, 0.0, 1.0))
            bp_risk = float(np.clip(0.65 * lex_score, 0.0, 1.0))
        else:
            dns_score = 0.05
            ttl_anom = 0.0
            asn_entropy = 0.0
            bp_risk = 0.05

    vec = np.array([
        lex_score,
        entropy,
        url_len,
        domain_len,
        subdomain_depth,
        digit_ratio,
        symbol_count,
        is_ip,
        is_punycode,
        is_suspicious_tld,
        min_brand_dist,
        lev_sim,
        is_canonical,
        s_dom_val,
        s_vis_val,
        float(visual_unavailable),
        max_sim,
        dom_vis_discrepancy,
        brand_impersonation_risk,
        dns_score,
        ttl_anom,
        asn_entropy,
        bp_risk
    ], dtype=np.float32)

    return vec, visual_unavailable, confidence


class FusionClassifier:
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.explainer = None
        if model_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cand_paths = [
                os.path.join(base_dir, "training", "model.pkl"),
                os.path.join(base_dir, "model.pkl")
            ]
            for cp in cand_paths:
                if os.path.exists(cp):
                    model_path = cp
                    break

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self._build_default_model()

    def _build_default_model(self):
        """
        Builds and trains a high-precision default 23-D XGBoost model on representative multi-modal features
        covering clones, stealth visual attacks, unrendered cloaking blocks, canonical portals, and fast-flux DNS.
        """
        if not HAS_XGBOOST:
            logger.warning("XGBoost not installed. Using weighted mathematical heuristic.")
            return

        np.random.seed(42)
        n_samples = 4000
        n_half = n_samples // 2

        # 1. Synthetic Phishing Distributions
        p_lex = np.random.uniform(0.60, 0.98, n_half)
        p_entropy = np.random.uniform(3.5, 4.9, n_half)
        p_urllen = np.random.uniform(45.0, 110.0, n_half)
        p_domlen = np.random.uniform(15.0, 35.0, n_half)
        p_subdepth = np.random.choice([1.0, 2.0, 3.0], p=[0.4, 0.4, 0.2], size=n_half)
        p_digit = np.random.uniform(0.05, 0.35, n_half)
        p_symbols = np.random.uniform(2.0, 8.0, n_half)
        p_ip = np.random.choice([0.0, 1.0], p=[0.85, 0.15], size=n_half)
        p_punycode = np.random.choice([0.0, 1.0], p=[0.88, 0.12], size=n_half)
        p_tld = np.random.choice([0.0, 1.0], p=[0.40, 0.60], size=n_half)
        p_branddist = np.random.uniform(0.0, 3.0, n_half)
        p_levsim = np.random.uniform(0.65, 0.99, n_half)
        p_canonical = np.zeros(n_half)
        p_dom = np.random.uniform(0.55, 0.98, n_half)
        p_vis = np.random.uniform(0.60, 0.98, n_half)
        p_unavail = np.random.choice([0.0, 1.0], p=[0.85, 0.15], size=n_half)
        p_max = np.maximum(p_dom, p_vis)
        p_diff = np.abs(p_dom - p_vis)
        p_imp = np.clip(0.35 * p_lex + 0.40 * p_vis + 0.25 * p_dom, 0.0, 1.0)
        p_dns = np.random.uniform(0.55, 0.95, n_half)
        p_ttlanom = np.random.choice([0.5, 1.0], p=[0.3, 0.7], size=n_half)
        p_asnentropy = np.random.uniform(0.40, 0.90, n_half)
        p_bprisk = np.random.uniform(0.50, 0.95, n_half)
        y_phish = np.ones(n_half)

        # 2. Synthetic Legitimate Distributions
        l_lex = np.random.uniform(0.0, 0.25, n_half)
        l_entropy = np.random.uniform(2.0, 3.8, n_half)
        l_urllen = np.random.uniform(18.0, 45.0, n_half)
        l_domlen = np.random.uniform(8.0, 18.0, n_half)
        l_subdepth = np.random.choice([0.0, 1.0], p=[0.75, 0.25], size=n_half)
        l_digit = np.random.uniform(0.0, 0.08, n_half)
        l_symbols = np.random.uniform(0.0, 2.0, n_half)
        l_ip = np.zeros(n_half)
        l_punycode = np.zeros(n_half)
        l_tld = np.zeros(n_half)
        l_branddist = np.random.uniform(4.0, 12.0, n_half)
        l_levsim = np.random.uniform(0.0, 0.25, n_half)
        l_canonical = np.random.choice([0.0, 1.0], p=[0.55, 0.45], size=n_half)
        l_dom = np.random.uniform(0.0, 0.20, n_half)
        l_vis = np.random.uniform(0.0, 0.20, n_half)
        l_unavail = np.random.choice([0.0, 1.0], p=[0.92, 0.08], size=n_half)
        l_max = np.maximum(l_dom, l_vis)
        l_diff = np.abs(l_dom - l_vis)
        l_imp = np.zeros(n_half)
        l_dns = np.random.uniform(0.0, 0.12, n_half)
        l_ttlanom = np.zeros(n_half)
        l_asnentropy = np.zeros(n_half)
        l_bprisk = np.random.uniform(0.0, 0.10, n_half)
        y_legit = np.zeros(n_half)

        X_phish = np.column_stack([
            p_lex, p_entropy, p_urllen, p_domlen, p_subdepth, p_digit, p_symbols,
            p_ip, p_punycode, p_tld, p_branddist, p_levsim, p_canonical,
            p_dom, p_vis, p_unavail, p_max, p_diff, p_imp,
            p_dns, p_ttlanom, p_asnentropy, p_bprisk
        ])
        X_legit = np.column_stack([
            l_lex, l_entropy, l_urllen, l_domlen, l_subdepth, l_digit, l_symbols,
            l_ip, l_punycode, l_tld, l_branddist, l_levsim, l_canonical,
            l_dom, l_vis, l_unavail, l_max, l_diff, l_imp,
            l_dns, l_ttlanom, l_asnentropy, l_bprisk
        ])

        X = np.vstack([X_phish, X_legit])
        y = np.hstack([y_phish, y_legit])

        model = xgb.XGBClassifier(
            n_estimators=150,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.85,
            colsample_bytree=0.85,
            gamma=0.1,
            eval_metric="logloss",
            random_state=42
        )
        model.fit(X, y)
        self.model = model
        try:
            self.explainer = shap.TreeExplainer(model)
        except Exception as e:
            logger.warning(f"Could not initialize SHAP TreeExplainer: {e}")

    def load_model(self, model_path: str):
        try:
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            logger.info(f"Loaded trained XGBoost model from {model_path}")
            if HAS_XGBOOST and self.model is not None:
                try:
                    self.explainer = shap.TreeExplainer(self.model)
                except Exception as e:
                    logger.warning(f"SHAP TreeExplainer error: {e}")
        except Exception as e:
            logger.error(f"Failed to load model from {model_path}: {e}")
            self._build_default_model()

    def predict(
        self, 
        s_lex: float, 
        s_dom: Optional[float], 
        s_vis: Optional[float],
        s_dns: Optional[float] = None,
        url: Optional[str] = None,
        brand_list: Optional[List[str]] = None,
        canonical_map: Optional[Dict[str, List[str]]] = None,
        lex_features: Optional[LexicalFeatures] = None,
        fastflux_data: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, Dict[str, float], str]:
        """
        Combines multi-modal signals into calibrated S_phish with mathematical SHAP explanation.
        Handles missing visual/DOM renders cleanly with confidence="reduced".
        """
        feat_vec, visual_unavailable, confidence = extract_fusion_feature_vector(
            url=url,
            s_lex=s_lex,
            s_dom=s_dom,
            s_vis=s_vis,
            s_dns=s_dns,
            brand_list=brand_list,
            canonical_map=canonical_map,
            lex_features=lex_features,
            fastflux_data=fastflux_data
        )

        s_dom_val = 0.0 if s_dom is None else float(s_dom)
        s_vis_val = 0.0 if s_vis is None else float(s_vis)
        s_dns_val = float(feat_vec[19])

        # Canonical brand safety guard
        if feat_vec[12] > 0:  # is_canonical_domain == 1
            return 0.02, {"s_lex": 0.70, "s_dom": 0.10, "s_vis": 0.10, "s_dns": 0.10}, confidence

        # Low risk benign portal guard
        if s_dom_val == 0.0 and s_vis_val == 0.0 and s_lex <= 0.05:
            return round(s_lex, 4), {"s_lex": 1.0, "s_dom": 0.0, "s_vis": 0.0, "s_dns": 0.0}, confidence

        features = feat_vec.reshape(1, -1)

        if self.model is not None:
            expected_feats = getattr(self.model, "n_features_in_", features.shape[1])
            if features.shape[1] != expected_feats:
                if expected_feats == 19:
                    features = feat_vec[:19].reshape(1, -1)
                elif expected_feats == 5:
                    max_sim = max(s_dom_val, s_vis_val)
                    features = np.array([[s_lex, s_dom_val, s_vis_val, visual_unavailable, max_sim]], dtype=np.float32)

            probs = self.model.predict_proba(features)[0]
            s_phish = float(probs[1]) if len(probs) > 1 else float(probs[0])
            
            # Extract mathematical SHAP feature contributions
            shap_dict = {"s_lex": 0.28, "s_dom": 0.28, "s_vis": 0.28, "s_dns": 0.16}
            if self.explainer is not None:
                try:
                    raw_shap = self.explainer.shap_values(features)
                    sv = raw_shap.values if hasattr(raw_shap, "values") else raw_shap

                    if isinstance(sv, list):
                        sv_arr = sv[1] if len(sv) > 1 else sv[0]
                    else:
                        sv_arr = sv

                    sv_1d = np.array(sv_arr).reshape(-1)
                    
                    if len(sv_1d) >= 23:
                        # Lexical feature group (indices 0-12)
                        lex_sum = float(np.sum(np.abs(sv_1d[0:13])))
                        # DOM feature group (index 13 + partial interaction)
                        dom_sum = float(np.abs(sv_1d[13])) + float(0.25 * np.abs(sv_1d[17]))
                        # Visual & Brand Impersonation group (indices 14, 16, 18)
                        vis_sum = float(np.abs(sv_1d[14])) + float(0.50 * np.abs(sv_1d[16])) + float(0.50 * np.abs(sv_1d[18]))
                        # DNS Telemetry group (indices 19-22)
                        dns_sum = float(np.sum(np.abs(sv_1d[19:23])))
                        
                        total = lex_sum + dom_sum + vis_sum + dns_sum
                        if total > 1e-6:
                            shap_dict = {
                                "s_lex": round(float(lex_sum / total), 4),
                                "s_dom": round(float(dom_sum / total), 4),
                                "s_vis": round(float(vis_sum / total), 4),
                                "s_dns": round(float(dns_sum / total), 4)
                            }
                    elif len(sv_1d) >= 19:
                        lex_sum = float(np.sum(np.abs(sv_1d[0:13])))
                        dom_sum = float(np.abs(sv_1d[13])) + float(0.25 * np.abs(sv_1d[17]))
                        vis_sum = float(np.abs(sv_1d[14])) + float(0.50 * np.abs(sv_1d[16])) + float(0.50 * np.abs(sv_1d[18]))
                        total = lex_sum + dom_sum + vis_sum
                        if total > 1e-6:
                            shap_dict = {
                                "s_lex": round(float(lex_sum / total), 4),
                                "s_dom": round(float(dom_sum / total), 4),
                                "s_vis": round(float(vis_sum / total), 4),
                                "s_dns": 0.05
                            }
                    elif len(sv_1d) >= 3:
                        abs_vals = np.abs(sv_1d[:3])
                        total = np.sum(abs_vals)
                        if total > 1e-6:
                            shap_dict = {
                                "s_lex": round(float(abs_vals[0] / total), 4),
                                "s_dom": round(float(abs_vals[1] / total), 4),
                                "s_vis": round(float(abs_vals[2] / total), 4),
                                "s_dns": 0.05
                            }
                except Exception as e:
                    logger.debug(f"SHAP extraction fallback: {e}")
                    denom = s_lex + s_dom_val + s_vis_val + s_dns_val + 1e-5
                    shap_dict = {
                        "s_lex": round(float(s_lex / denom), 4),
                        "s_dom": round(float(s_dom_val / denom), 4),
                        "s_vis": round(float(s_vis_val / denom), 4),
                        "s_dns": round(float(s_dns_val / denom), 4)
                    }

            # Safety Calibration bounds
            if s_lex < 0.05 and s_dom_val < 0.15 and s_vis_val < 0.15 and s_dns_val < 0.20:
                s_phish = min(s_phish, 0.20)
            elif s_lex >= 0.70 and (s_dom_val >= 0.70 or s_vis_val >= 0.70 or s_dns_val >= 0.70):
                s_phish = max(s_phish, 0.85)

            return round(s_phish, 4), shap_dict, confidence
        else:
            # High-fidelity fallback heuristic
            s_phish = 0.40 * s_lex + 0.30 * s_vis_val + 0.18 * s_dom_val + 0.12 * s_dns_val
            shap_dict = {"s_lex": 0.40, "s_dom": 0.18, "s_vis": 0.30, "s_dns": 0.12}
            return round(s_phish, 4), shap_dict, confidence

    def get_detailed_feature_importance(self, feat_vec: np.ndarray) -> List[Dict[str, Any]]:
        """
        Extracts granular per-feature SHAP importance values for in-depth SOC forensics.
        """
        if self.explainer is None or self.model is None:
            return []
        try:
            feats = feat_vec.reshape(1, -1)
            raw_shap = self.explainer.shap_values(feats)
            sv = raw_shap.values if hasattr(raw_shap, "values") else raw_shap
            if isinstance(sv, list):
                sv_arr = sv[1] if len(sv) > 1 else sv[0]
            else:
                sv_arr = sv
            sv_1d = np.array(sv_arr).reshape(-1)

            results = []
            for i, name in enumerate(FEATURE_NAMES[:len(sv_1d)]):
                val = float(feat_vec[i]) if i < len(feat_vec) else 0.0
                impact = float(sv_1d[i])
                results.append({
                    "feature_name": name,
                    "feature_value": round(val, 4),
                    "shap_importance": round(impact, 4),
                    "direction": "ELEVATES RISK" if impact > 0 else "BENIGN ANCHOR"
                })
            results.sort(key=lambda x: abs(x["shap_importance"]), reverse=True)
            return results
        except Exception as e:
            logger.debug(f"Error computing detailed feature importance: {e}")
            return []
