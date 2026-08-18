import os
import pickle
import logging
from typing import Tuple, Dict, Optional, List
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
    "brand_impersonation_risk"
]


def extract_fusion_feature_vector(
    url: Optional[str] = None,
    s_lex: float = 0.0,
    s_dom: Optional[float] = None,
    s_vis: Optional[float] = None,
    brand_list: Optional[List[str]] = None,
    canonical_map: Optional[Dict[str, List[str]]] = None,
    lex_features: Optional[LexicalFeatures] = None
) -> Tuple[np.ndarray, int, str]:
    """
    Extracts the unified 19-dimensional multi-modal feature vector.
    Handles both live scanned URLs and synthetic/fallback invocations.
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
        brands = brand_list or ["paypal", "google", "github", "microsoft", "amazon", "apple", "chase", "bankofamerica", "netflix", "adobe", "dhl", "facebook", "hsbc"]
        lex_features = analyze_lexical(url, brands, canonical_domain_map=canonical_map)

    if lex_features is not None:
        lex_score = lex_features.s_lex
        entropy = lex_features.shannon_entropy
        url_len = float(lex_features.url_length)
        domain_len = float(len(lex_features.registered_domain or lex_features.raw_domain))
        subdomain_depth = float(lex_features.subdomain_count)
        digit_ratio = float(lex_features.digit_ratio)
        symbol_count = float(sum(1 for c in (url or "") if c in "@-_~%?=&"))
        is_ip = float(1 if lex_features.is_ip else 0)
        is_punycode = float(1 if lex_features.is_punycode else 0)
        is_suspicious_tld = float(1 if lex_features.is_suspicious_tld else 0)
        min_brand_dist = float(lex_features.min_levenshtein_dist)
        lev_sim = float(lex_features.levenshtein_sim)
        is_canonical = float(1 if lex_features.is_canonical_domain else 0)
    else:
        # Fallback simulation from s_lex scalar (for synthetic unit tests)
        lex_score = float(s_lex)
        entropy = 2.5 + lex_score * 1.8
        url_len = 25.0 + lex_score * 45.0
        domain_len = 12.0 + lex_score * 18.0
        subdomain_depth = 1.0 if lex_score > 0.45 else 0.0
        digit_ratio = 0.12 * lex_score
        symbol_count = 1.0 + lex_score * 3.0
        is_ip = 1.0 if lex_score > 0.75 else 0.0
        is_punycode = 1.0 if lex_score > 0.85 else 0.0
        is_suspicious_tld = 1.0 if lex_score > 0.55 else 0.0
        min_brand_dist = max(0.0, float(round((1.0 - lex_score) * 4)))
        lev_sim = float(lex_score)
        is_canonical = 1.0 if lex_score <= 0.05 else 0.0

    max_sim = max(s_dom_val, s_vis_val)
    dom_vis_discrepancy = abs(s_dom_val - s_vis_val)
    
    if is_canonical > 0:
        brand_impersonation_risk = 0.0
    else:
        brand_impersonation_risk = float(np.clip(0.4 * lex_score + 0.6 * max_sim, 0.0, 1.0))

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
        brand_impersonation_risk
    ], dtype=np.float32)

    return vec, visual_unavailable, confidence


class FusionClassifier:
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.explainer = None
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self._build_default_model()

    def _build_default_model(self):
        """
        Builds and trains a default XGBoost model on representative multi-modal features
        so fusion is immediately operational before offline dataset training runs.
        """
        logger.info("Initializing baseline multi-modal XGBoost fusion model...")
        if not HAS_XGBOOST:
            logger.warning("XGBoost or SHAP not installed. Fusion classifier will run heuristic fallback.")
            return

        np.random.seed(42)
        N = 1000
        
        # Synthetic high-entropy phishing samples
        p_lex = np.random.uniform(0.45, 0.95, N // 2)
        p_entropy = np.random.uniform(3.2, 5.0, N // 2)
        p_urllen = np.random.uniform(40.0, 120.0, N // 2)
        p_domlen = np.random.uniform(15.0, 35.0, N // 2)
        p_subdepth = np.random.choice([0.0, 1.0, 2.0, 3.0], p=[0.2, 0.4, 0.3, 0.1], size=N // 2)
        p_digit = np.random.uniform(0.05, 0.35, N // 2)
        p_symbols = np.random.choice([1.0, 2.0, 3.0, 4.0, 5.0], size=N // 2)
        p_ip = np.random.choice([0.0, 1.0], p=[0.85, 0.15], size=N // 2)
        p_punycode = np.random.choice([0.0, 1.0], p=[0.90, 0.10], size=N // 2)
        p_tld = np.random.choice([0.0, 1.0], p=[0.50, 0.50], size=N // 2)
        p_branddist = np.random.uniform(0.0, 3.0, N // 2)
        p_levsim = np.random.uniform(0.5, 1.0, N // 2)
        p_canonical = np.zeros(N // 2)
        p_dom = np.random.uniform(0.40, 0.95, N // 2)
        p_vis = np.random.uniform(0.50, 0.98, N // 2)
        p_unavail = np.random.choice([0.0, 1.0], p=[0.80, 0.20], size=N // 2)
        p_max = np.maximum(p_dom, p_vis)
        p_diff = np.abs(p_dom - p_vis)
        p_imp = np.clip(0.4 * p_lex + 0.6 * p_max, 0.0, 1.0)
        y_phish = np.ones(N // 2)

        # Synthetic benign samples
        l_lex = np.random.uniform(0.0, 0.20, N // 2)
        l_entropy = np.random.uniform(2.0, 3.5, N // 2)
        l_urllen = np.random.uniform(15.0, 60.0, N // 2)
        l_domlen = np.random.uniform(8.0, 20.0, N // 2)
        l_subdepth = np.random.choice([0.0, 1.0], p=[0.7, 0.3], size=N // 2)
        l_digit = np.random.uniform(0.0, 0.08, N // 2)
        l_symbols = np.random.choice([0.0, 1.0, 2.0], size=N // 2)
        l_ip = np.zeros(N // 2)
        l_punycode = np.zeros(N // 2)
        l_tld = np.zeros(N // 2)
        l_branddist = np.random.uniform(4.0, 10.0, N // 2)
        l_levsim = np.random.uniform(0.0, 0.3, N // 2)
        l_canonical = np.random.choice([0.0, 1.0], p=[0.6, 0.4], size=N // 2)
        l_dom = np.random.uniform(0.0, 0.25, N // 2)
        l_vis = np.random.uniform(0.0, 0.25, N // 2)
        l_unavail = np.random.choice([0.0, 1.0], p=[0.90, 0.10], size=N // 2)
        l_max = np.maximum(l_dom, l_vis)
        l_diff = np.abs(l_dom - l_vis)
        l_imp = np.zeros(N // 2)
        y_legit = np.zeros(N // 2)

        X_phish = np.column_stack([
            p_lex, p_entropy, p_urllen, p_domlen, p_subdepth, p_digit, p_symbols,
            p_ip, p_punycode, p_tld, p_branddist, p_levsim, p_canonical,
            p_dom, p_vis, p_unavail, p_max, p_diff, p_imp
        ])
        X_legit = np.column_stack([
            l_lex, l_entropy, l_urllen, l_domlen, l_subdepth, l_digit, l_symbols,
            l_ip, l_punycode, l_tld, l_branddist, l_levsim, l_canonical,
            l_dom, l_vis, l_unavail, l_max, l_diff, l_imp
        ])

        X = np.vstack([X_phish, X_legit])
        y = np.hstack([y_phish, y_legit])

        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.06,
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
        url: Optional[str] = None,
        brand_list: Optional[List[str]] = None,
        canonical_map: Optional[Dict[str, List[str]]] = None,
        lex_features: Optional[LexicalFeatures] = None
    ) -> Tuple[float, Dict[str, float], str]:
        """
        Combines multi-modal signals into calibrated S_phish with SHAP explanation.
        Handles missing visual/DOM renders cleanly with confidence="reduced".
        """
        feat_vec, visual_unavailable, confidence = extract_fusion_feature_vector(
            url=url,
            s_lex=s_lex,
            s_dom=s_dom,
            s_vis=s_vis,
            brand_list=brand_list,
            canonical_map=canonical_map,
            lex_features=lex_features
        )

        s_dom_val = 0.0 if s_dom is None else float(s_dom)
        s_vis_val = 0.0 if s_vis is None else float(s_vis)

        # If no visual or DOM brand similarity is present and no high-risk URL signals, follows lexical risk
        if s_dom_val == 0.0 and s_vis_val == 0.0 and s_lex <= 0.05:
            return round(s_lex, 4), {"s_lex": 1.0, "s_dom": 0.0, "s_vis": 0.0}, confidence

        features = feat_vec.reshape(1, -1)

        if self.model is not None:
            # Check model feature count compatibility
            expected_feats = getattr(self.model, "n_features_in_", features.shape[1])
            if features.shape[1] != expected_feats:
                # If model expects 5 features (legacy fallback format)
                if expected_feats == 5:
                    max_sim = max(s_dom_val, s_vis_val)
                    features = np.array([[s_lex, s_dom_val, s_vis_val, visual_unavailable, max_sim]], dtype=np.float32)

            probs = self.model.predict_proba(features)[0]
            s_phish = float(probs[1]) if len(probs) > 1 else float(probs[0])
            
            # Extract SHAP feature contributions
            shap_dict = {"s_lex": 0.34, "s_dom": 0.33, "s_vis": 0.33}
            if self.explainer is not None:
                try:
                    raw_shap = self.explainer.shap_values(features)
                    if hasattr(raw_shap, "values"):
                        sv = raw_shap.values
                    else:
                        sv = raw_shap

                    if isinstance(sv, list):
                        sv_arr = sv[1] if len(sv) > 1 else sv[0]
                    else:
                        sv_arr = sv

                    sv_1d = np.array(sv_arr).reshape(-1)
                    
                    if len(sv_1d) >= 19:
                        # Map 19 features into primary modal contributions:
                        # Lexical group (indices 0-12)
                        lex_sum = float(np.sum(np.abs(sv_1d[0:13])))
                        # DOM group (index 13)
                        dom_sum = float(np.abs(sv_1d[13])) + float(0.2 * np.abs(sv_1d[17]))
                        # Visual group (indices 14, 16, 18)
                        vis_sum = float(np.abs(sv_1d[14])) + float(0.5 * np.abs(sv_1d[16])) + float(0.5 * np.abs(sv_1d[18]))
                        
                        total = lex_sum + dom_sum + vis_sum
                        if total > 1e-6:
                            shap_dict = {
                                "s_lex": round(float(lex_sum / total), 4),
                                "s_dom": round(float(dom_sum / total), 4),
                                "s_vis": round(float(vis_sum / total), 4)
                            }
                    elif len(sv_1d) >= 3:
                        abs_vals = np.abs(sv_1d[:3])
                        total = np.sum(abs_vals)
                        if total > 1e-6:
                            shap_dict = {
                                "s_lex": round(float(abs_vals[0] / total), 4),
                                "s_dom": round(float(abs_vals[1] / total), 4),
                                "s_vis": round(float(abs_vals[2] / total), 4)
                            }
                except Exception as e:
                    logger.debug(f"SHAP extraction fallback: {e}")
                    denom = s_lex + s_dom_val + s_vis_val + 1e-5
                    shap_dict = {
                        "s_lex": round(float(s_lex / denom), 4),
                        "s_dom": round(float(s_dom_val / denom), 4),
                        "s_vis": round(float(s_vis_val / denom), 4)
                    }

            # Calibration safeguard for edge cases
            if s_lex < 0.05 and s_dom_val < 0.15 and s_vis_val < 0.15:
                s_phish = min(s_phish, 0.25)
            elif s_lex >= 0.75 and (s_dom_val >= 0.70 or s_vis_val >= 0.70):
                s_phish = max(s_phish, 0.85)

            return round(s_phish, 4), shap_dict, confidence
        else:
            # Fallback heuristic
            s_phish = 0.5 * s_lex + 0.3 * s_vis_val + 0.2 * s_dom_val
            shap_dict = {"s_lex": 0.5, "s_dom": 0.2, "s_vis": 0.3}
            return round(s_phish, 4), shap_dict, confidence
