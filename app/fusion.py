import os
import pickle
import logging
from typing import Tuple, Dict, Optional
import numpy as np

try:
    import xgboost as xgb
    import shap
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

logger = logging.getLogger(__name__)

FEATURE_NAMES = ["s_lex", "s_dom", "s_vis", "visual_unavailable", "max_similarity"]

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
        Builds and trains a default XGBoost model on representative synthetic features
        so fusion is immediately operational before offline dataset training runs.
        """
        logger.info("Initializing baseline XGBoost fusion model...")
        if not HAS_XGBOOST:
            logger.warning("XGBoost or SHAP not installed. Fusion classifier will run heuristic fallback.")
            return

        # Generate synthetic training dataset representing phishing fusion logic:
        # High s_lex + high s_vis/s_dom -> Phishing (1)
        # Low s_lex + low s_vis/s_dom -> Legitimate (0)
        # Legitimate domain (low s_lex) even with high s_vis to itself -> Legitimate (0)
        np.random.seed(42)
        N = 500
        
        # Phishing samples: spoofed brand (high s_vis or s_dom) + elevated s_lex
        p_lex = np.random.uniform(0.4, 0.9, N // 2)
        p_dom = np.random.uniform(0.5, 0.95, N // 2)
        p_vis = np.random.uniform(0.6, 0.98, N // 2)
        p_unavail = np.random.choice([0, 1], p=[0.85, 0.15], size=N // 2)
        p_max = np.maximum(p_dom, p_vis)
        y_phish = np.ones(N // 2)

        # Legitimate samples: low s_lex, low similarity to WRONG brands
        l_lex = np.random.uniform(0.0, 0.25, N // 2)
        l_dom = np.random.uniform(0.0, 0.4, N // 2)
        l_vis = np.random.uniform(0.0, 0.4, N // 2)
        l_unavail = np.random.choice([0, 1], p=[0.9, 0.1], size=N // 2)
        l_max = np.maximum(l_dom, l_vis)
        y_legit = np.zeros(N // 2)

        X = np.vstack([
            np.column_stack([p_lex, p_dom, p_vis, p_unavail, p_max]),
            np.column_stack([l_lex, l_dom, l_vis, l_unavail, l_max])
        ])
        y = np.hstack([y_phish, y_legit])

        model = xgb.XGBClassifier(
            n_estimators=50,
            max_depth=3,
            learning_rate=0.1,
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
        s_vis: Optional[float]
    ) -> Tuple[float, Dict[str, float], str]:
        """
        Combines s_lex, s_dom, s_vis into s_phish with SHAP explanation per FR-FUS-01 to FR-FUS-03.
        Handles missing visual/DOM render as confidence="reduced" per System Design §2 and NFR-04.
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

        # If no visual or DOM brand similarity is present, score cleanly follows lexical probability
        if s_dom_val == 0.0 and s_vis_val == 0.0:
            return round(s_lex, 4), {"s_lex": 1.0, "s_dom": 0.0, "s_vis": 0.0}, confidence

        max_sim = max(s_dom_val, s_vis_val)
        features = np.array([[s_lex, s_dom_val, s_vis_val, visual_unavailable, max_sim]], dtype=np.float32)

        if self.model is not None:
            probs = self.model.predict_proba(features)[0]
            s_phish = float(probs[1]) if len(probs) > 1 else float(probs[0])
            
            # SHAP contributions
            shap_dict = {"s_lex": 0.33, "s_dom": 0.33, "s_vis": 0.34}
            if self.explainer is not None:
                try:
                    raw_shap = self.explainer.shap_values(features)
                    
                    # Robust extraction across SHAP versions & types
                    if hasattr(raw_shap, "values"):
                        sv = raw_shap.values
                    else:
                        sv = raw_shap

                    if isinstance(sv, list):
                        sv_arr = sv[1] if len(sv) > 1 else sv[0]
                    else:
                        sv_arr = sv

                    # Ensure sv_arr is 1D vector of length 5
                    sv_1d = np.array(sv_arr).reshape(-1)
                    if len(sv_1d) >= 3:
                        abs_vals = np.abs(sv_1d[:3])
                        total = np.sum(abs_vals)
                        if total > 1e-6:
                            shap_dict = {
                                "s_lex": round(float(abs_vals[0] / total), 4),
                                "s_dom": round(float(abs_vals[1] / total), 4),
                                "s_vis": round(float(abs_vals[2] / total), 4)
                            }
                        else:
                            shap_dict = {"s_lex": 0.4, "s_dom": 0.3, "s_vis": 0.3}
                except Exception as e:
                    logger.warning(f"SHAP explanation computation fallback: {e}")
                    # Proportional fallback
                    denom = s_lex + s_dom_val + s_vis_val + 1e-5
                    shap_dict = {
                        "s_lex": round(float(s_lex / denom), 4),
                        "s_dom": round(float(s_dom_val / denom), 4),
                        "s_vis": round(float(s_vis_val / denom), 4)
                    }

            return round(s_phish, 4), shap_dict, confidence

        else:
            # Fallback heuristic if XGBoost model is missing
            s_phish = 0.5 * s_lex + 0.3 * s_vis_val + 0.2 * s_dom_val
            shap_dict = {"s_lex": 0.5, "s_dom": 0.2, "s_vis": 0.3}
            return round(s_phish, 4), shap_dict, confidence

