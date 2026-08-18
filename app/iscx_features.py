"""
app/iscx_features.py
====================
79-Dimensional ISCX-URL2016 Feature Extractor & Multi-Model Ensemble Engine.

Extracts all 79 discriminative lexical/URL features and evaluates them against
the trained Logistic Regression, Random Forest, and Support Vector Machine (SVM + Scaler) models.
"""

import re
import math
import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import joblib

logger = logging.getLogger(__name__)

FEATURE_NAMES_79: List[str] = [
    'Querylength', 'domain_token_count', 'path_token_count', 'avgdomaintokenlen',
    'longdomaintokenlen', 'avgpathtokenlen', 'tld', 'charcompvowels',
    'charcompace', 'ldl_url', 'ldl_domain', 'ldl_path', 'ldl_filename',
    'ldl_getArg', 'dld_url', 'dld_domain', 'dld_path', 'dld_filename',
    'dld_getArg', 'urlLen', 'domainlength', 'pathLength', 'subDirLen',
    'fileNameLen', 'this.fileExtLen', 'ArgLen', 'pathurlRatio', 'ArgUrlRatio',
    'argDomanRatio', 'domainUrlRatio', 'pathDomainRatio', 'argPathRatio',
    'executable', 'isPortEighty', 'NumberofDotsinURL', 'ISIpAddressInDomainName',
    'CharacterContinuityRate', 'LongestVariableValue', 'URL_DigitCount',
    'host_DigitCount', 'Directory_DigitCount', 'File_name_DigitCount',
    'Extension_DigitCount', 'Query_DigitCount', 'URL_Letter_Count',
    'host_letter_count', 'Directory_LetterCount', 'Filename_LetterCount',
    'Extension_LetterCount', 'Query_LetterCount', 'LongestPathTokenLength',
    'Domain_LongestWordLength', 'Path_LongestWordLength',
    'sub-Directory_LongestWordLength', 'Arguments_LongestWordLength',
    'URL_sensitiveWord', 'URLQueries_variable', 'spcharUrl', 'delimeter_Domain',
    'delimeter_path', 'delimeter_Count', 'NumberRate_URL', 'NumberRate_Domain',
    'NumberRate_DirectoryName', 'NumberRate_FileName', 'NumberRate_Extension',
    'NumberRate_AfterPath', 'SymbolCount_URL', 'SymbolCount_Domain',
    'SymbolCount_Directoryname', 'SymbolCount_FileName',
    'SymbolCount_Extension', 'SymbolCount_Afterpath', 'Entropy_URL',
    'Entropy_Domain', 'Entropy_DirectoryName', 'Entropy_Filename',
    'Entropy_Extension', 'Entropy_Afterpath'
]

SENSITIVE_WORDS = [
    "login", "signin", "update", "secure", "bank", "account", "verify",
    "password", "confirm", "auth", "admin", "wallet", "support", "billing"
]

SPECIAL_CHARS = r"!@#$%^&*()_+=-[]{}|;:'\",.<>?/"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 4)


def _longest_consecutive(s: str, char_type: str = "alpha") -> int:
    if not s:
        return 0
    pattern = r"[a-zA-Z]+" if char_type == "alpha" else r"[0-9]+"
    matches = re.findall(pattern, s)
    return max((len(m) for m in matches), default=0)


def _longest_word(s: str) -> int:
    if not s:
        return 0
    words = re.findall(r"[a-zA-Z0-9]+", s)
    return max((len(w) for w in words), default=0)


def _count_continuity_rate(s: str) -> float:
    if not s:
        return 0.0
    max_alpha = _longest_consecutive(s, "alpha")
    max_digit = _longest_consecutive(s, "digit")
    return round(max(max_alpha, max_digit) / max(1, len(s)), 4)


def _extract_iscx_feature_dict(url: str) -> Dict[str, float]:
    """
    Extracts the 79-dimensional ISCXURL feature dictionary from a candidate URL string.
    """
    if not url.startswith(("http://", "https://")):
        url_parsed = urlparse("http://" + url)
    else:
        url_parsed = urlparse(url)

    host = url_parsed.netloc.split(":")[0].lower()
    port = url_parsed.port
    path = url_parsed.path or "/"
    query = url_parsed.query or ""
    
    # Path components
    path_parts = [p for p in path.split("/") if p]
    filename = path_parts[-1] if path_parts and "." in path_parts[-1] else ""
    extension = filename.split(".")[-1] if "." in filename else ""
    directory = "/".join(path_parts[:-1]) if filename else path

    # Domain tokens
    domain_tokens = [t for t in re.split(r"[.\-_]", host) if t]
    path_tokens = [t for t in re.split(r"[/.\-_]", path) if t]

    # Query variables
    query_vars = query.split("&") if query else []
    query_vals = [v.split("=")[-1] for v in query_vars if "=" in v]
    longest_var_val = max((len(v) for v in query_vals), default=0)

    # Calculate basic lengths
    url_len = len(url)
    dom_len = len(host)
    path_len = len(path)
    dir_len = len(directory)
    file_len = len(filename)
    ext_len = len(extension)
    arg_len = len(query)

    # Letter and Digit counts
    url_digits = sum(1 for c in url if c.isdigit())
    host_digits = sum(1 for c in host if c.isdigit())
    dir_digits = sum(1 for c in directory if c.isdigit())
    file_digits = sum(1 for c in filename if c.isdigit())
    ext_digits = sum(1 for c in extension if c.isdigit())
    query_digits = sum(1 for c in query if c.isdigit())

    url_letters = sum(1 for c in url if c.isalpha())
    host_letters = sum(1 for c in host if c.isalpha())
    dir_letters = sum(1 for c in directory if c.isalpha())
    file_letters = sum(1 for c in filename if c.isalpha())
    ext_letters = sum(1 for c in extension if c.isalpha())
    query_letters = sum(1 for c in query if c.isalpha())

    # Symbols & Delimiters
    spchar_url = sum(1 for c in url if c in SPECIAL_CHARS)
    delim_domain = sum(1 for c in host if c in ".-_")
    delim_path = sum(1 for c in path if c in "/.-_")
    delim_count = delim_domain + delim_path

    sym_url = sum(1 for c in url if not c.isalnum())
    sym_dom = sum(1 for c in host if not c.isalnum())
    sym_dir = sum(1 for c in directory if not c.isalnum())
    sym_file = sum(1 for c in filename if not c.isalnum())
    sym_ext = sum(1 for c in extension if not c.isalnum())
    sym_afterpath = sum(1 for c in query if not c.isalnum())

    # Sensitive words
    sensitive_count = sum(1 for w in SENSITIVE_WORDS if w in url.lower())

    # IP detection
    is_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) else 0

    # Executable flag
    is_exe = 1 if extension.lower() in ["exe", "bat", "cmd", "sh", "vbs", "js", "msi"] else 0

    # Build 79-feature dictionary
    feat_dict: Dict[str, float] = {
        'Querylength': float(arg_len),
        'domain_token_count': float(len(domain_tokens)),
        'path_token_count': float(len(path_tokens)),
        'avgdomaintokenlen': float(np.mean([len(t) for t in domain_tokens])) if domain_tokens else 0.0,
        'longdomaintokenlen': float(max((len(t) for t in domain_tokens), default=0)),
        'avgpathtokenlen': float(np.mean([len(t) for t in path_tokens])) if path_tokens else 0.0,
        'tld': float(len(host.split('.')[-1])) if '.' in host else 0.0,
        'charcompvowels': float(sum(1 for c in url.lower() if c in "aeiou")),
        'charcompace': float(sum(1 for c in url.lower() if c in "ace")),
        'ldl_url': float(_longest_consecutive(url, "alpha")),
        'ldl_domain': float(_longest_consecutive(host, "alpha")),
        'ldl_path': float(_longest_consecutive(path, "alpha")),
        'ldl_filename': float(_longest_consecutive(filename, "alpha")),
        'ldl_getArg': float(_longest_consecutive(query, "alpha")),
        'dld_url': float(_longest_consecutive(url, "digit")),
        'dld_domain': float(_longest_consecutive(host, "digit")),
        'dld_path': float(_longest_consecutive(path, "digit")),
        'dld_filename': float(_longest_consecutive(filename, "digit")),
        'dld_getArg': float(_longest_consecutive(query, "digit")),
        'urlLen': float(url_len),
        'domainlength': float(dom_len),
        'pathLength': float(path_len),
        'subDirLen': float(dir_len),
        'fileNameLen': float(file_len),
        'this.fileExtLen': float(ext_len),
        'ArgLen': float(arg_len),
        'pathurlRatio': float(path_len / max(1, url_len)),
        'ArgUrlRatio': float(arg_len / max(1, url_len)),
        'argDomanRatio': float(arg_len / max(1, dom_len)),
        'domainUrlRatio': float(dom_len / max(1, url_len)),
        'pathDomainRatio': float(path_len / max(1, dom_len)),
        'argPathRatio': float(arg_len / max(1, path_len)),
        'executable': float(is_exe),
        'isPortEighty': 1.0 if port == 80 else 0.0,
        'NumberofDotsinURL': float(url.count(".")),
        'ISIpAddressInDomainName': float(is_ip),
        'CharacterContinuityRate': float(_count_continuity_rate(url)),
        'LongestVariableValue': float(longest_var_val),
        'URL_DigitCount': float(url_digits),
        'host_DigitCount': float(host_digits),
        'Directory_DigitCount': float(dir_digits),
        'File_name_DigitCount': float(file_digits),
        'Extension_DigitCount': float(ext_digits),
        'Query_DigitCount': float(query_digits),
        'URL_Letter_Count': float(url_letters),
        'host_letter_count': float(host_letters),
        'Directory_LetterCount': float(dir_letters),
        'Filename_LetterCount': float(file_letters),
        'Extension_LetterCount': float(ext_letters),
        'Query_LetterCount': float(query_letters),
        'LongestPathTokenLength': float(max((len(t) for t in path_tokens), default=0)),
        'Domain_LongestWordLength': float(_longest_word(host)),
        'Path_LongestWordLength': float(_longest_word(path)),
        'sub-Directory_LongestWordLength': float(_longest_word(directory)),
        'Arguments_LongestWordLength': float(_longest_word(query)),
        'URL_sensitiveWord': float(sensitive_count),
        'URLQueries_variable': float(len(query_vars)),
        'spcharUrl': float(spchar_url),
        'delimeter_Domain': float(delim_domain),
        'delimeter_path': float(delim_path),
        'delimeter_Count': float(delim_count),
        'NumberRate_URL': float(url_digits / max(1, url_len)),
        'NumberRate_Domain': float(host_digits / max(1, dom_len)),
        'NumberRate_DirectoryName': float(dir_digits / max(1, dir_len)),
        'NumberRate_FileName': float(file_digits / max(1, file_len)),
        'NumberRate_Extension': float(ext_digits / max(1, ext_len)),
        'NumberRate_AfterPath': float((ext_digits + query_digits) / max(1, file_len + arg_len)),
        'SymbolCount_URL': float(sym_url),
        'SymbolCount_Domain': float(sym_dom),
        'SymbolCount_Directoryname': float(sym_dir),
        'SymbolCount_FileName': float(sym_file),
        'SymbolCount_Extension': float(sym_ext),
        'SymbolCount_Afterpath': float(sym_afterpath),
        'Entropy_URL': float(_shannon_entropy(url)),
        'Entropy_Domain': float(_shannon_entropy(host)),
        'Entropy_DirectoryName': float(_shannon_entropy(directory)),
        'Entropy_Filename': float(_shannon_entropy(filename)),
        'Entropy_Extension': float(_shannon_entropy(extension)),
        'Entropy_Afterpath': float(_shannon_entropy(query))
    }

    return feat_dict


def extract_iscx_79_features_df(url: str) -> pd.DataFrame:
    """
    Extracts the 79-dimensional ISCXURL feature vector as a pandas DataFrame.
    """
    feat_dict = _extract_iscx_feature_dict(url)
    return pd.DataFrame([feat_dict], columns=FEATURE_NAMES_79)


def extract_iscx_79_features(url: str, as_df: bool = False) -> Any:
    """
    Extracts the 79-dimensional ISCXURL feature vector.
    Returns 1D numpy array of length 79 by default (or pd.DataFrame if as_df=True).
    """
    df = extract_iscx_79_features_df(url)
    if as_df:
        return df
    return df.iloc[0].to_numpy(dtype=np.float64)


class ISCXModelEnsemble:
    """
    Multi-model ensemble executing Logistic Regression, Random Forest,
    and Support Vector Machine (SVM + Scaler) over the 79-dimensional feature space.
    """
    def __init__(self, samples_dir: str = "samples"):
        self.logistic_model = None
        self.rf_model = None
        self.svm_scaler = None
        self.svm_model = None
        self._load_models(samples_dir)

    def _load_models(self, samples_dir: str):
        lr_path = os.path.join(samples_dir, "logistic_model.pkl")
        rf_path = os.path.join(samples_dir, "random_forest_model.pkl")
        scaler_path = os.path.join(samples_dir, "svm_scaler.pkl")
        svm_path = os.path.join(samples_dir, "svm_mlflow.pkl")

        # Fallback paths in tests/ and training/
        if not os.path.exists(lr_path):
            lr_path = "training/logistic_model.pkl"
        if not os.path.exists(rf_path):
            rf_path = "tests/random_forest_model.pkl"
        if not os.path.exists(scaler_path):
            scaler_path = "tests/svm_scaler.pkl"
        if not os.path.exists(svm_path):
            svm_path = "tests/svm_mlflow.pkl"

        try:
            if os.path.exists(lr_path):
                self.logistic_model = joblib.load(lr_path)
                logger.info(f"Loaded Logistic Regression model from {lr_path}")
        except Exception as e:
            logger.warning(f"Could not load Logistic model: {e}")

        try:
            if os.path.exists(rf_path):
                self.rf_model = joblib.load(rf_path)
                logger.info(f"Loaded Random Forest model from {rf_path}")
        except Exception as e:
            logger.warning(f"Could not load Random Forest model: {e}")

        try:
            if os.path.exists(scaler_path):
                self.svm_scaler = joblib.load(scaler_path)
                logger.info(f"Loaded SVM StandardScaler from {scaler_path}")
        except Exception as e:
            logger.warning(f"Could not load SVM scaler: {e}")

        try:
            if os.path.exists(svm_path):
                self.svm_model = joblib.load(svm_path)
                logger.info(f"Loaded SVM model from {svm_path}")
        except Exception as e:
            logger.warning(f"Could not load SVM model: {e}")

    def evaluate_url(self, url: str) -> Dict[str, Any]:
        """
        Extracts 79 features and returns predictions from all active models.
        """
        df_feats = extract_iscx_79_features_df(url)
        results = {
            "logistic_regression_score": 0.0,
            "random_forest_score": 0.0,
            "svm_decision": 0,
            "ensemble_phish_score": 0.0,
            "feature_vector_dim": 79
        }

        p_lr = 0.0
        p_rf = 0.0
        p_svm = 0.0

        if self.logistic_model is not None:
            try:
                p_lr = float(self.logistic_model.predict_proba(df_feats)[0][1])
                results["logistic_regression_score"] = round(p_lr, 4)
            except Exception as e:
                logger.debug(f"Logistic predict error: {e}")

        if self.rf_model is not None:
            try:
                p_rf = float(self.rf_model.predict_proba(df_feats)[0][1])
                results["random_forest_score"] = round(p_rf, 4)
            except Exception as e:
                logger.debug(f"RF predict error: {e}")

        if self.svm_model is not None and self.svm_scaler is not None:
            try:
                scaled = self.svm_scaler.transform(df_feats)
                svm_pred = int(self.svm_model.predict(scaled)[0])
                results["svm_decision"] = svm_pred
                p_svm = 1.0 if svm_pred == 1 else 0.0
            except Exception as e:
                logger.debug(f"SVM predict error: {e}")

        # Calibrated weighted ensemble
        scores = []
        weights = []
        if self.rf_model is not None:
            scores.append(p_rf)
            weights.append(0.45)
        if self.svm_model is not None:
            scores.append(p_svm)
            weights.append(0.35)
        if self.logistic_model is not None:
            scores.append(p_lr)
            weights.append(0.20)

        if scores:
            total_w = sum(weights)
            ens = sum(s * w for s, w in zip(scores, weights)) / total_w
            results["ensemble_phish_score"] = round(ens, 4)
        else:
            results["ensemble_phish_score"] = 0.50

        return results

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Alias for evaluate_url with normalized probability keys.
        """
        res = self.evaluate_url(url)
        return {
            "lr_prob": res["logistic_regression_score"],
            "rf_prob": res["random_forest_score"],
            "svm_pred": res["svm_decision"],
            "ensemble_score": res["ensemble_phish_score"],
            **res
        }

