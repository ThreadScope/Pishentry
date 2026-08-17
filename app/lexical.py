import math
import re
from dataclasses import dataclass
from typing import List, Tuple, Optional
import Levenshtein
import tldextract

# List of TLDs statistically associated with high abuse rates
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "buzz", "online",
    "site", "icu", "monster", "club", "info", "top", "cfd", "sbs", "rest", "fit"
}

@dataclass
class LexicalFeatures:
    raw_domain: str
    registered_domain: str
    subdomain: str
    tld: str
    shannon_entropy: float
    min_levenshtein_dist: int
    matched_brand: str
    levenshtein_sim: float
    is_punycode: bool
    is_suspicious_tld: bool
    subdomain_count: int
    has_hyphen: bool
    digit_ratio: float
    url_length: int
    s_lex: float

def compute_shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_domain_parts(url: str) -> Tuple[str, str, str, str]:
    """
    Extracts (raw_domain, registered_domain, subdomain, tld) from a URL without making network calls.
    """
    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "http://" + cleaned_url
        
    ext = tldextract.extract(cleaned_url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ext.domain or ""
    subdomain = ext.subdomain or ""
    tld = ext.suffix or ""
    raw_domain = f"{subdomain}.{registered_domain}".strip(".") if subdomain else registered_domain
    return raw_domain, registered_domain, subdomain, tld

def analyze_lexical(url: str, brand_list: List[str]) -> LexicalFeatures:
    """
    Pure-function lexical analyzer according to FR-LEX-01 to 05.
    No network calls.
    """
    raw_domain, registered_domain, subdomain, tld = extract_domain_parts(url)
    target_string = raw_domain.lower()
    
    # 1. Shannon entropy (FR-LEX-01)
    entropy = compute_shannon_entropy(target_string)
    
    # 2. Levenshtein distance against reference brands (FR-LEX-02)
    min_dist = 999
    best_matched_brand = ""
    max_lev_sim = 0.0
    
    # Extract SLD (second-level domain body, e.g. "paypa1-secure" from "paypa1-secure.tk")
    ext = tldextract.extract(url if url.startswith(("http://", "https://")) else "http://" + url)
    domain_body = ext.domain.lower() if ext.domain else target_string

    # Check domain body, raw domain, and hyphen/dot split tokens (e.g. "paypa1" from "paypa1-secure")
    tokens = [domain_body, target_string] + [t for t in re.split(r'[-._]', domain_body) if t]
    
    for brand in brand_list:
        brand_clean = brand.lower().strip()
        if not brand_clean:
            continue
            
        for tok in tokens:
            if not tok:
                continue
            dist_tok = Levenshtein.distance(tok, brand_clean)
            max_len = max(len(tok), len(brand_clean))
            sim = 1.0 - (dist_tok / max_len) if max_len > 0 else 0.0
            
            if dist_tok < min_dist:
                min_dist = dist_tok
                best_matched_brand = brand_clean
                max_lev_sim = sim
    
    if min_dist == 999:
        min_dist = 0
        best_matched_brand = ""
        max_lev_sim = 0.0

    # 3. Punycode / Homoglyph check (FR-LEX-03)
    is_punycode = "xn--" in target_string.lower() or "xn--" in url.lower()

    # 4. Suspicious TLD check (FR-LEX-04)
    primary_tld = tld.split(".")[-1].lower() if tld else ""
    is_suspicious_tld = primary_tld in SUSPICIOUS_TLDS

    # Structural lexical signals
    subdomain_count = len(subdomain.split(".")) if subdomain else 0
    has_hyphen = "-" in target_string
    digits = sum(c.isdigit() for c in target_string)
    digit_ratio = digits / len(target_string) if target_string else 0.0
    url_length = len(url)

    # 5. Calculate S_lex composite risk score in [0.0, 1.0]
    score = 0.0
    
    # Exact brand match on SLD: if it's the exact brand name but on suspicious TLD or complex subdomain, score higher
    if domain_body == best_matched_brand and best_matched_brand != "":
        # Check if the domain is literally just brand.com or brand.org vs brand-secure.tk
        if is_suspicious_tld:
            score += 0.5
        if has_hyphen or subdomain_count > 0:
            score += 0.3
    else:
        # Near match (typosquatting / brand spoofing in domain)
        # e.g., Levenshtein distance 1 or 2 to brand (like paypa1 vs paypal)
        if 0 < min_dist <= 2 and len(best_matched_brand) >= 4:
            score += 0.55
        elif 2 < min_dist <= 4 and max_lev_sim >= 0.6:
            score += 0.30

    if is_punycode:
        score += 0.40
    if is_suspicious_tld:
        score += 0.25
    if entropy > 3.8:
        score += 0.15
    if has_hyphen:
        score += 0.10
    if subdomain_count >= 2:
        score += 0.15
    if digit_ratio > 0.15:
        score += 0.15

    s_lex = min(1.0, max(0.0, score))

    return LexicalFeatures(
        raw_domain=raw_domain,
        registered_domain=registered_domain,
        subdomain=subdomain,
        tld=tld,
        shannon_entropy=round(entropy, 4),
        min_levenshtein_dist=min_dist,
        matched_brand=best_matched_brand,
        levenshtein_sim=round(max_lev_sim, 4),
        is_punycode=is_punycode,
        is_suspicious_tld=is_suspicious_tld,
        subdomain_count=subdomain_count,
        has_hyphen=has_hyphen,
        digit_ratio=round(digit_ratio, 4),
        url_length=url_length,
        s_lex=round(s_lex, 4)
    )
