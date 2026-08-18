import ipaddress
import math
import re
import urllib.parse
from dataclasses import dataclass
from typing import List, Tuple, Optional, Set, Dict
import Levenshtein
import tldextract

# List of TLDs statistically associated with high abuse rates
SUSPICIOUS_TLDS: Set[str] = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "buzz", "online",
    "site", "icu", "monster", "club", "info", "cfd", "sbs", "rest", "fit",
    "cc", "ws", "country", "stream", "gdn", "mom", "cam", "kim", "vip",
    "click", "link", "surf", "casa", "bar", "lat", "live", "space", "support"
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
    is_ip: bool
    subdomain_count: int
    has_hyphen: bool
    digit_ratio: float
    url_length: int
    is_canonical_domain: bool
    s_lex: float

def compute_shannon_entropy(s: str) -> float:
    """Computes Shannon entropy for character distribution in a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_domain_parts(url: str) -> Tuple[str, str, str, str]:
    """
    Extracts (raw_domain, registered_domain, subdomain, tld) from a URL without making network calls.
    Strips ports if present.
    """
    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "http://" + cleaned_url
        
    parsed = urllib.parse.urlparse(cleaned_url)
    netloc = parsed.netloc.split(":")[0]  # strip port if present
    
    ext = tldextract.extract(netloc)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ext.domain or ""
    subdomain = ext.subdomain or ""
    tld = ext.suffix or ""
    raw_domain = f"{subdomain}.{registered_domain}".strip(".") if subdomain else (registered_domain or netloc)
    return raw_domain, registered_domain, subdomain, tld

def is_valid_ip_address(host: str) -> bool:
    """Checks if a string is a valid IPv4 or IPv6 address (with optional port)."""
    if not host:
        return False
    clean = host.strip()
    # Handle bracketed IPv6 with port e.g. [::1]:8080
    if clean.startswith("[") and "]:" in clean:
        raw_ip = clean.split("]:")[0].lstrip("[")
        try:
            ipaddress.ip_address(raw_ip)
            return True
        except ValueError:
            return False

    clean_unbracketed = clean.strip("[]")
    # Direct IP parse (handles IPv4, IPv6 like ::1)
    try:
        ipaddress.ip_address(clean_unbracketed)
        return True
    except ValueError:
        pass

    # Try stripping port for IPv4 (e.g. 192.168.1.1:8080)
    if ":" in clean_unbracketed and "." in clean_unbracketed:
        parts = clean_unbracketed.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            try:
                ipaddress.ip_address(parts[0])
                return True
            except ValueError:
                pass

    return False


def analyze_lexical(
    url: str, 
    brand_list: List[str], 
    canonical_domain_map: Optional[Dict[str, List[str]]] = None
) -> LexicalFeatures:
    """
    Pure-function lexical analyzer according to FR-LEX-01 to 05.
    No network calls.
    """
    raw_domain, registered_domain, subdomain, tld = extract_domain_parts(url)
    target_string = raw_domain.lower()
    
    # Check IP address
    is_ip = is_valid_ip_address(target_string) or is_valid_ip_address(registered_domain)
    
    # 1. Shannon entropy (FR-LEX-01)
    entropy = compute_shannon_entropy(target_string)
    
    # 2. Levenshtein distance against reference brands (FR-LEX-02)
    min_dist = 999
    best_matched_brand = ""
    max_lev_sim = 0.0
    brand_exact_in_token = False
    
    ext = tldextract.extract(target_string if not is_ip else "")
    domain_body = ext.domain.lower() if ext.domain else target_string
    
    # Extract sub-tokens from subdomain and domain body
    tokens = set()
    if domain_body:
        tokens.add(domain_body)
        for part in re.split(r'[-._0-9]', domain_body):
            if part:
                tokens.add(part)
    if subdomain:
        tokens.add(subdomain)
        for part in re.split(r'[-._0-9]', subdomain):
            if part:
                tokens.add(part)
    tokens.add(target_string)

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
            
            if dist_tok == 0:
                brand_exact_in_token = True
            
            if dist_tok < min_dist:
                min_dist = dist_tok
                best_matched_brand = brand_clean
                max_lev_sim = sim
            elif dist_tok == min_dist and sim > max_lev_sim:
                best_matched_brand = brand_clean
                max_lev_sim = sim

    # Only assign best_matched_brand if similarity meets high confidence threshold
    if min_dist == 999 or (max_lev_sim < 0.60 and min_dist > 2 and not brand_exact_in_token):
        if min_dist == 999:
            min_dist = 0
        best_matched_brand = ""
        max_lev_sim = 0.0

    # Check canonical domain matching
    is_canonical = False
    if canonical_domain_map and best_matched_brand in canonical_domain_map:
        official_domains = [d.lower() for d in canonical_domain_map[best_matched_brand]]
        if registered_domain.lower() in official_domains or target_string.lower() in official_domains:
            is_canonical = True
    elif best_matched_brand:
        # Default canonical check: if registered_domain is literally brand.com, brand.org, etc.
        if registered_domain.lower() == f"{best_matched_brand}.com" or registered_domain.lower() == f"{best_matched_brand}.org":
            is_canonical = True

    # 3. Punycode / Homoglyph check (FR-LEX-03)
    is_punycode = "xn--" in target_string or "xn--" in url.lower()
    has_mixed_script = False
    try:
        if is_punycode:
            import idna
            decoded = idna.decode(target_string.split(":")[0])
            # Check if contains non-ascii characters
            if any(ord(c) > 127 for c in decoded):
                has_mixed_script = True
    except Exception:
        has_mixed_script = is_punycode

    # 4. Suspicious TLD check (FR-LEX-04)
    primary_tld = tld.split(".")[-1].lower() if tld else ""
    is_suspicious_tld = primary_tld in SUSPICIOUS_TLDS

    # Structural lexical signals
    subdomain_count = len(subdomain.split(".")) if subdomain else 0
    has_hyphen = "-" in target_string
    digits = sum(c.isdigit() for c in target_string)
    digit_ratio = digits / len(target_string) if target_string else 0.0
    url_length = len(url)

    # Subdomain Masquerading Detection (e.g. paypal.com.attacker.tk or login.microsoft.com.spoof.net)
    is_subdomain_masquerading = False
    if subdomain and best_matched_brand:
        sub_lower = subdomain.lower()
        if (f"{best_matched_brand}.com" in sub_lower or 
            f"{best_matched_brand}." in sub_lower or 
            sub_lower.startswith(f"{best_matched_brand}-") or
            sub_lower.endswith(f"-{best_matched_brand}")):
            if not is_canonical:
                is_subdomain_masquerading = True

    # 5. Calculate S_lex composite risk score in [0.0, 1.0]
    score = 0.0
    
    if is_canonical:
        # Verified canonical domain — risk is strictly minimal
        score = 0.02
    else:
        # Subdomain Masquerading is an immediate high-confidence phishing indicator
        if is_subdomain_masquerading:
            score += 0.70

        # Brand spoofing / Typosquatting in non-canonical domain
        if brand_exact_in_token and best_matched_brand:
            # Contains exact brand name (e.g. paypal-update.com, login.google.xyz)
            score += 0.55
            if is_suspicious_tld:
                score += 0.20
            if has_hyphen or subdomain_count > 0:
                score += 0.15
        elif 0 < min_dist <= 2 and len(best_matched_brand) >= 3:
            # Near typosquatting (e.g. paypa1, gooogle)
            score += 0.60
            if is_suspicious_tld:
                score += 0.20
        elif 2 < min_dist <= 4 and max_lev_sim >= 0.6:
            score += 0.35

        if is_punycode or has_mixed_script:
            score += 0.50
        if is_suspicious_tld:
            score += 0.25
        if is_ip:
            score += 0.55
        if entropy > 3.8:
            score += 0.15
        if has_hyphen and not brand_exact_in_token:
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
        is_punycode=is_punycode or has_mixed_script,
        is_suspicious_tld=is_suspicious_tld,
        is_ip=is_ip,
        subdomain_count=subdomain_count,
        has_hyphen=has_hyphen,
        digit_ratio=round(digit_ratio, 4),
        url_length=url_length,
        is_canonical_domain=is_canonical,
        s_lex=round(s_lex, 4)
    )

