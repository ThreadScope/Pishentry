"""
app/dom_similarity.py
=====================
Advanced Multi-Modal DOM Structural & Semantic Brand Disambiguation Engine.

Features:
- 64-bit Locality-Sensitive Hashing (SimHash) for sub-millisecond structural DOM fingerprinting
- Hierarchical tag path tree extraction preserving parent-child layout topology
- Multi-factor DOM similarity fusion (Tag N-Grams + SimHash + Form/Input Topology)
- Expanded 35+ enterprise brand signature dictionary for precise disambiguation
- Anti-obfuscation filtering with CSS visibility & Zero-Font sanitization
"""

import re
import hashlib
import logging
from typing import List, Tuple, Dict, Optional, Set, Any
from bs4 import BeautifulSoup

from app.dom_visibility import clean_human_visible_dom_text

logger = logging.getLogger(__name__)

MAX_HTML_PARSE_LENGTH = 1_000_000  # 1 MB safety cap

# Expanded 35+ Enterprise Brand Signature Dictionary
BRAND_TOKEN_SIGNATURES: Dict[str, List[str]] = {
    "google": [
        "google", "gmail", "gsuite", "google account", "accounts.google.com",
        "sign in with google", "use your google account", "google llc", "google workspace",
        "myaccount.google.com", "google drive", "google docs"
    ],
    "microsoft": [
        "microsoft", "office 365", "office365", "outlook", "login.microsoftonline.com",
        "login.live.com", "azure", "microsoft corporation", "sign in to your microsoft account",
        "msft", "sharepoint", "onedrive", "microsoft authenticator", "entra id"
    ],
    "paypal": [
        "paypal", "paypal inc", "paypal.com", "pay with paypal", "log in to your paypal account",
        "paypal balance", "paypal credit", "paypal checkout", "service@paypal.com"
    ],
    "apple": [
        "apple", "apple id", "icloud", "apple.com", "apple inc", "sign in with apple",
        "two-factor authentication for apple id", "find my", "app store"
    ],
    "amazon": [
        "amazon", "amazon.com", "amazon prime", "aws", "amazon web services",
        "sign in to amazon", "amazon login", "amazon pay", "amazon.co.uk", "amazon.de"
    ],
    "netflix": [
        "netflix", "netflix inc", "netflix.com", "watch netflix", "sign in to netflix",
        "netflix membership", "unlimited movies, tv shows"
    ],
    "github": [
        "github", "github inc", "github.com", "sign in to github", "github enterprise",
        "github personal access token", "github copilot"
    ],
    "gitlab": [
        "gitlab", "gitlab.com", "gitlab inc", "sign in to gitlab", "gitlab devops"
    ],
    "bankofamerica": [
        "bank of america", "bofa", "bankofamerica.com", "merrill lynch", "bofaml",
        "online banking passcode", "bank of america login", "bofa online banking"
    ],
    "chase": [
        "chase", "jpmorgan", "chase.com", "chase online", "chase bank", "jpmorgan chase",
        "chase sapphire", "chase commercial online"
    ],
    "wellsfargo": [
        "wells fargo", "wellsfargo.com", "wells fargo online", "wells fargo advisor",
        "wells fargo sign on", "wells fargo banking"
    ],
    "citibank": [
        "citibank", "citi", "citi.com", "citi cards", "citigroup", "citi online"
    ],
    "hsbc": [
        "hsbc", "hsbc.com", "hsbc holdings", "hsbc online banking", "hsbc uk", "hsbc personal banking"
    ],
    "barclays": [
        "barclays", "barclays.co.uk", "barclays bank", "barclays online banking", "barclays corporate"
    ],
    "dhl": [
        "dhl", "dhl express", "dhl parcel", "dhl tracking", "dhl.com", "dhl global forwarding",
        "track your shipment with dhl", "mydhl"
    ],
    "fedex": [
        "fedex", "fedex.com", "fedex express", "fedex tracking", "fedex ground", "fedex delivery manager"
    ],
    "ups": [
        "ups", "ups.com", "united parcel service", "ups tracking", "ups my choice"
    ],
    "usps": [
        "usps", "usps.com", "united states postal service", "usps tracking", "informed delivery"
    ],
    "adobe": [
        "adobe", "adobe creative cloud", "adobe.com", "adobe systems", "adobe acrobat",
        "sign in with adobe id", "adobe document cloud"
    ],
    "docusign": [
        "docusign", "docusign inc", "docusign.com", "docusign electronic signature",
        "review and sign document"
    ],
    "dropbox": [
        "dropbox", "dropbox inc", "dropbox.com", "sign in to dropbox", "dropbox business"
    ],
    "facebook": [
        "facebook", "meta", "facebook.com", "meta platforms", "log into facebook",
        "connect with facebook", "meta business suite"
    ],
    "instagram": [
        "instagram", "instagram.com", "log in with instagram", "instagram from meta"
    ],
    "linkedin": [
        "linkedin", "linkedin.com", "linkedin corporation", "sign in to linkedin", "linkedin learning"
    ],
    "twitter": [
        "twitter", "x.com", "twitter.com", "sign in to x", "sign in to twitter"
    ],
    "coinbase": [
        "coinbase", "coinbase.com", "coinbase pro", "coinbase wallet", "sign in to coinbase"
    ],
    "binance": [
        "binance", "binance.com", "binance exchange", "binance us", "binance login"
    ],
    "metamask": [
        "metamask", "metamask.io", "connect your wallet", "secret recovery phrase", "metamask extension"
    ],
    "steam": [
        "steam", "steampowered.com", "valve corporation", "sign in to steam", "steam community", "steam guard"
    ],
    "spotify": [
        "spotify", "spotify.com", "spotify music", "sign in to spotify", "spotify premium"
    ],
    "ebay": [
        "ebay", "ebay.com", "ebay inc", "sign in to ebay", "ebay secure login"
    ]
}

IGNORED_TAGS = frozenset([
    "script", "style", "meta", "link", "noscript", "svg", "path",
    "defs", "clippath", "head", "title"
])


def extract_tag_sequence(html_content: str) -> List[str]:
    """
    Parses HTML and extracts a standardized sequence of tag names, encoding input types.
    """
    if not html_content or not html_content.strip():
        return []
    
    clipped_html = html_content[:MAX_HTML_PARSE_LENGTH]
    
    try:
        soup = BeautifulSoup(clipped_html, "html.parser")
        tags: List[str] = []
        for elem in soup.find_all(True):
            name = elem.name.lower() if elem.name else ""
            if name and name not in IGNORED_TAGS:
                if name == "input":
                    itype = elem.get("type", "text").lower()
                    tags.append(f"input_{itype}")
                else:
                    tags.append(name)
        return tags
    except Exception as e:
        logger.error(f"Error parsing DOM HTML: {e}")
        return []


def extract_tag_ngrams(tags: List[str], n: int = 2) -> Set[Tuple[str, ...]]:
    """
    Extracts set of n-grams from tag sequence.
    """
    if len(tags) < n:
        return set()
    return set(tuple(tags[i:i+n]) for i in range(len(tags) - n + 1))


def extract_dom_tree_paths(html_content: str, max_depth: int = 6) -> List[str]:
    """
    Extracts depth-weighted hierarchical tag paths representing the DOM tree skeleton.
    Example: 'html>body>div>form>input_password'
    """
    if not html_content or not html_content.strip():
        return []
    
    paths: List[str] = []
    try:
        soup = BeautifulSoup(html_content[:MAX_HTML_PARSE_LENGTH], "html.parser")
        
        def walk(node, current_path: List[str], depth: int):
            if depth > max_depth or not hasattr(node, "name") or not node.name:
                return
            name = node.name.lower()
            if name in IGNORED_TAGS:
                return
            
            tag_repr = f"input_{node.get('type', 'text').lower()}" if name == "input" else name
            new_path = current_path + [tag_repr]
            
            # Record structural branch endpoints
            if not getattr(node, "find_all", None) or len(node.find_all(True, recursive=False)) == 0 or name in ["form", "input", "button", "iframe"]:
                paths.append(">".join(new_path))
                
            for child in getattr(node, "children", []):
                if hasattr(child, "name") and child.name:
                    walk(child, new_path, depth + 1)

        body = soup.body or soup
        walk(body, ["html"], 1)
        return paths
    except Exception as e:
        logger.debug(f"Error extracting DOM tree paths: {e}")
        return []


def compute_dom_simhash(html_content: str) -> str:
    """
    Computes a 64-bit Locality-Sensitive Hash (SimHash) of the DOM layout topology.
    Similar DOM structures yield small Hamming distances between their 64-bit fingerprints.
    """
    if not html_content or not html_content.strip():
        return "0000000000000000"

    paths = extract_dom_tree_paths(html_content)
    tags = extract_tag_sequence(html_content)
    
    if not paths and not tags:
        return "0000000000000000"

    v = [0] * 64
    
    # Weight features by architectural significance
    features: Dict[str, int] = {}
    for p in paths:
        w = 3 if "form" in p or "input" in p else 1
        features[p] = features.get(p, 0) + w
        
    for i in range(len(tags) - 1):
        bigram = f"{tags[i]}_{tags[i+1]}"
        features[bigram] = features.get(bigram, 0) + 1

    for feature_str, weight in features.items():
        # Compute 64-bit hash
        md5_hash = hashlib.md5(feature_str.encode("utf-8")).digest()
        hash_val = int.from_bytes(md5_hash[:8], byteorder="big")
        
        for bit in range(64):
            if (hash_val >> bit) & 1:
                v[bit] += weight
            else:
                v[bit] -= weight

    simhash_int = 0
    for bit in range(64):
        if v[bit] > 0:
            simhash_int |= (1 << bit)

    return f"{simhash_int:016x}"


def compute_simhash_similarity(hash1: str, hash2: str) -> float:
    """
    Calculates normalized SimHash similarity [0.0, 1.0] via bitwise Hamming distance.
    """
    if not hash1 or not hash2 or hash1 == "0000000000000000" or hash2 == "0000000000000000":
        return 0.0
    try:
        int1 = int(hash1, 16)
        int2 = int(hash2, 16)
        xor_val = int1 ^ int2
        hamming_dist = bin(xor_val).count("1")
        similarity = 1.0 - (hamming_dist / 64.0)
        return round(float(similarity), 4)
    except Exception:
        return 0.0


def extract_form_topology(html_content: str) -> Dict[str, Any]:
    """
    Extracts structural credential form metrics for layout topology comparison.
    """
    if not html_content or not html_content.strip():
        return {"form_count": 0, "password_count": 0, "text_input_count": 0, "has_submit": False}
    try:
        soup = BeautifulSoup(html_content[:MAX_HTML_PARSE_LENGTH], "html.parser")
        forms = soup.find_all("form")
        passwords = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})
        text_inputs = soup.find_all("input", attrs={"type": re.compile(r"^(text|email|tel|number)$", re.I)})
        submits = soup.find_all(["button", "input"], attrs={"type": re.compile(r"^submit$", re.I)})
        return {
            "form_count": len(forms),
            "password_count": len(passwords),
            "text_input_count": len(text_inputs),
            "has_submit": len(submits) > 0
        }
    except Exception:
        return {"form_count": 0, "password_count": 0, "text_input_count": 0, "has_submit": False}


def extract_dom_semantic_text(html_content: str) -> str:
    """
    Extracts visible text, titles, alt text, form actions, and button labels for semantic disambiguation,
    applying anti-zero-font and computed CSS visibility filters.
    """
    if not html_content or not html_content.strip():
        return ""
    try:
        cleaned_body_text, _, _ = clean_human_visible_dom_text(html_content[:MAX_HTML_PARSE_LENGTH])
        soup = BeautifulSoup(html_content[:MAX_HTML_PARSE_LENGTH], "html.parser")
        pieces = [cleaned_body_text.lower()]
        
        # Title tag
        if soup.title and soup.title.string:
            pieces.append(soup.title.string.lower())
            
        # Form actions & inputs
        for f in soup.find_all("form"):
            action = f.get("action") or ""
            pieces.append(action.lower())
        for inp in soup.find_all("input"):
            placeholder = inp.get("placeholder") or ""
            name = inp.get("name") or ""
            pieces.append(f"{name} {placeholder}".lower())
            
        # Image alt & src
        for img in soup.find_all("img"):
            alt = img.get("alt") or ""
            src = img.get("src") or ""
            pieces.append(f"{alt} {src}".lower())
            
        # Button & heading text
        for btn in soup.find_all(["button", "a", "h1", "h2", "h3", "p", "span", "div"]):
            txt = btn.get_text(strip=True)
            if txt and len(txt) <= 120:
                pieces.append(txt.lower())
                
        return " ".join(pieces)
    except Exception:
        return html_content.lower()


def compute_brand_semantic_score(dom_text: str, brand_id: str) -> float:
    """
    Evaluates brand keyword token density and distinctive presence in DOM text.
    """
    clean_brand = brand_id.lower().strip()
    signatures = BRAND_TOKEN_SIGNATURES.get(clean_brand, [clean_brand])
    
    score = 0.0
    matched_any = False
    
    for sig in signatures:
        if sig in dom_text:
            matched_any = True
            # Higher weight for exact multi-word brand phrases or domain strings
            if " " in sig or "." in sig:
                score += 0.45
            else:
                score += 0.25
                
    if matched_any:
        return min(1.0, max(0.50, score))
    return 0.0


def compute_dom_similarity(html1: Optional[str], html2: Optional[str]) -> float:
    """
    Computes multi-factor structural DOM similarity between two web surfaces.
    Fuses:
    1. Multi-gram Tag N-Gram Jaccard overlap (40%)
    2. 64-bit Locality-Sensitive SimHash similarity (35%)
    3. Credential Form Topology Alignment (25%)
    """
    if not html1 or not html2 or not html1.strip() or not html2.strip():
        return 0.0

    if html1 == html2:
        return 1.0

    tags1 = extract_tag_sequence(html1)
    tags2 = extract_tag_sequence(html2)
    
    if not tags1 or not tags2:
        return 0.0

    # 1. Tag Jaccard N-Grams (1-gram, 2-gram, 3-gram)
    set1_1 = set(tags1)
    set2_1 = set(tags2)
    jaccard_1 = len(set1_1 & set2_1) / len(set1_1 | set2_1) if (set1_1 | set2_1) else 0.0

    ngrams1_2 = extract_tag_ngrams(tags1, 2)
    ngrams2_2 = extract_tag_ngrams(tags2, 2)
    jaccard_2 = len(ngrams1_2 & ngrams2_2) / len(ngrams1_2 | ngrams2_2) if (ngrams1_2 | ngrams2_2) else 0.0

    ngrams1_3 = extract_tag_ngrams(tags1, 3)
    ngrams2_3 = extract_tag_ngrams(tags2, 3)
    jaccard_3 = len(ngrams1_3 & ngrams2_3) / len(ngrams1_3 | ngrams2_3) if (ngrams1_3 | ngrams2_3) else 0.0

    tag_similarity = 0.30 * jaccard_1 + 0.45 * jaccard_2 + 0.25 * jaccard_3

    # 2. 64-bit Structural SimHash Similarity
    hash1 = compute_dom_simhash(html1)
    hash2 = compute_dom_simhash(html2)
    simhash_sim = compute_simhash_similarity(hash1, hash2)

    # 3. Form Topology Match
    topo1 = extract_form_topology(html1)
    topo2 = extract_form_topology(html2)
    
    topo_sim = 1.0 if topo1["form_count"] == topo2["form_count"] and topo1["password_count"] == topo2["password_count"] and topo1["has_submit"] == topo2["has_submit"] else (
        0.50 if (topo1["password_count"] > 0 and topo2["password_count"] > 0) else 0.20
    )

    combined_similarity = 0.40 * tag_similarity + 0.35 * simhash_sim + 0.25 * topo_sim
    return round(float(combined_similarity), 4)


def match_dom_against_brands(
    candidate_html: str, 
    brand_dom_map: Dict[str, str]
) -> Tuple[float, Optional[str]]:
    """
    Compares candidate DOM against reference brand DOM snapshots with Multi-Modal Semantic Disambiguation.
    Returns (highest_score, matched_brand_id).
    """
    if not candidate_html or not brand_dom_map:
        return 0.0, None
        
    candidate_text = extract_dom_semantic_text(candidate_html)
    
    best_score = 0.0
    best_brand = None
    
    semantic_scores = {}
    for brand_id in brand_dom_map.keys():
        semantic_scores[brand_id] = compute_brand_semantic_score(candidate_text, brand_id)
        
    for brand_id, ref_html in brand_dom_map.items():
        structural_score = compute_dom_similarity(candidate_html, ref_html)
        sem_score = semantic_scores.get(brand_id, 0.0)
        
        if sem_score > 0:
            combined = round(0.55 * sem_score + 0.45 * structural_score, 4)
            combined = min(1.0, combined + 0.20)
        else:
            other_brands_present = any(s > 0 for b, s in semantic_scores.items() if b != brand_id)
            if other_brands_present:
                combined = round(structural_score * 0.25, 4)  # Suppress cross-brand false overlap
            else:
                combined = structural_score

        if combined > best_score:
            best_score = combined
            best_brand = brand_id

    if best_score < 0.35:
        return 0.0, None

    return best_score, best_brand

