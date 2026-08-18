"""
app/stackmodel_features.py
===========================
StackModel 23-Feature Content-Based Extraction Engine.

Implements the FGCS (Future Generation Computer Systems) StackModel
DOM+URL feature extraction methodology from Liang et al.'s experiment code.

Extracts 14 HTML-based features and 9 URL-based features for content-level
phishing classification, complementing the 79-dimensional ISCX lexical features.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment

logger = logging.getLogger(__name__)

# TLD list for TLD-in-domain/path checks (top 50 most phishing-abused TLDs)
SUSPICIOUS_TLDS = frozenset([
    "com", "net", "org", "info", "biz", "xyz", "top", "club", "online",
    "site", "store", "live", "tech", "space", "fun", "icu", "buzz",
    "shop", "work", "pro", "cloud", "host", "website", "press",
    "cc", "tk", "ml", "ga", "cf", "gq", "co", "io", "me", "us",
    "de", "uk", "ru", "cn", "br", "in", "au", "ca", "fr", "it",
    "nl", "jp", "es", "se", "no", "fi"
])

SENSITIVE_WORDS = frozenset([
    "secure", "account", "webscr", "login", "signin",
    "ebayisapi", "banking", "confirm"
])


def _extract_domain_from_url(url: str) -> str:
    """Extract domain from URL, handling edge cases."""
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        return parsed.netloc.split(":")[0].lower()
    except Exception:
        return ""


class HTMLFeatureExtractor:
    """
    Extracts 14 HTML-based features from parsed DOM content.
    Adapted from StackModel's html_check class (FGCS experiment).
    """

    def __init__(self, soup: BeautifulSoup, url: str):
        self.soup = soup
        self.url = url
        self.domain = _extract_domain_from_url(url)

    def _find_tag_text_length(self, tag: str) -> int:
        if tag == '!--':
            total = 0
            for comment in self.soup.find_all(string=lambda text: isinstance(text, Comment)):
                total += len(comment)
            return total
        else:
            elements = self.soup.find_all(str(tag))
            return sum(len(el.get_text()) for el in elements)

    def len_html_tag(self) -> int:
        """Total length of special HTML tags (style, link, form, comments, script)."""
        return sum(self._find_tag_text_length(t) for t in ["style", "link", "form", "!--", "script"])

    def len_html(self) -> int:
        """Total visible text length of the page."""
        return len(self.soup.get_text())

    def hidden_content(self) -> int:
        """Detects hidden divs, disabled buttons, or hidden inputs."""
        # Hidden divs
        for div in self.soup.find_all('div'):
            style = div.get('style', '')
            if 'visibility:hidden' in style or 'display:none' in style:
                return 1
        # Disabled buttons
        for btn in self.soup.find_all('button'):
            if btn.get('disabled') == 'disabled':
                return 1
        # Hidden/disabled inputs
        for inp in self.soup.find_all('input'):
            inp_type = inp.get('type', '')
            if inp_type == 'hidden' or inp.get('disabled') == 'disabled':
                return 1
        return 0

    def find_all_links(self) -> List[str]:
        """Extract all href values from anchor tags."""
        links = []
        for a in self.soup.find_all('a'):
            href = a.get('href', '')
            if href:
                links.append(href)
        return links

    def internal_external_links(self) -> Tuple[int, int]:
        """Count internal vs external hyperlinks."""
        links = self.find_all_links()
        if not links:
            return 0, 0
        internal = 0
        for link in links:
            if "http" in link:
                link_domain = _extract_domain_from_url(link)
                if link_domain == self.domain:
                    internal += 1
            else:
                internal += 1  # relative links are internal
        return internal, len(links) - internal

    def empty_link_count(self) -> int:
        """Count empty/dead hyperlinks (null, #, javascript:void)."""
        null_patterns = {"", "#", "#javascript::void(0)", "#content", "#skip",
                         "javascript:;", "javascript::void(0);", "javascript::void(0)",
                         "javascript:void(0)", "javascript:void(0);"}
        links = self.find_all_links()
        return sum(1 for link in links if link.strip().lower() in null_patterns)

    def login_form_present(self) -> int:
        """Check if any form contains password/login/signin fields."""
        for form in self.soup.find_all('form'):
            for inp in form.find_all('input'):
                name = (inp.get('name') or '').lower()
                if any(kw in name for kw in ['password', 'pass', 'login', 'signin']):
                    return 1
        return 0

    def find_resources(self, tag: str) -> List[str]:
        """Find all src/href resource URLs for a given tag."""
        if tag == 'link':
            return [el.get('href', '') for el in self.soup.find_all('link') if el.get('href')]
        return [el.get('src', '') for el in self.soup.find_all(tag) if el.get('src')]

    def internal_external_resources(self) -> Tuple[int, int]:
        """Count internal vs external resources (link, img, script, noscript)."""
        resources = []
        for tag in ['link', 'img', 'script', 'noscript']:
            resources.extend(self.find_resources(tag))
        if not resources:
            return 0, 0
        external = 0
        for res in resources:
            if "http" in res:
                res_domain = _extract_domain_from_url(res)
                if res_domain != self.domain:
                    external += 1
        return len(resources) - external, external

    def redirect_present(self) -> int:
        """Check for auto-redirect meta tag or JS."""
        return int('redirect' in str(self.soup).lower()[:5000])

    def alarm_window(self) -> int:
        """Check for alert() or window.open() in scripts."""
        for script in self.soup.find_all('script'):
            content = str(script.string or '')
            if 'alert' in content or 'window.open' in content:
                return 1
        return 0

    def title_contains_domain(self) -> int:
        """Check if page title contains the domain name."""
        try:
            title = self.soup.title
            if title and title.string:
                title_str = title.string.lower()
                if self.domain and self.domain in title_str:
                    return 1
                parts = self.domain.split('.')
                for p in parts:
                    if len(p) >= 3 and p not in {'com', 'net', 'org', 'www', 'http', 'https', 'html'} and p in title_str:
                        return 1
        except Exception:
            pass
        return 0

    def domain_occurrence_count(self) -> int:
        """Count occurrences of domain name in HTML."""
        try:
            return str(self.soup).lower().count(self.domain)
        except Exception:
            return 0

    def brand_is_most_frequent_domain(self) -> int:
        """Check if the page's own domain is the most frequently linked domain."""
        links = self.find_all_links()
        domains = []
        for link in links:
            if "http" in link:
                domains.append(_extract_domain_from_url(link))
            else:
                domains.append(self.domain)
        if not domains:
            return 1
        from collections import Counter
        most_common = Counter(domains).most_common(1)[0][0]
        return int(most_common == self.domain)

    def extract_all_features(self) -> Dict[str, int]:
        """Extract all 14 HTML-based features."""
        int_links, ext_links = self.internal_external_links()
        int_res, ext_res = self.internal_external_resources()

        return {
            'internal_link': int_links,
            'external_link': ext_links,
            'empty_link': self.empty_link_count(),
            'login_form': self.login_form_present(),
            'html_len_tag': self.len_html_tag(),
            'html_len': self.len_html(),
            'alarm_window': self.alarm_window(),
            'redirection': self.redirect_present(),
            'hidden': self.hidden_content(),
            'title_domain': self.title_contains_domain(),
            'brand_domain': self.brand_is_most_frequent_domain(),
            'internal_resource': int_res,
            'external_resource': ext_res,
            'domain_occurrence': self.domain_occurrence_count()
        }


class URLFeatureExtractor:
    """
    Extracts 9 URL-based features.
    Adapted from StackModel's URL_check class (FGCS experiment).
    """

    def __init__(self, url: str):
        self.url = url.lower()
        self.parsed = urlparse(self.url if self.url.startswith(("http://", "https://")) else "http://" + self.url)
        self.domain = _extract_domain_from_url(url)

    def domain_is_ip(self) -> int:
        """Check if hostname is an IP address."""
        hostname = self.parsed.netloc.split(":")[0]
        parts = hostname.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return 1
        return 0

    def symbol_count(self) -> int:
        """Count suspicious symbols (@, -, ~)."""
        return sum(1 for c in self.url if c in "@-~")

    def has_https(self) -> int:
        """Check for HTTPS protocol."""
        return int(self.url.startswith("https://"))

    def domain_length(self) -> int:
        """Full domain length including subdomain and suffix."""
        return len(self.parsed.netloc.split(":")[0])

    def url_length(self) -> int:
        """Full URL length."""
        return len(self.url)

    def num_dots_in_hostname(self) -> int:
        """Count dots in hostname (subdomain depth indicator)."""
        return self.parsed.netloc.split(":")[0].count(".")

    def sensitive_word_present(self) -> int:
        """Check for phishing-sensitive keywords in URL."""
        return int(any(w in self.url for w in SENSITIVE_WORDS))

    def tld_in_domain(self) -> int:
        """Check if a known TLD appears as a subdomain or domain token."""
        hostname = self.parsed.netloc.split(":")[0]
        parts = hostname.split(".")
        for part in parts[:-1]:  # Exclude actual TLD
            if part in SUSPICIOUS_TLDS:
                return 1
        return 0

    def tld_in_path(self) -> int:
        """Check if a known TLD appears in the path, params, query, or fragment."""
        check_parts = [
            self.parsed.path, self.parsed.params,
            self.parsed.query, self.parsed.fragment
        ]
        for part in check_parts:
            for tld in SUSPICIOUS_TLDS:
                if tld == part.strip("/"):
                    return 1
        return 0

    def extract_all_features(self) -> Dict[str, int]:
        """Extract all 9 URL-based features."""
        return {
            'domain_is_ip': self.domain_is_ip(),
            'symbol_count': self.symbol_count(),
            'https': self.has_https(),
            'domain_len': self.domain_length(),
            'url_len': self.url_length(),
            'num_dot_hostname': self.num_dots_in_hostname(),
            'sensitive_word': self.sensitive_word_present(),
            'tld_in_domain': self.tld_in_domain(),
            'tld_in_path': self.tld_in_path()
        }


def extract_stackmodel_23_features(url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
    """
    Extracts the complete 23-feature StackModel vector from a URL + optional HTML.

    Returns dict with 14 HTML features + 9 URL features + composite score.
    """
    # URL features (always available)
    url_extractor = URLFeatureExtractor(url)
    url_features = url_extractor.extract_all_features()

    # HTML features (only if content available)
    html_features = {
        'internal_link': 0, 'external_link': 0, 'empty_link': 0,
        'login_form': 0, 'html_len_tag': 0, 'html_len': 0,
        'alarm_window': 0, 'redirection': 0, 'hidden': 0,
        'title_domain': 0, 'brand_domain': 1, 'internal_resource': 0,
        'external_resource': 0, 'domain_occurrence': 0
    }

    if html_content and len(html_content) > 50:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            html_extractor = HTMLFeatureExtractor(soup, url)
            html_features = html_extractor.extract_all_features()
        except Exception as e:
            logger.debug(f"HTML feature extraction error: {e}")

    # Combine all features
    combined = {**html_features, **url_features}

    # Compute a composite phishing risk score from the 23 features
    risk_signals = 0
    total_signals = 0

    # URL risk signals
    if url_features['domain_is_ip']:
        risk_signals += 2
    if url_features['sensitive_word']:
        risk_signals += 1
    if not url_features['https']:
        risk_signals += 1
    if url_features['domain_len'] > 30:
        risk_signals += 1
    if url_features['url_len'] > 75:
        risk_signals += 1
    if url_features['num_dot_hostname'] > 3:
        risk_signals += 1
    if url_features['tld_in_domain']:
        risk_signals += 2
    if url_features['tld_in_path']:
        risk_signals += 1
    if url_features['symbol_count'] > 2:
        risk_signals += 1
    total_signals += 11

    # HTML risk signals
    if html_content and len(html_content) > 50:
        if html_features['external_link'] > html_features['internal_link'] and html_features['external_link'] > 3:
            risk_signals += 2
        if html_features['empty_link'] > 3:
            risk_signals += 2
        if html_features['login_form']:
            risk_signals += 1
        if html_features['alarm_window']:
            risk_signals += 1
        if html_features['redirection']:
            risk_signals += 1
        if html_features['hidden']:
            risk_signals += 1
        if not html_features['title_domain']:
            risk_signals += 1
        if not html_features['brand_domain']:
            risk_signals += 2
        if html_features['external_resource'] > html_features['internal_resource']:
            risk_signals += 1
        total_signals += 12
    else:
        total_signals += 0  # No HTML signals to count

    combined['stackmodel_risk_score'] = round(risk_signals / max(1, total_signals), 4)
    combined['feature_count'] = 23

    return combined
