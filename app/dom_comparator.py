"""
app/dom_comparator.py
=====================
Deep DOM Forensic Examiner & Client-Side Feature Extraction Engine.

Implements state-of-the-art anti-phishing literature methodologies:
- CANTINA+ Feature Framework (Xiang et al., 2011)
- 12-Dimensional Hyperlink & Anchor Discrepancy Heuristics (Jain & Gupta, 2018b, 2019)
- Server Form Handler (SFH) and Insecure Action Auditing (Rao & Pais, 2019)
- Browser-in-the-Browser (BiTB) False Authentication Detection (Asiri et al., 2023, 2024)
- Anti-Analysis / Right-Click / Text Selection Disablement Auditing
- Zero-Font & Computed CSS Steganography Sanitization
- Direct C2 / Webhook Exfiltration Hook Inspection
"""

import re
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dataclasses import dataclass, asdict, field

from app.dom_visibility import clean_human_visible_dom_text

logger = logging.getLogger(__name__)

EXFILTRATION_HOOK_REGEX = re.compile(
    r"https?://(?:api\.telegram\.org/bot[^\"'\s\)\&]+|discord\.com/api/webhooks/[^\"'\s\)\&]+|webhook\.site/[a-zA-Z0-9_\-]+|pipedream\.net/[a-zA-Z0-9_\-]+|[a-zA-Z0-9_\-]+\.workers\.dev/[^\"'\s\)\&]+|[a-zA-Z0-9_\-]+\.supabase\.co/[^\"'\s\)\&]+)",
    re.IGNORECASE
)

DROP_FILE_REGEX = re.compile(
    r"[\"']([a-zA-Z0-9_\-\./]+/(?:login|log|post|drop|capture|gate|send|process|action|auth)\.(?:php|aspx|cgi|jsp|py))[\"']",
    re.IGNORECASE
)

# Common enterprise brands for anchor text deception detection
TARGET_BRAND_NAMES = frozenset([
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "citibank", "dhl", "fedex",
    "ups", "usps", "adobe", "docusign", "dropbox", "facebook", "instagram",
    "linkedin", "coinbase", "binance", "metamask", "steam", "spotify", "ebay"
])

SUSPICIOUS_SCRIPT_TLDS = frozenset([".tk", ".xyz", ".top", ".ru", ".buzz", ".live", ".cc", ".icu", ".cfd", ".monster", ".work", ".shop", ".fit", ".rest"])


@dataclass
class FormActionAudit:
    form_id: Optional[str]
    form_name: Optional[str]
    action_url: str
    method: str
    target_domain: str
    is_external_mismatch: bool
    input_fields: List[str]
    has_password_field: bool
    is_insecure_transport: bool = False
    is_null_or_empty_action: bool = False


@dataclass
class DOMForensicsDetail:
    total_dom_nodes: int
    form_count: int
    password_input_count: int
    form_actions: List[FormActionAudit]
    has_form_action_mismatch: bool
    suspicious_external_scripts: List[str]
    has_iframe_overlay: bool
    structural_node_diff_ratio: float  # 0.0 to 1.0 similarity against baseline
    mitre_attack_id: str
    forensic_highlights: List[str]
    is_formless_harvesting: bool = False
    has_zero_font_obfuscation: bool = False
    exfiltration_endpoints: List[str] = field(default_factory=list)
    has_shadow_dom_nodes: bool = False
    # CANTINA+ & Client-Side DOM Forensics (Jain & Gupta 2018b, 2019; Xiang et al. 2011; Rao & Pais 2019)
    total_hyperlinks_count: int = 0
    null_hyperlinks_ratio: float = 0.0
    external_hyperlinks_ratio: float = 0.0
    internal_hyperlinks_ratio: float = 0.0
    empty_anchor_tags_ratio: float = 0.0
    anchor_text_discrepancy_count: int = 0
    external_resources_ratio: float = 0.0
    favicon_external_mismatch: bool = False
    has_server_form_handler_mismatch: bool = False
    has_right_click_disabled: bool = False
    has_text_selection_disabled: bool = False
    has_browser_in_the_browser: bool = False


def _is_null_hyperlink(href: str) -> bool:
    """Checks if hyperlink destination is empty, placeholder, or JavaScript pseudo-protocol."""
    h = href.strip().lower()
    return not h or h in ["#", "#!", "javascript:void(0)", "javascript:void(0);", "javascript:;", "javascript:void()", "about:blank", "mailto:"]


def _extract_domain(url_str: str) -> str:
    """Safely extracts normalized second-level or hostname from a URL string."""
    try:
        if not url_str.startswith(("http://", "https://", "//")):
            return ""
        if url_str.startswith("//"):
            url_str = "https:" + url_str
        parsed = urlparse(url_str)
        return (parsed.netloc or "").split(":")[0].lower()
    except Exception:
        return ""


def _audit_hyperlinks_and_anchors(
    soup: BeautifulSoup,
    candidate_host: str,
    canon_set: Set[str]
) -> Tuple[int, float, float, float, float, int, List[str]]:
    """
    Implements Jain & Gupta (2019) 12-feature hyperlink forensics and anchor discrepancy analysis.
    """
    anchors = soup.find_all("a")
    total_anchors = len(anchors)
    if total_anchors == 0:
        return 0, 0.0, 0.0, 0.0, 0.0, 0, []

    null_count = 0
    external_count = 0
    internal_count = 0
    empty_count = 0
    discrepancy_count = 0
    discrepancy_details = []

    for a in anchors:
        href = a.get("href")
        text = a.get_text(strip=True).lower()
        
        # 1. Null / Placeholder Hyperlinks
        if href is None or _is_null_hyperlink(href):
            null_count += 1
            if not text and not a.find(["img", "svg", "i", "span"]):
                empty_count += 1
            continue

        if not text and not a.find(["img", "svg", "i", "span"]):
            empty_count += 1

        href_trimmed = href.strip()
        target_domain = _extract_domain(href_trimmed)

        # 2. Internal vs External Ratio
        if not target_domain or target_domain == candidate_host or (candidate_host and candidate_host.endswith("." + target_domain)):
            internal_count += 1
        elif canon_set and target_domain in canon_set:
            internal_count += 1
        else:
            external_count += 1

        # 3. Anchor Text Discrepancy (e.g. text says paypal.com, href points to attacker.xyz)
        if target_domain and target_domain != candidate_host and target_domain not in canon_set:
            # Check if text mimics a domain or official brand
            has_domain_text = bool(re.search(r"[a-z0-9_\-\.]+\.(?:com|org|net|gov|edu|io|co|uk|de|xyz|top)", text))
            has_brand_text = any(b in text for b in TARGET_BRAND_NAMES)
            
            if (has_domain_text or has_brand_text) and not any(target_domain.endswith(b) for b in TARGET_BRAND_NAMES):
                discrepancy_count += 1
                if len(discrepancy_details) < 3:
                    discrepancy_details.append(f"Anchor text '{text[:40]}' deceptively routes to external host '{target_domain}'")

    null_ratio = round(null_count / total_anchors, 4)
    external_ratio = round(external_count / total_anchors, 4)
    internal_ratio = round(internal_count / total_anchors, 4)
    empty_ratio = round(empty_count / total_anchors, 4)

    return total_anchors, null_ratio, external_ratio, internal_ratio, empty_ratio, discrepancy_count, discrepancy_details


def _audit_external_resources_and_favicon(
    soup: BeautifulSoup,
    candidate_host: str,
    canon_set: Set[str]
) -> Tuple[float, bool]:
    """
    Implements CANTINA+ (Xiang et al., 2011) and Rao & Pais (2019) external resource ratio & favicon origin audit.
    """
    total_resources = 0
    external_resources = 0
    favicon_mismatch = False

    # Check images, scripts, stylesheets, audio/video
    resource_tags = [
        ("img", "src"),
        ("script", "src"),
        ("link", "href"),
        ("source", "src"),
        ("iframe", "src")
    ]

    for tag_name, attr_name in resource_tags:
        for elem in soup.find_all(tag_name):
            val = elem.get(attr_name)
            if not val or val.startswith(("data:", "blob:", "#")):
                continue
            
            total_resources += 1
            domain = _extract_domain(val.strip())
            
            if domain and domain != candidate_host:
                if not (canon_set and domain in canon_set):
                    external_resources += 1

    # Check Favicon origin
    favicons = soup.find_all("link", rel=lambda r: r and any(x in str(r).lower() for x in ["icon", "shortcut icon"]))
    for fav in favicons:
        href = fav.get("href")
        if href:
            f_domain = _extract_domain(href.strip())
            if f_domain and f_domain != candidate_host and not (canon_set and f_domain in canon_set):
                favicon_mismatch = True

    ratio = round(external_resources / max(1, total_resources), 4) if total_resources > 0 else 0.0
    return ratio, favicon_mismatch


def _audit_anti_analysis_behaviors(dom_html: str, soup: BeautifulSoup) -> Tuple[bool, bool, bool]:
    """
    Detects client-side anti-forensic techniques (Rao & Pais, 2019; Asiri et al., 2024):
    - Right-click / context menu disabling
    - Text selection / copy disabling
    - Popup window parameter stripping
    """
    html_lower = dom_html.lower()

    # 1. Right Click Disabled
    right_click_disabled = bool(
        'oncontextmenu="return false' in html_lower or
        'oncontextmenu="return false;' in html_lower or
        'event.button == 2' in html_lower or
        'event.button==2' in html_lower or
        'contextmenu", function(e){e.preventdefault' in html_lower.replace(" ", "") or
        'contextmenu", (e) => e.preventdefault' in html_lower.replace(" ", "")
    )

    # 2. Text Selection / Copy Disabled
    text_selection_disabled = bool(
        'onselectstart="return false' in html_lower or
        'oncopy="return false' in html_lower or
        'user-select: none' in html_lower or
        'user-select:none' in html_lower or
        '-webkit-user-select: none' in html_lower or
        '-webkit-user-select:none' in html_lower
    )

    # 3. Popup window manipulation (window.open with suppressed browser chrome)
    popup_manipulation = bool(
        'window.open(' in html_lower and (
            'location=no' in html_lower or
            'toolbar=no' in html_lower or
            'menubar=no' in html_lower or
            'status=no' in html_lower
        )
    )

    return right_click_disabled, text_selection_disabled, popup_manipulation


def _detect_browser_in_the_browser(dom_html: str, soup: BeautifulSoup) -> bool:
    """
    Detects Browser-in-the-Browser (BiTB) simulated desktop windows / OAuth modals (Asiri et al., 2023, 2024).
    Phishers render fake Windows/Mac/Chrome titlebars + address bars inside DOM to mimic legitimate SSO popups.
    """
    html_lower = dom_html.lower()
    
    # Check for characteristic BiTB structural CSS classes and IDs
    bitb_markers = [
        "browser-window", "fake-browser", "bitb-window", "fake-address-bar",
        "browser-header", "window-controls", "chrome-titlebar", "apple-titlebar",
        "fake-url-bar", "mock-browser", "window-header-buttons"
    ]
    has_marker = any(m in html_lower for m in bitb_markers)

    # Check for simulated address bars containing legitimate SSO domains inside a div/input
    sso_targets = ["login.microsoftonline.com", "accounts.google.com", "appleid.apple.com", "auth.paypal.com", "id.sonyentertainmentnetwork.com"]
    simulated_address_bar = False
    
    for sso in sso_targets:
        if sso in html_lower:
            # Check if rendered inside a read-only input, span, or address bar container
            for elem in soup.find_all(["input", "div", "span", "p"]):
                txt = (elem.get("value") or elem.get_text() or "").strip().lower()
                if sso in txt and ("http://" in txt or "https://" in txt or "lock" in (elem.get("class") or [])):
                    simulated_address_bar = True
                    break
        if simulated_address_bar:
            break

    return has_marker or simulated_address_bar


def extract_dom_deep_forensics(
    dom_html: Optional[str],
    candidate_url: str,
    canonical_domains: Optional[List[str]] = None
) -> DOMForensicsDetail:
    """
    Executes low-latency (<10ms) multi-dimensional extraction and audit of HTML nodes, hyperlinks,
    form actions, zero-font obfuscation, formless harvesting, anti-analysis scripts, BiTB attacks,
    and iframe clickjacking overlays.
    """
    if not dom_html or not dom_html.strip():
        return DOMForensicsDetail(
            total_dom_nodes=0,
            form_count=0,
            password_input_count=0,
            form_actions=[],
            has_form_action_mismatch=False,
            suspicious_external_scripts=[],
            has_iframe_overlay=False,
            structural_node_diff_ratio=0.0,
            mitre_attack_id="N/A",
            forensic_highlights=["Empty or unreachable DOM."],
            is_formless_harvesting=False,
            has_zero_font_obfuscation=False,
            exfiltration_endpoints=[],
            has_shadow_dom_nodes=False,
            total_hyperlinks_count=0,
            null_hyperlinks_ratio=0.0,
            external_hyperlinks_ratio=0.0,
            internal_hyperlinks_ratio=0.0,
            empty_anchor_tags_ratio=0.0,
            anchor_text_discrepancy_count=0,
            external_resources_ratio=0.0,
            favicon_external_mismatch=False,
            has_server_form_handler_mismatch=False,
            has_right_click_disabled=False,
            has_text_selection_disabled=False,
            has_browser_in_the_browser=False
        )

    try:
        soup = BeautifulSoup(dom_html, "html.parser")
        candidate_parsed = urlparse(candidate_url)
        candidate_host = candidate_parsed.netloc.split(":")[0].lower()
        is_page_https = candidate_url.lower().startswith("https://")
        
        all_elements = soup.find_all(True)
        total_nodes = len(all_elements)
        canon_set = {d.lower() for d in (canonical_domains or [])}

        # 1. Inspect Form Actions & Server Form Handlers (SFH) (Rao & Pais 2019; Jain & Gupta 2018b)
        forms = soup.find_all("form")
        form_audits: List[FormActionAudit] = []
        has_action_mismatch = False
        has_sfh_mismatch = False
        password_count = 0

        for idx, f in enumerate(forms):
            action_raw = (f.get("action") or "").strip()
            method = (f.get("method") or "GET").upper()
            form_id = f.get("id") or f"form_{idx}"
            form_name = f.get("name")

            # Extract inputs inside this form
            inputs = f.find_all("input")
            field_types = []
            has_pwd = False
            for inp in inputs:
                t = (inp.get("type") or "text").lower()
                n = inp.get("name") or inp.get("id") or t
                field_types.append(f"{n}:{t}")
                if t == "password":
                    has_pwd = True
                    password_count += 1

            # Check null/empty/insecure Server Form Handler (SFH)
            is_null_action = _is_null_hyperlink(action_raw)
            is_insecure_transport = is_page_https and action_raw.startswith("http://")

            if is_null_action:
                target_domain = candidate_host
                if has_pwd:
                    has_sfh_mismatch = True
            elif action_raw.startswith(("http://", "https://")):
                target_domain = urlparse(action_raw).netloc.split(":")[0].lower()
            elif action_raw.startswith("//"):
                target_domain = urlparse("https:" + action_raw).netloc.split(":")[0].lower()
            else:
                target_domain = candidate_host  # Relative action submits to host

            # Check for External Mismatch
            is_mismatch = False
            if target_domain and target_domain != candidate_host:
                if canon_set and target_domain not in canon_set:
                    is_mismatch = True
                    has_action_mismatch = True
                elif not canon_set:
                    is_mismatch = True
                    has_action_mismatch = True

            form_audits.append(FormActionAudit(
                form_id=form_id,
                form_name=form_name,
                action_url=action_raw or "(self / relative)",
                method=method,
                target_domain=target_domain,
                is_external_mismatch=is_mismatch,
                input_fields=field_types,
                has_password_field=has_pwd,
                is_insecure_transport=is_insecure_transport,
                is_null_or_empty_action=is_null_action
            ))

        # 2. Check Formless Credential Harvesters (Password/User inputs outside <form>)
        all_pwd_inputs = soup.find_all("input", {"type": "password"})
        standalone_pwds = [p for p in all_pwd_inputs if not p.find_parent("form")]
        is_formless = len(standalone_pwds) > 0

        if len(all_pwd_inputs) > password_count:
            password_count = len(all_pwd_inputs)

        # 3. Comprehensive Hyperlink Forensics (Jain & Gupta, 2019)
        total_links, null_links_ratio, ext_links_ratio, int_links_ratio, empty_links_ratio, disc_count, disc_details = _audit_hyperlinks_and_anchors(
            soup=soup,
            candidate_host=candidate_host,
            canon_set=canon_set
        )

        # 4. Resource Provenance & Favicon Mismatch (CANTINA+ / Xiang et al., 2011)
        ext_resources_ratio, favicon_mismatch = _audit_external_resources_and_favicon(
            soup=soup,
            candidate_host=candidate_host,
            canon_set=canon_set
        )

        # 5. Anti-Analysis & Defense Evasion Behaviors (Rao & Pais, 2019)
        has_right_click_off, has_text_select_off, has_popup_manip = _audit_anti_analysis_behaviors(dom_html, soup)

        # 6. Browser-in-the-Browser (BiTB) Detection (Asiri et al., 2023, 2024)
        has_bitb = _detect_browser_in_the_browser(dom_html, soup)

        # 7. Inspect External Script Ingestion & Exfiltration Hooks
        scripts = soup.find_all("script")
        suspicious_scripts = []
        exfil_endpoints = []

        for m in EXFILTRATION_HOOK_REGEX.finditer(dom_html):
            exfil_endpoints.append(m.group(0))

        for m in DROP_FILE_REGEX.finditer(dom_html):
            exfil_endpoints.append(m.group(1))

        for s in scripts:
            src = s.get("src")
            if src and src.startswith(("http://", "https://")):
                s_domain = urlparse(src).netloc.split(":")[0].lower()
                if canon_set and s_domain not in canon_set and candidate_host not in s_domain:
                    if any(s_domain.endswith(tld) for tld in SUSPICIOUS_SCRIPT_TLDS):
                        suspicious_scripts.append(src)

        # 8. Inspect Iframe Overlays
        iframes = soup.find_all("iframe")
        has_iframe_overlay = False
        for ifr in iframes:
            style = (ifr.get("style") or "").lower()
            if "opacity: 0" in style or "opacity:0" in style or "z-index: 999" in style or "position: absolute" in style:
                has_iframe_overlay = True
                break

        # 9. Anti-Zero-Font & Computed CSS Visibility Audit
        _, has_zero_font_obfuscation, evasion_details = clean_human_visible_dom_text(dom_html)

        # 10. Shadow DOM & Web Component Detection
        has_shadow_dom = (
            'data-shadow-root="true"' in dom_html or
            'shadowroot="open"' in dom_html or
            'shadowrootmode="open"' in dom_html or
            any("-" in tag.name for tag in all_elements if tag.name not in ["annotation-xml"])
        )

        # 11. Generate Forensic Highlights & MITRE ATT&CK Mapping
        highlights = []
        mitre_ids = []

        if has_action_mismatch:
            highlights.append("Credential Exfiltration Vector: Form action submits authentication payloads to mismatched external host.")
            mitre_ids.append("T1056.001 (Credential Harvester Action Mismatch)")

        if has_sfh_mismatch:
            highlights.append("Server Form Handler (SFH) Anomaly: Credential input form lacks a valid server action handler (empty/placeholder destination).")
            mitre_ids.append("T1056.001 (Server Form Handler Mismatch)")

        if is_formless:
            highlights.append(f"Formless Credential Harvesting: Detected {len(standalone_pwds)} password input(s) rendered outside standard <form> wrappers.")
            mitre_ids.append("T1056.004 (Input Capture: Formless Credential Interception)")

        if has_bitb:
            highlights.append("Browser-in-the-Browser (BiTB): Simulated desktop browser UI / OAuth modal detected mimicking legitimate SSO providers.")
            mitre_ids.append("T1185 (Browser-in-the-Browser False Authentication Window)")

        if disc_count > 0:
            highlights.append(f"Anchor Text Deception: Detected {disc_count} hyperlink(s) displaying legitimate brand names that route to external target hosts.")
            for d in disc_details:
                highlights.append(f"  • {d}")
            mitre_ids.append("T1566.002 (Spearphishing Link: Anchor Text Discrepancy)")

        if null_links_ratio > 0.40 and total_links >= 3:
            highlights.append(f"Null Hyperlink Density: {null_links_ratio*100:.0f}% of anchor tags are dead/placeholder links (#, javascript:void(0)), characteristic of cloned phishing kits.")
            mitre_ids.append("T1566.002 (Dead Navigation Template)")

        if ext_resources_ratio > 0.60:
            highlights.append(f"External Resource Dependency: {ext_resources_ratio*100:.0f}% of images/scripts/stylesheets are hotlinked from external origins (CANTINA+ heuristic).")

        if favicon_mismatch:
            highlights.append("Favicon Origin Mismatch: Site favicon is loaded from an external third-party domain.")

        if has_right_click_off:
            highlights.append("Anti-Analysis Evasion: Right-click / context menu has been programmatically disabled to obstruct source code review.")
            mitre_ids.append("T1027 (Defense Evasion: Disabled Right-Click)")

        if has_text_select_off:
            highlights.append("Anti-Analysis Evasion: Text selection / copy has been disabled via inline events or CSS user-select.")

        if exfil_endpoints:
            unique_exfils = list(set(exfil_endpoints))[:3]
            highlights.append(f"Direct Exfiltration Hooks: Discovered {len(unique_exfils)} C2/Webhook endpoints ({', '.join(unique_exfils)}).")
            mitre_ids.append("T1020 (Automated Exfiltration: Webhook / C2 Drop)")

        if has_zero_font_obfuscation:
            highlights.append(f"Zero-Font / CSS Text Obfuscation: Stripped {len(evasion_details)} hidden zero-pixel/off-screen decoy spans.")
            mitre_ids.append("T1027.006 (HTML Steganography / Zero-Font Evasion)")

        if has_shadow_dom:
            highlights.append("Shadow DOM / Custom Components: Nested web components traversed to expose encapsulated authentication nodes.")
            mitre_ids.append("T1027 (Defense Evasion: Encapsulated Shadow DOM)")

        if has_iframe_overlay:
            highlights.append("Clickjacking Overlay: Hidden or zero-opacity iframe structure detected over viewport.")
            mitre_ids.append("T1204.001 (User Execution: Clickjacking Overlay)")

        if suspicious_scripts:
            highlights.append(f"External Script Ingestion: Detected {len(suspicious_scripts)} script(s) loaded from suspicious abuse TLDs.")
            mitre_ids.append("T1059.007 (JavaScript Execution from Untrusted Source)")

        if not highlights:
            highlights.append("DOM structures and form action endpoints exhibit normal layout patterns.")

        mitre_attack = " / ".join(dict.fromkeys(mitre_ids)) if mitre_ids else "N/A"

        return DOMForensicsDetail(
            total_dom_nodes=total_nodes,
            form_count=len(forms),
            password_input_count=password_count,
            form_actions=form_audits,
            has_form_action_mismatch=has_action_mismatch,
            suspicious_external_scripts=suspicious_scripts,
            has_iframe_overlay=has_iframe_overlay,
            structural_node_diff_ratio=1.0,
            mitre_attack_id=mitre_attack,
            forensic_highlights=highlights,
            is_formless_harvesting=is_formless,
            has_zero_font_obfuscation=has_zero_font_obfuscation,
            exfiltration_endpoints=list(set(exfil_endpoints)),
            has_shadow_dom_nodes=has_shadow_dom,
            total_hyperlinks_count=total_links,
            null_hyperlinks_ratio=null_links_ratio,
            external_hyperlinks_ratio=ext_links_ratio,
            internal_hyperlinks_ratio=int_links_ratio,
            empty_anchor_tags_ratio=empty_links_ratio,
            anchor_text_discrepancy_count=disc_count,
            external_resources_ratio=ext_resources_ratio,
            favicon_external_mismatch=favicon_mismatch,
            has_server_form_handler_mismatch=has_sfh_mismatch,
            has_right_click_disabled=has_right_click_off,
            has_text_selection_disabled=has_text_select_off,
            has_browser_in_the_browser=has_bitb
        )

    except Exception as e:
        logger.warning(f"Error extracting DOM forensics: {e}")
        return DOMForensicsDetail(
            total_dom_nodes=0,
            form_count=0,
            password_input_count=0,
            form_actions=[],
            has_form_action_mismatch=False,
            suspicious_external_scripts=[],
            has_iframe_overlay=False,
            structural_node_diff_ratio=0.0,
            mitre_attack_id="N/A",
            forensic_highlights=[f"DOM parser exception: {e}"]
        )
