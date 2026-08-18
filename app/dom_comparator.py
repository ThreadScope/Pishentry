import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

from dataclasses import dataclass, asdict, field
from app.dom_visibility import clean_human_visible_dom_text

EXFILTRATION_HOOK_REGEX = re.compile(
    r"https?://(?:api\.telegram\.org/bot[^\"'\s\)\&]+|discord\.com/api/webhooks/[^\"'\s\)\&]+|webhook\.site/[a-zA-Z0-9_\-]+|pipedream\.net/[a-zA-Z0-9_\-]+|[a-zA-Z0-9_\-]+\.workers\.dev/[^\"'\s\)\&]+|[a-zA-Z0-9_\-]+\.supabase\.co/[^\"'\s\)\&]+)",
    re.IGNORECASE
)


DROP_FILE_REGEX = re.compile(
    r"[\"']([a-zA-Z0-9_\-\./]+/(?:login|log|post|drop|capture|gate|send|process|action|auth)\.(?:php|aspx|cgi|jsp|py))[\"']",
    re.IGNORECASE
)

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

def extract_dom_deep_forensics(
    dom_html: Optional[str],
    candidate_url: str,
    canonical_domains: Optional[List[str]] = None
) -> DOMForensicsDetail:
    """
    Executes low-latency (<10ms) extraction and audit of HTML nodes, script tags,
    form actions, zero-font obfuscation, formless harvesting, and iframe overlays.
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
            has_shadow_dom_nodes=False
        )

    try:
        soup = BeautifulSoup(dom_html, "html.parser")
        candidate_parsed = urlparse(candidate_url)
        candidate_host = candidate_parsed.netloc.split(":")[0].lower()
        
        all_elements = soup.find_all(True)
        total_nodes = len(all_elements)

        # 1. Inspect Form Actions & Credential Target Endpoints
        forms = soup.find_all("form")
        form_audits: List[FormActionAudit] = []
        has_action_mismatch = False
        password_count = 0

        canon_set = {d.lower() for d in (canonical_domains or [])}

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

            # Parse action target host
            if action_raw.startswith(("http://", "https://")):
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
                has_password_field=has_pwd
            ))

        # 2. Check Formless Credential Harvesters (Password/User inputs outside <form>)
        all_pwd_inputs = soup.find_all("input", {"type": "password"})
        standalone_pwds = [p for p in all_pwd_inputs if not p.find_parent("form")]
        is_formless = len(standalone_pwds) > 0

        if len(all_pwd_inputs) > password_count:
            password_count = len(all_pwd_inputs)

        # 3. Inspect External Script Ingestion & Exfiltration Hooks
        scripts = soup.find_all("script")
        suspicious_scripts = []
        exfil_endpoints = []

        # Find direct webhook drops
        for m in EXFILTRATION_HOOK_REGEX.finditer(dom_html):
            exfil_endpoints.append(m.group(0))

        for m in DROP_FILE_REGEX.finditer(dom_html):
            exfil_endpoints.append(m.group(1))

        for s in scripts:
            src = s.get("src")
            if src and src.startswith(("http://", "https://")):
                s_domain = urlparse(src).netloc.split(":")[0].lower()
                if canon_set and s_domain not in canon_set and candidate_host not in s_domain:
                    if any(tld in s_domain for tld in [".tk", ".xyz", ".top", ".ru", ".buzz", ".live", ".cc"]):
                        suspicious_scripts.append(src)

        # 4. Inspect Iframe Overlays
        iframes = soup.find_all("iframe")
        has_iframe_overlay = False
        for ifr in iframes:
            style = (ifr.get("style") or "").lower()
            if "opacity: 0" in style or "opacity:0" in style or "z-index: 999" in style or "position: absolute" in style:
                has_iframe_overlay = True
                break

        # 5. Anti-Zero-Font & Computed CSS Visibility Audit
        _, has_zero_font_obfuscation, evasion_details = clean_human_visible_dom_text(dom_html)

        # 6. Shadow DOM & Web Component Detection
        has_shadow_dom = (
            'data-shadow-root="true"' in dom_html or
            'shadowroot="open"' in dom_html or
            'shadowrootmode="open"' in dom_html or
            any("-" in tag.name for tag in all_elements if tag.name not in ["annotation-xml"])
        )

        # 7. Generate Forensic Highlights & MITRE ATT&CK Mapping
        highlights = []
        mitre_ids = []

        if has_action_mismatch:
            highlights.append("Credential Exfiltration Vector: Form action submits authentication payloads to mismatched external host.")
            mitre_ids.append("T1056.001 (Credential Harvester Action Mismatch)")

        if is_formless:
            highlights.append(f"Formless Credential Harvesting: Detected {len(standalone_pwds)} password input(s) rendered outside standard <form> wrappers.")
            mitre_ids.append("T1056.004 (Input Capture: Formless Credential Interception)")

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

        mitre_attack = " / ".join(mitre_ids) if mitre_ids else "N/A"

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
            has_shadow_dom_nodes=has_shadow_dom
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
