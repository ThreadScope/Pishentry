import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def generate_sigma_rule(scan_result: Dict[str, Any]) -> str:
    """
    Generates a Sigma Detection Rule (YAML) for SIEM log ingestion (Splunk, Elastic, Sentinel)
    to detect network connections or proxy logs to this malicious phishing URL.
    """
    url = scan_result.get("url", "unknown")
    matched_brand = (scan_result.get("matched_brand") or "generic_brand").upper()
    s_phish = scan_result.get("s_phish", 0.0)
    rule_id = str(uuid.uuid4())
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    domain = url.split("://")[-1].split("/")[0].split(":")[0]

    yaml_rule = f"""title: CloneCatcher AI - Phishing Impersonation of {matched_brand}
id: {rule_id}
status: experimental
description: Detects outbound web proxy requests to confirmed phishing campaign impersonating {matched_brand} (Score: {s_phish:.2f}).
references:
    - https://attack.mitre.org/techniques/T1566/002/
author: CloneCatcher AI SOC Auto-Generator
date: {today}
tags:
    - attack.initial_access
    - attack.t1566.002
    - attack.t1556
logsource:
    category: proxy
    product: zeek_http / proxy_logs
detection:
    selection_domain:
        c-uri|contains: '{domain}'
    selection_url:
        c-uri: '{url}'
    condition: selection_domain or selection_url
fields:
    - c-ip
    - c-uri
    - cs-method
    - cs-host
falsepositives:
    - Legitimate connections to authorized partner domains
level: critical
"""
    return yaml_rule.strip()

def generate_yara_rule(scan_result: Dict[str, Any]) -> str:
    """
    Generates a YARA rule for network payload, proxy packet analysis, or memory scanning.
    """
    url = scan_result.get("url", "unknown")
    domain = url.split("://")[-1].split("/")[0].split(":")[0]
    clean_domain_tag = domain.replace(".", "_").replace("-", "_")
    matched_brand = (scan_result.get("matched_brand") or "Phish").replace(" ", "_")
    today = datetime.now(timezone.utc).strftime("%Y%m%d")

    yara_rule = f"""rule CloneCatcher_{matched_brand}_{clean_domain_tag}_{today} {{
    meta:
        description = "CloneCatcher AI automated detection for {matched_brand} credential harvester"
        author = "CloneCatcher AI Security Pipeline"
        date = "{today}"
        threat_level = "Critical"
        target_domain = "{domain}"
    strings:
        $url_pattern = "{url}" ascii wide nocase
        $domain_pattern = "{domain}" ascii wide nocase
        $form_input = "password" ascii nocase
    condition:
        ($url_pattern or $domain_pattern) and $form_input
}}"""
    return yara_rule.strip()

def generate_dns_blocklist(scan_results: List[Dict[str, Any]]) -> str:
    """
    Generates a Pi-hole / BIND RPZ / Palo Alto EDL formatted DNS firewall blocklist.
    """
    lines = [
        "# ========================================================",
        "# CloneCatcher AI Threat Intelligence — DNS Firewall Feed",
        f"# Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}",
        "# Format: Standard FQDN Blocklist (RPZ / Pi-hole / Palo Alto EDL)",
        "# ========================================================",
        ""
    ]

    domains_seen = set()
    for r in scan_results:
        if r.get("s_phish", 0.0) >= 0.35:
            u = r.get("url", "")
            d = u.split("://")[-1].split("/")[0].split(":")[0].strip()
            if d and d not in domains_seen and not d.startswith("127.") and not d.startswith("localhost"):
                domains_seen.add(d)
                lines.append(f"0.0.0.0 {d} # S_phish={r.get('s_phish', 0):.2f} Matched={r.get('matched_brand', 'none')}")

    return "\n".join(lines)
