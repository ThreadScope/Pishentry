"""
app/firewall_rules.py
======================
Multi-Vendor Automated Firewall & WAF Rule Generator.

Generates production-ready, syntax-exact security enforcement rules for:
- Palo Alto Networks (PAN-OS CLI & XML)
- Cloudflare WAF (Custom Expression JSON)
- Fortinet FortiGate (CLI configuration)
- Cisco ASA (ACL syntax)
- Suricata / Snort IPS (Network signature rule)
"""

import urllib.parse
from typing import Dict, Any
from pydantic import BaseModel, Field

class MultiVendorFirewallRules(BaseModel):
    target_domain: str
    target_ip: str = "any"
    palo_alto_cli: str
    cloudflare_waf_json: str
    fortigate_cli: str
    cisco_asa_acl: str
    suricata_ips_rule: str

def generate_multi_vendor_firewall_rules(scan_result: Dict[str, Any]) -> MultiVendorFirewallRules:
    """
    Generates syntax-exact blocking rules across 5 major network security platforms.
    """
    url = scan_result.get("url", "")
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower() or "suspicious-phish.net"
    clean_tag = domain.replace(".", "_").replace("-", "_")
    
    tls_data = scan_result.get("tls_telemetry") or {}
    resolved_ip = tls_data.get("resolved_ip") or "0.0.0.0"
    s_phish = scan_result.get("s_phish", 0.0)

    # 1. Palo Alto Networks PAN-OS CLI
    palo_alto = f"""# --- Palo Alto Networks PAN-OS Configuration ---
set address ADDR_PHISH_{clean_tag} fqdn {domain}
set address-group GRP_PHISH_BLOCK address ADDR_PHISH_{clean_tag}
set security rules RULE_BLOCK_PHISHSENTRY_{clean_tag} to any from trust source any destination ADDR_PHISH_{clean_tag} application any service any action drop log-end yes
commit
"""

    # 2. Cloudflare WAF JSON Expression
    cf_expr = f'(http.host eq "{domain}" or ssl.client.hello.sni eq "{domain}")'
    cloudflare_json = f"""{{
  "name": "CloneCatcher AI - Block Malicious Phishing Domain {domain}",
  "description": "Automated AI block rule (Score: {s_phish:.2f})",
  "action": "block",
  "expression": "{cf_expr}",
  "enabled": true
}}"""

    # 3. Fortinet FortiGate CLI
    fortigate = f"""# --- Fortinet FortiGate CLI ---
config firewall address
    edit "ADDR_{clean_tag}"
        set type fqdn
        set fqdn "{domain}"
    next
end
config firewall policy
    edit 0
        set name "CloneCatcher_Block_{clean_tag}"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "ADDR_{clean_tag}"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
"""

    # 4. Cisco ASA ACL
    cisco = f"""! --- Cisco ASA Security Appliance ---
object network OBJ_PHISH_{clean_tag}
 fqdn v4 {domain}
access-list OUTSIDE_IN deny ip any object OBJ_PHISH_{clean_tag}
access-list INSIDE_OUT deny ip any object OBJ_PHISH_{clean_tag}
"""

    # 5. Suricata / Snort IPS Rule
    suricata = f"""# --- Suricata / Snort IPS Rule ---
drop http $HOME_NET any -> $EXTERNAL_NET any (msg:"CloneCatcher AI - Blocked outbound connection to phishing domain {domain}"; http.host; content:"{domain}"; nocase; classtype:trojan-activity; sid:9001{abs(hash(domain))%9000:04d}; rev:1;)
drop tls $HOME_NET any -> $EXTERNAL_NET any (msg:"CloneCatcher AI - Blocked TLS SNI to phishing domain {domain}"; tls.sni; content:"{domain}"; nocase; classtype:trojan-activity; sid:9002{abs(hash(domain))%9000:04d}; rev:1;)
"""

    return MultiVendorFirewallRules(
        target_domain=domain,
        target_ip=resolved_ip,
        palo_alto_cli=palo_alto,
        cloudflare_waf_json=cloudflare_json,
        fortigate_cli=fortigate,
        cisco_asa_acl=cisco,
        suricata_ips_rule=suricata
    )
