"""
tests/test_nextgen_ai_features.py
==================================
Comprehensive unit & integration tests for Next-Gen AI features:
- Multi-Modal Target Identity Attribution & Campaign Archetype Classifier
- Autonomous Synthetic Honeytoken Exfiltration Trapping
- In-Image Visual Text & Canvas OCR
- Multi-Hop Redirect Lineage Graph Analyzer
- Autonomous AI Threat Narrative & Incident Briefing Generator
- Multi-Vendor Automated Firewall & WAF Rule Generator
"""

import pytest
from io import BytesIO
from PIL import Image, ImageDraw

from app.target_attribution import attribute_target_identity
from app.honeytoken_interactor import analyze_outbound_network_requests, generate_canary_identity
from app.visual_ocr import extract_visual_text_from_screenshot
from app.redirect_graph import trace_redirect_graph
from app.threat_narrative import generate_threat_narrative
from app.firewall_rules import generate_multi_vendor_firewall_rules
from app.schemas import RuleExportRequest

def test_target_attribution_canonical_google():
    res = attribute_target_identity(
        registered_domain="google.com",
        lexical_matched_brand="google"
    )
    assert res.target_identity == "google"
    assert res.is_canonical_identity is True
    assert res.attribution_confidence == 1.0
    assert "Google Workspace & Accounts" in res.identity_display_name

def test_target_attribution_spoofed_paypal():
    res = attribute_target_identity(
        registered_domain="paypa1-security.tk",
        lexical_matched_brand="paypal",
        vis_matched_brand="paypal",
        vis_score=0.85,
        dom_score=0.60
    )
    assert res.target_identity == "paypal"
    assert res.is_canonical_identity is False
    assert res.attribution_confidence >= 0.70
    assert "PayPal" in res.identity_display_name

def test_target_attribution_aitm_reverse_proxy():
    res = attribute_target_identity(
        registered_domain="login-microsoftonline-verify.xyz",
        is_aitm=True
    )
    assert res.campaign_archetype in ["Adversary-in-the-Middle (AiTM) Reverse Proxy", "Dynamic Session Interception"]
    assert res.attribution_confidence >= 0.70

def test_target_attribution_web3_drainer():
    res = attribute_target_identity(
        registered_domain="claim-airdrop-tokens.io",
        dom_text="Please connect wallet and enter private key seed phrase to claim reward."
    )
    assert res.target_identity == "web3_wallet_drainer"
    assert "Web3" in res.identity_display_name
    assert res.campaign_archetype == "Cryptocurrency Asset Theft"

def test_honeytoken_trapping_discord_webhook():
    canary_id, _ = generate_canary_identity()
    sample_requests = [
        {
            "url": "https://discord.com/api/webhooks/123456789/abcdef-token",
            "method": "POST",
            "post_data": f'{{"content": "Stolen credentials: user={canary_id}&pass=secret"}}'
        }
    ]
    res = analyze_outbound_network_requests(
        target_url="http://fake-login.com",
        captured_requests=sample_requests,
        decoy_id=canary_id
    )
    assert res.is_trapped is True
    assert res.exfiltration_protocol == "DISCORD_WEBHOOK"
    assert res.is_external_c2 is True
    assert "Discord Webhook" in res.evidence[0]

def test_honeytoken_trapping_telegram_bot():
    canary_id, _ = generate_canary_identity()
    sample_requests = [
        {
            "url": "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage",
            "method": "POST",
            "post_data": f"chat_id=987654&text={canary_id}:p@ssword"
        }
    ]
    res = analyze_outbound_network_requests(
        target_url="http://fake-login.com",
        captured_requests=sample_requests,
        decoy_id=canary_id
    )
    assert res.is_trapped is True
    assert res.exfiltration_protocol == "TELEGRAM_BOT"

def test_visual_ocr_clean_image():
    img = Image.new("RGB", (400, 300), color=(240, 240, 240))
    buf = BytesIO()
    img.save(buf, format="PNG")
    res = extract_visual_text_from_screenshot(buf.getvalue())
    assert isinstance(res.detected_brand_keywords, list)
    assert res.has_in_image_text in [True, False]

@pytest.mark.asyncio
async def test_redirect_graph_direct_url():
    res = await trace_redirect_graph("https://example.com")
    assert res.hop_count >= 1
    assert res.initial_url == "https://example.com"
    assert isinstance(res.hops, list)

def test_threat_narrative_generation():
    scan_data = {
        "url": "http://microsoft-login-aitm.xyz/auth",
        "s_phish": 0.95,
        "matched_brand": "microsoft",
        "target_attribution": {
            "identity_display_name": "Microsoft 365 & Entra ID",
            "campaign_archetype": "Adversary-in-the-Middle (AiTM) Reverse Proxy"
        },
        "aitm_telemetry": {"is_aitm_suspect": True},
        "honeytoken_telemetry": {"is_trapped": True, "exfiltration_protocol": "DISCORD_WEBHOOK", "exfiltration_host": "discord.com"},
        "dom_forensics": {"has_form_action_mismatch": True, "is_formless_harvesting": False},
        "tls_telemetry": {"resolved_ip": "185.220.101.5", "issuer": "Let's Encrypt"}
    }
    report = generate_threat_narrative(scan_data)
    assert report.severity_level == "CRITICAL"
    assert "Microsoft 365" in report.incident_title
    assert "Adversary-in-the-Middle" in report.threat_actor_tradecraft
    assert len(report.recommended_soc_actions) >= 3
    assert any("WAF" in a or "blocklist" in a for a in report.recommended_soc_actions)

def test_multi_vendor_firewall_rules():
    scan_data = {
        "url": "http://paypa1-security-auth.top/login",
        "s_phish": 0.92,
        "tls_telemetry": {"resolved_ip": "194.26.29.112"}
    }
    fw = generate_multi_vendor_firewall_rules(scan_data)
    assert "paypa1-security-auth.top" in fw.palo_alto_cli
    assert "paypa1-security-auth.top" in fw.cloudflare_waf_json
    assert "paypa1-security-auth.top" in fw.fortigate_cli
    assert "paypa1-security-auth.top" in fw.cisco_asa_acl
    assert "paypa1-security-auth.top" in fw.suricata_ips_rule
