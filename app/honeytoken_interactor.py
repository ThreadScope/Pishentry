"""
app/honeytoken_interactor.py
=============================
Autonomous Synthetic Honeytoken Interaction & Exfiltration Trapping Engine.

When an authentication form or credential prompt is detected in Playwright,
this engine injects uniquely tagged synthetic honeytoken test credentials
and listens to the dynamic browser network layer to trap the destination
of the outgoing credential POST request (Discord webhook, Telegram bot, C2 drop, etc.).
"""

import re
import uuid
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class HoneytokenTelemetry(BaseModel):
    is_trapped: bool = Field(False, description="True if honeytoken submission exfiltration was trapped")
    decoy_identifier: str = Field("", description="Unique synthetic canary username")
    exfiltration_destination: Optional[str] = Field(None, description="Captured destination URL of credential POST")
    exfiltration_protocol: Optional[str] = Field(None, description="HTTP_POST, DISCORD_WEBHOOK, TELEGRAM_BOT, WEBSOCKET")
    exfiltration_host: Optional[str] = Field(None, description="Host header of exfiltration endpoint")
    is_external_c2: bool = Field(False, description="True if exfiltrating outside target domain")
    trapped_payload_preview: Optional[str] = Field(None, description="Redacted preview of captured exfiltration packet")
    mitre_technique: str = Field("T1056.001", description="MITRE ATT&CK: Input Capture - Web-based Credential Harvesting")
    evidence: List[str] = Field(default_factory=list, description="Forensic audit trail")

# Well-known malicious exfiltration drops
DISCORD_WEBHOOK_PATTERN = re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", re.IGNORECASE)
TELEGRAM_BOT_PATTERN = re.compile(r"api\.telegram\.org/bot\d+:[\w-]+/send(?:Message|Document)", re.IGNORECASE)
C2_DROP_SCRIPTS = ["gate.php", "login.php", "drop.php", "exfil.php", "stealer.php", "pass.php", "action.php", "send.php", "submit.php"]

def analyze_outbound_network_requests(
    target_url: str,
    captured_requests: List[Dict[str, Any]],
    decoy_id: str
) -> HoneytokenTelemetry:
    """
    Parses intercepted network POST requests to determine if synthetic honeytokens were exfiltrated.
    """
    if not captured_requests:
        return HoneytokenTelemetry(
            is_trapped=False,
            decoy_identifier=decoy_id,
            evidence=["No form submission or network exfiltration triggers executed."]
        )

    evidence = []
    exfil_dest = None
    exfil_proto = "HTTP_POST"
    exfil_host = None
    is_external = False
    trapped_payload = None

    import urllib.parse
    target_parsed = urllib.parse.urlparse(target_url)
    target_host = target_parsed.netloc.lower()

    for req in captured_requests:
        req_url = req.get("url", "")
        req_method = req.get("method", "GET").upper()
        req_post_data = str(req.get("post_data", ""))
        
        req_parsed = urllib.parse.urlparse(req_url)
        req_host = req_parsed.netloc.lower()

        # Check if request contained decoy token or standard password payload
        has_canary = decoy_id in req_post_data or "decoy" in req_post_data or "sec-trap" in req_post_data
        
        # Check Discord Webhook
        if DISCORD_WEBHOOK_PATTERN.search(req_url) or "discord.com/api/webhooks" in req_url:
            exfil_dest = req_url
            exfil_proto = "DISCORD_WEBHOOK"
            exfil_host = req_host
            is_external = True
            evidence.append(f"CRITICAL: Credentials exfiltrate directly to an active Discord Webhook endpoint: {req_host}")
            trapped_payload = "Decoy credentials dispatched to Discord Webhook channel."
            break

        # Check Telegram Bot
        if TELEGRAM_BOT_PATTERN.search(req_url) or "api.telegram.org/bot" in req_url:
            exfil_dest = req_url
            exfil_proto = "TELEGRAM_BOT"
            exfil_host = req_host
            is_external = True
            evidence.append(f"CRITICAL: Credentials exfiltrate to an automated Telegram C2 Bot: {req_host}")
            trapped_payload = "Decoy credentials dispatched to Telegram Bot chat."
            break

        # Check external credential harvesting host
        if req_method in ["POST", "PUT"] and (has_canary or "password=" in req_post_data or "pass=" in req_post_data):
            exfil_dest = req_url
            exfil_host = req_host
            is_external = (req_host != target_host and not req_host.endswith(f".{target_host}"))
            
            if any(s in req_url.lower() for s in C2_DROP_SCRIPTS):
                evidence.append(f"Identified credential drop script: {req_url}")
            
            if is_external:
                evidence.append(f"Cross-Origin Exfiltration: Target submits credentials to foreign backend: {req_host}")
            else:
                evidence.append(f"Local Form Capture: Target accepts POST credentials at {req_url}")

            trapped_payload = f"Captured {req_method} to {req_host} ({len(req_post_data)} bytes)"
            break

    if exfil_dest:
        return HoneytokenTelemetry(
            is_trapped=True,
            decoy_identifier=decoy_id,
            exfiltration_destination=exfil_dest,
            exfiltration_protocol=exfil_proto,
            exfiltration_host=exfil_host,
            is_external_c2=is_external,
            trapped_payload_preview=trapped_payload,
            evidence=evidence
        )

    return HoneytokenTelemetry(
        is_trapped=False,
        decoy_identifier=decoy_id,
        evidence=["Authentication forms inspected. Outbound credential exfiltration was silent or dormant."]
    )

def generate_canary_identity() -> Tuple_Decoy:
    """Generates a randomized, tagged synthetic decoy credential pair."""
    canary_id = f"decoy.{uuid.uuid4().hex[:8]}@sec-trap.internal"
    canary_pw = f"TrapP@ss!{uuid.uuid4().hex[:6]}"
    return canary_id, canary_pw

from typing import Tuple as Tuple_Decoy
