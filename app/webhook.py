import os
import json
import logging
import urllib.request
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def dispatch_soc_webhook_alert(
  webhook_url: str,
  scan_result: Dict[str, Any],
  custom_title: Optional[str] = " PhishSentry AI Critical Phishing Alert"
) -> bool:
  """
  Sends an automated JSON alert payload to SOC Webhooks (Slack, MS Teams, Cortex XSOAR, Splunk HEC).
  """
  if not webhook_url or not webhook_url.startswith(("http://", "https://")):
    logger.warning(f"Invalid webhook URL provided: {webhook_url}")
    return False

  url_target = scan_result.get("url", "Unknown")
  s_phish = scan_result.get("s_phish", 0.0)
  matched_brand = scan_result.get("matched_brand", "None")
  latency = scan_result.get("latency_ms", 0.0)
  tls_info = scan_result.get("tls_telemetry") or {}
  resolved_ip = tls_info.get("resolved_ip", "Unknown")
  
  # Universal Webhook Payload
  payload = {
    "text": f"{custom_title}: {url_target} (Risk: {s_phish*100:.1f}%)",
    "attachments": [
      {
        "color": "#ef4444" if s_phish >= 0.65 else "#f59e0b",
        "title": f"Target: {url_target}",
        "fields": [
          {"title": "Threat Score (S_phish)", "value": f"{s_phish*100:.1f}%", "short": True},
          {"title": "Impersonated Brand", "value": (matched_brand or 'None').upper(), "short": True},
          {"title": "Resolved IP", "value": str(resolved_ip), "short": True},
          {"title": "Analysis Latency", "value": f"{latency/1000:.2f}s", "short": True}
        ],
        "footer": "PhishSentry AI Enterprise SOC Sentinel"
      }
    ],
    "raw_scan_data": scan_result
  }

  try:
    req = urllib.request.Request(
      webhook_url,
      data=json.dumps(payload).encode("utf-8"),
      headers={"Content-Type": "application/json", "User-Agent": "PhishSentry-SOC-Webhook/1.2"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
      logger.info(f"Successfully dispatched webhook alert (HTTP {resp.status}) to {webhook_url}")
      return True
  except Exception as e:
    logger.warning(f"Failed to dispatch webhook alert: {e}")
    return False
