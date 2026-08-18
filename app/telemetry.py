import asyncio
import socket
import ssl
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Optional, List, Dict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Known free or automated Certificate Authorities commonly abused for short-lived phishing campaigns
AUTOMATED_FREE_CAS = {
    "let's encrypt", "zerossl", "cpanel, inc.", "cloudflare, inc.", "google trust services llc",
    "buypass", "ssl.com", "certum", "actalis"
}

@dataclass
class TLSInfo:
    has_tls: bool
    issuer: Optional[str]
    subject: Optional[str]
    san_list: List[str]
    valid_from: Optional[str]
    valid_to: Optional[str]
    days_to_expiry: Optional[int]
    is_self_signed: bool
    is_free_ca: bool
    resolved_ip: Optional[str]
    error_detail: Optional[str]

async def extract_tls_telemetry(url: str, timeout_seconds: float = 3.0) -> TLSInfo:
    """
    Asynchronously probes the target host to extract TLS certificate metadata,
    validity timelines, Subject Alternative Names (SANs), and IP resolution.
    Runs non-blockingly via asyncio socket wrapper.
    """
    cleaned = url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
        
    parsed = urllib.parse.urlparse(cleaned)
    hostname = parsed.netloc.split(":")[0]
    port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)

    if not hostname:
        return TLSInfo(
            has_tls=False, issuer=None, subject=None, san_list=[],
            valid_from=None, valid_to=None, days_to_expiry=None,
            is_self_signed=False, is_free_ca=False, resolved_ip=None,
            error_detail="Invalid hostname"
        )

    # 1. Resolve IP asynchronously
    resolved_ip = None
    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(hostname, port, family=socket.AF_INET)
        if addr_info:
            resolved_ip = addr_info[0][4][0]
    except Exception as e:
        logger.debug(f"DNS resolution failed for {hostname}: {e}")

    # If HTTP only and port is 80 without SSL
    if parsed.scheme == "http" and port == 80:
        return TLSInfo(
            has_tls=False, issuer=None, subject=None, san_list=[],
            valid_from=None, valid_to=None, days_to_expiry=None,
            is_self_signed=False, is_free_ca=False, resolved_ip=resolved_ip,
            error_detail="Insecure plain HTTP transport"
        )

    # 2. Probe TLS certificate in a worker thread with timeout
    def _probe_ssl() -> TLSInfo:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE  # Accept unverified certs to inspect self-signed/phishing certs

        try:
            with socket.create_connection((hostname, port or 443), timeout=timeout_seconds) as sock:
                with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    # Extract fields from peer cert dict
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    
                    issuer_org = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))
                    subject_cn = subject_dict.get("commonName", hostname)
                    
                    san_list = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
                    
                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")
                    
                    days_left = None
                    if not_after:
                        try:
                            # Format: 'May 15 12:00:00 2026 GMT'
                            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_left = (exp_dt - now).days
                        except Exception:
                            pass

                    is_self_signed = (issuer_dict == subject_dict) and bool(issuer_dict)
                    is_free_ca = any(ca in issuer_org.lower() for ca in AUTOMATED_FREE_CAS)

                    return TLSInfo(
                        has_tls=True,
                        issuer=issuer_org,
                        subject=subject_cn,
                        san_list=san_list[:10],  # cap at 10 for clean reporting
                        valid_from=not_before,
                        valid_to=not_after,
                        days_to_expiry=days_left,
                        is_self_signed=is_self_signed,
                        is_free_ca=is_free_ca,
                        resolved_ip=resolved_ip,
                        error_detail=None
                    )
        except Exception as e:
            return TLSInfo(
                has_tls=False, issuer=None, subject=None, san_list=[],
                valid_from=None, valid_to=None, days_to_expiry=None,
                is_self_signed=False, is_free_ca=False, resolved_ip=resolved_ip,
                error_detail=str(e)
            )

    try:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(loop.run_in_executor(None, _probe_ssl), timeout=timeout_seconds + 0.5)
    except Exception as e:
        return TLSInfo(
            has_tls=False, issuer=None, subject=None, san_list=[],
            valid_from=None, valid_to=None, days_to_expiry=None,
            is_self_signed=False, is_free_ca=False, resolved_ip=resolved_ip,
            error_detail=f"TLS probe timeout ({e})"
        )
