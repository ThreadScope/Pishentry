"""
app/redirect_graph.py
======================
Multi-Hop Redirection Lineage & Graph Path Analyzer.

Traces multi-stage redirect chains, measuring hop count, URL shorteners,
open redirects, protocol downgrades, and ASN domain transitions used by
phishing delivery infrastructure.
"""

import re
import urllib.parse
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class RedirectHop(BaseModel):
    hop_index: int = Field(..., description="0-indexed sequence in chain")
    url: str = Field(..., description="URL at this hop")
    domain: str = Field(..., description="Domain hostname")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    is_shortener: bool = Field(False, description="True if URL shortener")
    is_open_redirect: bool = Field(False, description="True if intermediate redirector")
    protocol: str = Field("https", description="http or https")

class RedirectGraphResult(BaseModel):
    hop_count: int = Field(0, description="Total number of redirect hops")
    initial_url: str = Field("", description="Origin entry URL")
    final_destination_url: str = Field("", description="Final resolved landing URL")
    has_url_shortener: bool = Field(False, description="Chain utilizes link shorteners (bit.ly, t.co, etc.)")
    has_open_redirect: bool = Field(False, description="Chain abuses trusted open redirectors")
    has_protocol_downgrade: bool = Field(False, description="HTTPS was downgraded to insecure HTTP")
    unique_domains_in_chain: int = Field(1, description="Number of distinct domains in path")
    graph_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Redirect topology risk score")
    hops: List[RedirectHop] = Field(default_factory=list, description="Ordered hops")
    evidence: List[str] = Field(default_factory=list, description="Forensic audit trail")

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "trib.al", "linktr.ee"
]

OPEN_REDIRECT_PARAMS = ["redirect", "url", "next", "target", "dest", "r", "u", "return", "link", "goto", "out"]

async def trace_redirect_graph(initial_url: str, timeout_sec: float = 4.0) -> RedirectGraphResult:
    """
    Traces the redirection graph of a candidate URL using asynchronous HTTP inspection.
    """
    import httpx

    hops: List[RedirectHop] = []
    evidence: List[str] = []
    has_shortener = False
    has_open_red = False
    has_downgrade = False
    distinct_domains = set()

    current_url = initial_url
    hop_idx = 0

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        async with httpx.AsyncClient(timeout=timeout_sec, follow_redirects=False, verify=False) as client:
            while hop_idx < 8:
                parsed = urllib.parse.urlparse(current_url)
                host = parsed.netloc.lower()
                proto = parsed.scheme.lower()
                distinct_domains.add(host)

                # Check shortener
                is_short = any(s in host for s in URL_SHORTENERS)
                if is_short:
                    has_shortener = True

                # Check open redirect param
                q_params = urllib.parse.parse_qs(parsed.query)
                is_open = any(p in q_params for p in OPEN_REDIRECT_PARAMS)
                if is_open and hop_idx > 0:
                    has_open_red = True

                try:
                    resp = await client.get(current_url, headers=headers)
                    status = resp.status_code
                    next_url = resp.headers.get("location")
                except Exception:
                    status = 200
                    next_url = None

                hops.append(RedirectHop(
                    hop_index=hop_idx,
                    url=current_url,
                    domain=host,
                    status_code=status,
                    is_shortener=is_short,
                    is_open_redirect=is_open,
                    protocol=proto
                ))

                if not next_url or status not in [301, 302, 303, 307, 308]:
                    break

                # Resolve relative redirects
                next_full = urllib.parse.urljoin(current_url, next_url)
                
                # Check protocol downgrade
                next_proto = urllib.parse.urlparse(next_full).scheme.lower()
                if proto == "https" and next_proto == "http":
                    has_downgrade = True

                current_url = next_full
                hop_idx += 1

    except Exception as e:
        logger.debug(f"Redirect graph tracer encountered: {e}")

    # Fallback if no hops recorded
    if not hops:
        parsed = urllib.parse.urlparse(initial_url)
        hops.append(RedirectHop(
            hop_index=0,
            url=initial_url,
            domain=parsed.netloc.lower(),
            status_code=200,
            protocol=parsed.scheme.lower()
        ))
        distinct_domains.add(parsed.netloc.lower())

    final_dest = hops[-1].url
    hop_count = len(hops)

    # Compute risk score
    risk = 0.0
    if hop_count >= 3:
        risk += 0.35
        evidence.append(f"Multi-Hop Chain: {hop_count} sequential redirection hops detected.")
    if has_shortener:
        risk += 0.25
        evidence.append("Obfuscated Link Shortener: Chain masks destination using public shortener service.")
    if has_open_red:
        risk += 0.30
        evidence.append("Open Redirector Abuse: Intermediate hop exploits trusted domain redirection parameter.")
    if has_downgrade:
        risk += 0.20
        evidence.append("Protocol Downgrade: HTTPS transport downgraded to insecure plaintext HTTP.")
    if len(distinct_domains) >= 3:
        risk += 0.20
        evidence.append(f"Cross-Domain Hopping: {len(distinct_domains)} unique domains spanned across chain.")

    risk = min(1.0, risk)

    return RedirectGraphResult(
        hop_count=hop_count,
        initial_url=initial_url,
        final_destination_url=final_dest,
        has_url_shortener=has_shortener,
        has_open_redirect=has_open_red,
        has_protocol_downgrade=has_downgrade,
        unique_domains_in_chain=len(distinct_domains),
        graph_risk_score=risk,
        hops=hops,
        evidence=evidence
    )
