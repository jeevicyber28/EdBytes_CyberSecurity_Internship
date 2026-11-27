"""Synthetic phishing indicator checker for educational triage practice."""

from __future__ import annotations

import ipaddress
import re
import sys
from urllib.parse import urlparse

RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".ps1", ".docm", ".xlsm", ".zip", ".iso")
URGENCY_TERMS = ("urgent", "immediately", "suspended", "verify now", "wire transfer", "overdue")


def inspect_url(raw_url: str) -> list[str]:
    findings: list[str] = []
    parsed = urlparse(raw_url.strip())
    host = (parsed.hostname or "").lower()

    if not host:
        findings.append("missing or unparseable hostname")
        return findings

    if parsed.scheme != "https":
        findings.append(f"non-HTTPS scheme ({parsed.scheme or 'none'})")

    try:
        ipaddress.ip_address(host)
        findings.append("raw IP literal used instead of domain name")
    except ValueError:
        pass

    if host.endswith(".invalid") or host.endswith(".example"):
        findings.append(f"reserved/unverified synthetic domain ({host})")

    if "@" in raw_url:
        findings.append("contains '@' userinfo trick in URL")

    if host.count("-") >= 2 or host.count(".") >= 3:
        findings.append("multi-hyphen or deeply nested subdomain pattern")

    return findings


def analyze_message(subject: str, body: str, urls: list[str] | None = None, attachments: list[str] | None = None) -> dict:
    urls = urls or []
    attachments = attachments or []
    combined = f"{subject} {body}".lower()

    indicators: list[str] = []
    for term in URGENCY_TERMS:
        if re.search(rf"\b{re.escape(term)}\b", combined):
            indicators.append(f"urgency/pressure phrase detected: '{term}'")

    if "mismatched" in combined or "changed bank" in combined:
        indicators.append("payment destination change or mismatch mentioned")

    if "password" in combined and urls:
        indicators.append("message combines credential request with external link")

    for url in urls:
        for flag in inspect_url(url):
            indicators.append(f"URL [{url}]: {flag}")

    for filename in attachments:
        lower = filename.strip().lower()
        if lower.endswith(RISKY_EXTENSIONS):
            indicators.append(f"unexpected risky attachment extension: '{filename}'")

    verdict = "review_out_of_band" if indicators else "no_obvious_red_flags"
    return {
        "verdict": verdict,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "note": "Indicators suggest verification via a known channel; appearances alone are inconclusive.",
    }


if __name__ == "__main__":
    sample_url = sys.argv[1] if len(sys.argv) > 1 else "http://college-login.example.invalid/auth"
    result = analyze_message(
        subject="Urgent password verification",
        body="Please confirm your password immediately.",
        urls=[sample_url],
    )
    print(result)
