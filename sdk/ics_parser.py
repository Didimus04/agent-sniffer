"""
sdk/ics_parser.py — Dedicated ICS Calendar Parser Module (Ambiguitas 6, Req 9.8)
Inspects text-based calendar metadata (SUMMARY, DESCRIPTION, URL, ORGANIZER) for phishing indicators.
Pure stdlib implementation with zero external dependencies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)


@dataclass
class ICSParseResult:
    external_anomaly: bool = False
    flags: list[str] = field(default_factory=list)
    initial_context_score: float = 0.0
    fields: dict = field(default_factory=dict)


def _unfold(content: str) -> list[str]:
    """RFC 5545 line unfolding: space/tab-prefixed lines continue the previous."""
    lines: list[str] = []
    for raw in content.splitlines():
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _field(lines: list[str], name: str) -> list[str]:
    prefix = name.upper() + ":"
    alt = name.upper() + ";"
    return [ln.split(":", 1)[1] for ln in lines
            if ln.upper().startswith(prefix) or ln.upper().startswith(alt)]


def _url_anomalies(url: str) -> list[str]:
    out: list[str] = []
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except ValueError:
        return ["malformed_url"]
    if parsed.scheme != "https":
        out.append("non_https_url")
    if host.replace(".", "").isdigit() or ":" in host:
        out.append("ip_host_url")
    if "xn--" in host or "@" in (url.split("/")[2] if "/" in url else url):
        out.append("deceptive_url")
    return out


def parse_ics(content: str, trusted_domains: list[str] | None = None) -> ICSParseResult:
    """Parse calendar metadata; flag external anomalies. Never executes content."""
    trusted = {d.lower() for d in (trusted_domains or [])}
    res = ICSParseResult()
    lines = _unfold(content)
    summaries = _field(lines, "SUMMARY")
    descriptions = _field(lines, "DESCRIPTION")
    urls = _field(lines, "URL") + [u for d in descriptions for u in _URL_RE.findall(d)]
    organizers = _field(lines, "ORGANIZER")
    res.fields = {"summary": summaries, "description": descriptions,
                  "urls": urls, "organizer": organizers}
    for url in urls:
        for flag in _url_anomalies(url):
            res.flags.append(f"url:{flag}:{url[:64]}")
    for org in organizers:
        m = re.search(r"mailto:([^@\s]+)@([^\s;>]+)", org, re.IGNORECASE)
        if m and m.group(2).lower() not in trusted:
            res.flags.append(f"organizer:untrusted_domain:{m.group(2)[:64]}")
    boost = sum(1.5 if f.startswith("url:") else 1.0 for f in res.flags)
    if res.flags:
        res.external_anomaly = True
        res.initial_context_score = round(min(boost, 10.0), 1)
    return res
