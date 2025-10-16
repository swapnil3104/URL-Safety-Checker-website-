import re
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "men", "work", "click", "link", "xyz", "top",
    "gq", "ml", "cf", "tk", "ga", "fit", "surf", "viajes", "science", "download"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "rb.gy", "rebrand.ly", "cutt.ly", "lnkd.in"
}

PHISHY_KEYWORDS = {
    "login", "verify", "update", "password", "secure", "account", "bank", "wallet", "gift",
    "free", "winner", "bonus", "prize", "support", "helpdesk"
}


@dataclass
class ExternalCheckConfig:
    google_safe_browsing_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    enable_external_checks: bool = True
    request_timeout_seconds: int = 6


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _count_subdomains(host: str) -> int:
    return max(0, host.count(".") - 1)


def _has_misleading_chars(host: str) -> bool:
    if host.startswith("xn--"):  # punycode (potential IDN homograph)
        return True
    return ("@" in host) or ("-" in host and host.count("-") >= 2)


def _is_http(url_components: Tuple[str, str, str, str, str, str]) -> bool:
    scheme = url_components[0]
    return scheme.lower() == "http"


def _tld(host: str) -> str:
    parts = host.rsplit(".", 1)
    return parts[1].lower() if len(parts) == 2 else ""


def _has_many_params(query: str) -> bool:
    if not query:
        return False
    return query.count("=") >= 5


def _has_double_slash_path(url: str) -> bool:
    return "//" in url.split("://", 1)[-1]


def _keyword_hits(text: str) -> List[str]:
    text_lower = text.lower()
    hits = [kw for kw in PHISHY_KEYWORDS if kw in text_lower]
    return sorted(hits)


def _score_heuristics(url: str) -> Dict:
    parsed = urlparse(url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else f"http://{url}")
    host = parsed.hostname or ""

    risk = 0
    factors: List[str] = []

    if not host:
        return {
            "valid": False,
            "reason": "URL parsing failed: missing hostname",
        }

    # Heuristic: IP address host
    if _looks_like_ip(host):
        risk += 20
        factors.append("Host is an IP address instead of domain")

    # Heuristic: HTTP scheme
    if _is_http(parsed):
        risk += 10
        factors.append("Uses HTTP instead of HTTPS")

    # Heuristic: long URL
    if len(url) >= 100:
        risk += 10
        factors.append("Very long URL")

    # Heuristic: many subdomains
    subdomain_count = _count_subdomains(host)
    if subdomain_count >= 3:
        risk += 10
        factors.append("Too many subdomains")

    # Heuristic: suspicious TLD
    tld = _tld(host)
    if tld in SUSPICIOUS_TLDS:
        risk += 10
        factors.append(f"Suspicious TLD: .{tld}")

    # Heuristic: many params
    if _has_many_params(parsed.query):
        risk += 5
        factors.append("Many query parameters")

    # Heuristic: misleading characters
    if _has_misleading_chars(host):
        risk += 5
        factors.append("Potentially misleading domain characters")

    # Heuristic: double slash in path/host part
    if _has_double_slash_path(url):
        risk += 5
        factors.append("Unexpected '//' in URL path/host")

    # Heuristic: URL shortener
    if host.lower() in URL_SHORTENERS:
        risk += 10
        factors.append("Known URL shortener (destination obscured)")

    # Heuristic: phishy keywords
    hits = _keyword_hits(url)
    if hits:
        risk += 10
        factors.append(f"Contains sensitive-action keywords: {', '.join(hits)}")

    # Normalize score to 0..100 range (cap)
    risk = min(100, risk)

    classification = (
        "high_risk" if risk >= 40 else
        "medium_risk" if risk >= 20 else
        "low_risk"
    )

    return {
        "valid": True,
        "host": host,
        "scheme": parsed.scheme or "",
        "path": parsed.path or "",
        "query": parsed.query or "",
        "risk_score": risk,
        "risk_level": classification,
        "risk_factors": factors,
    }


def _check_google_safe_browsing(url: str, api_key: str, timeout: int) -> Optional[Dict]:
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        body = {
            "client": {"clientId": "ins-url-checker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = requests.post(endpoint, json=body, timeout=timeout)
        if resp.status_code != 200:
            return {"ok": False, "error": f"GSB HTTP {resp.status_code}"}
        data = resp.json()
        matches = data.get("matches") or []
        return {"ok": True, "malicious": len(matches) > 0, "matches": matches}
    except Exception as exc:
        return {"ok": False, "error": f"GSB error: {type(exc).__name__}"}


def _check_virustotal(url: str, api_key: str, timeout: int) -> Optional[Dict]:
    try:
        headers = {"x-apikey": api_key}
        # Submit URL for analysis (VT v3)
        analyze_resp = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=timeout)
        if analyze_resp.status_code not in (200, 201):
            return {"ok": False, "error": f"VT submit HTTP {analyze_resp.status_code}"}
        analysis_id = analyze_resp.json().get("data", {}).get("id")
        if not analysis_id:
            return {"ok": False, "error": "VT missing analysis id"}

        # Poll a couple times quickly (avoid long waits)
        result = None
        for _ in range(2):
            time.sleep(0.6)
            r = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=timeout)
            if r.status_code != 200:
                break
            data = r.json().get("data", {}).get("attributes", {})
            status = data.get("status")
            if status == "completed":
                result = data.get("stats") or {}
                break

        if result is None:
            return {"ok": True, "pending": True}
        malicious = (result.get("malicious", 0) or 0) > 0
        return {"ok": True, "malicious": malicious, "stats": result}
    except Exception as exc:
        return {"ok": False, "error": f"VT error: {type(exc).__name__}"}


def assess_url_safety(url: str, external_cfg: ExternalCheckConfig) -> Dict:
    heur = _score_heuristics(url)
    if not heur.get("valid"):
        return {"valid": False, "error": heur.get("reason", "Invalid URL")}

    report = {
        "input_url": url,
        "heuristics": heur,
        "external": {},
        "overall_risk_score": heur["risk_score"],
        "overall_risk_level": heur["risk_level"],
    }

    if not external_cfg.enable_external_checks:
        return report

    # Optional: Google Safe Browsing
    if external_cfg.google_safe_browsing_api_key:
        gsb = _check_google_safe_browsing(url, external_cfg.google_safe_browsing_api_key, external_cfg.request_timeout_seconds)
        report["external"]["google_safe_browsing"] = gsb
        if gsb and gsb.get("ok") and gsb.get("malicious"):
            report["overall_risk_score"] = min(100, report["overall_risk_score"] + 40)
            report["overall_risk_level"] = "high_risk"

    # Optional: VirusTotal
    if external_cfg.virustotal_api_key:
        vt = _check_virustotal(url, external_cfg.virustotal_api_key, external_cfg.request_timeout_seconds)
        report["external"]["virustotal"] = vt
        if vt and vt.get("ok") and vt.get("malicious"):
            report["overall_risk_score"] = min(100, report["overall_risk_score"] + 40)
            report["overall_risk_level"] = "high_risk"

    return report


