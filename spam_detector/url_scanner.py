"""
URL Scanner — Threat Analysis Module
-------------------------------------
Analyzes URLs found in email bodies using:
  1. Heuristic rule engine   (always runs, no API key needed)
  2. Google Safe Browsing v4 (optional — set SAFE_BROWSING_API_KEY in env)

Threat Levels:
  SAFE        — no red flags
  SUSPICIOUS  — some heuristic hits, treat with caution
  DANGEROUS   — high-confidence threat (multiple heuristics or GSB hit)
"""

import re
import os
import requests
import tldextract
from urllib.parse import urlparse

SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")
SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
)

# Known legitimate domains that are almost never phishing origins
WHITELIST_TLDS = {"google.com", "microsoft.com", "apple.com", "amazon.com",
                  "github.com", "linkedin.com", "twitter.com", "facebook.com"}

# Common phishing / malware TLDs (heuristic signal only)
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                   ".click", ".link", ".club", ".online", ".site", ".icu"}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "password", "credential", "confirm", "paypal", "ebay", "amazon-",
    "apple-", "google-", "microsoft-", "free-", "winner", "prize",
    "click-here", "urgent", "limited-time", "gift", "offer",
]

IP_URL_PATTERN = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}"
)

URL_PATTERN = re.compile(
    r"https?://[^\s\">\'<\)\(]+", re.IGNORECASE
)


def extract_urls(text: str) -> list[str]:
    """Pull all URLs from a block of text."""
    return list(set(URL_PATTERN.findall(text)))


def _heuristic_score(url: str) -> tuple[int, list[str]]:
    """
    Returns (score, reasons).
    score 0 = clean, higher = more suspicious.
    Each triggered rule adds points.
    """
    score = 0
    reasons = []
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    full_url_lower = url.lower()

    # Rule 1: IP address instead of domain
    if IP_URL_PATTERN.match(url):
        score += 40
        reasons.append("IP address used instead of domain name")

    # Rule 2: Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if full_url_lower.endswith(tld) or f"{tld}/" in full_url_lower:
            score += 20
            reasons.append(f"Suspicious TLD detected ({tld})")
            break

    # Rule 3: Phishing keywords in URL
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if hits:
        score += min(30, len(hits) * 10)
        reasons.append(f"Phishing keyword(s) in URL: {', '.join(hits[:3])}")

    # Rule 4: Excessive subdomains (e.g. secure.login.verify.badsite.com)
    subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0
    if subdomain_count >= 3:
        score += 15
        reasons.append(f"Excessive subdomains ({subdomain_count} levels)")

    # Rule 5: Very long URL (often obfuscation)
    if len(url) > 150:
        score += 10
        reasons.append("Unusually long URL (possible obfuscation)")

    # Rule 6: Uses HTTP not HTTPS
    if parsed.scheme == "http":
        score += 10
        reasons.append("Insecure HTTP connection (no SSL)")

    # Rule 7: Misleading domain (brand name in subdomain but different root)
    brand_names = ["paypal", "apple", "google", "microsoft", "amazon", "ebay", "netflix"]
    for brand in brand_names:
        if brand in ext.subdomain.lower() and brand not in ext.domain.lower():
            score += 35
            reasons.append(f"Brand name '{brand}' used in subdomain to mislead")
            break

    # Rule 8: URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "rb.gy", "is.gd", "buff.ly", "short.io", "cutt.ly"]
    if domain in shorteners:
        score += 15
        reasons.append("URL shortener detected (destination unknown)")

    return score, reasons


def _check_safe_browsing(urls: list[str]) -> dict[str, bool]:
    """
    Returns {url: True} if Google flagged it as dangerous.
    Silently fails if no API key.
    """
    if not SAFE_BROWSING_API_KEY or not urls:
        return {}

    payload = {
        "client": {"clientId": "spam-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        resp = requests.post(
            SAFE_BROWSING_URL + SAFE_BROWSING_API_KEY,
            json=payload, timeout=5
        )
        data = resp.json()
        flagged = {}
        for match in data.get("matches", []):
            flagged[match["threat"]["url"]] = True
        return flagged
    except Exception:
        return {}


def scan_urls(text: str) -> list[dict]:
    """
    Main function. Takes email body text, returns list of scan results.
    Each result dict has: url, threat_level, score, reasons, gsb_flagged
    """
    urls = extract_urls(text)
    if not urls:
        return []

    gsb_flags = _check_safe_browsing(urls)
    results = []

    for url in urls:
        score, reasons = _heuristic_score(url)
        gsb_flagged = gsb_flags.get(url, False)

        if gsb_flagged:
            score += 60
            reasons.insert(0, "🔴 Flagged by Google Safe Browsing")

        if score >= 40:
            threat_level = "DANGEROUS"
            color = "#ef4444"
            icon = "🔴"
        elif score >= 15:
            threat_level = "SUSPICIOUS"
            color = "#f97316"
            icon = "🟠"
        else:
            threat_level = "SAFE"
            color = "#22c55e"
            icon = "🟢"

        results.append({
            "url":         url[:80] + "..." if len(url) > 80 else url,
            "full_url":    url,
            "threat_level": threat_level,
            "score":       score,
            "reasons":     reasons,
            "gsb_flagged": gsb_flagged,
            "color":       color,
            "icon":        icon,
        })

    # Sort: most dangerous first
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def threat_summary(scan_results: list[dict]) -> dict:
    dangerous   = sum(1 for r in scan_results if r["threat_level"] == "DANGEROUS")
    suspicious  = sum(1 for r in scan_results if r["threat_level"] == "SUSPICIOUS")
    safe        = sum(1 for r in scan_results if r["threat_level"] == "SAFE")
    return {
        "total":      len(scan_results),
        "dangerous":  dangerous,
        "suspicious": suspicious,
        "safe":       safe,
        "has_threats": dangerous > 0 or suspicious > 0,
    }
