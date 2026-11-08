import os
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import requests
import whois
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ai_engine import generate_threat_explanation

app = FastAPI(
    title="PhishLens API",
    description="AI-powered web threat detection and digital trust intelligence backend",
    version="1.0.0"
)

# Enable CORS for Vercel frontend, preview domains, and localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


class ScanRequest(BaseModel):
    url: str


def sanitize_and_parse_url(raw_input: str) -> tuple[str, str]:
    """Validates and extracts a normalized URL and hostname."""
    target = raw_input.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    hostname = (parsed.hostname or "").lower()
    return target, hostname


def is_valid_domain(hostname: str) -> bool:
    """Checks whether the hostname is a valid Fully Qualified Domain Name (FQDN)."""
    if not hostname or "." not in hostname:
        return False
    # Hostname pattern allowing letters, numbers, hyphens, and dots
    fqdn_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
    return bool(re.match(fqdn_pattern, hostname))


def inspect_tls(hostname: str) -> dict:
    """Probes the remote endpoint using SNI to retrieve the TLS certificate."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            # server_hostname enables SNI, crucial for Netflix, Instagram, Cloudflare, AWS CDNs
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Trusted Authority"
                return {
                    "valid": True,
                    "issuer": issuer,
                    "version": ssock.version()
                }
    except Exception as e:
        return {
            "valid": False,
            "issuer": "None / Unverified",
            "error": str(e)
        }


def inspect_whois(hostname: str) -> dict:
    """Performs a WHOIS registration query, preserving ambiguous/rate-limited states."""
    try:
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            return {
                "age_days": max(0, age_days),
                "age_readable": f"{age_days} days (~{round(age_days / 365, 1)} years)",
                "registrar": domain_info.registrar or "Unknown"
            }
    except Exception:
        pass

    # Never default to 0 days when WHOIS is rate-limited or firewalled
    return {
        "age_days": None,
        "age_readable": "Unknown (Registry Query Protected / Rate-Limited)",
        "registrar": "Private / Cloudflare / Protected"
    }


def inspect_http_metadata(url: str) -> dict:
    """Retrieves HTTP status and scans for page titles and form elements."""
    try:
        response = requests.get(url, headers=BROWSER_HEADERS, timeout=4, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else "No Title Found"
        forms = len(soup.find_all("form"))
        password_inputs = len(soup.find_all("input", {"type": "password"}))

        form_desc = "None"
        if password_inputs > 0:
            form_desc = f"Contains {password_inputs} login/password input field(s)"
        elif forms > 0:
            form_desc = f"Contains {forms} generic form field(s)"

        return {
            "status_code": response.status_code,
            "page_title": title[:100],
            "forms_detected": form_desc
        }
    except Exception:
        return {
            "status_code": "Unreachable",
            "page_title": "Site Unreachable or Scraping Blocked",
            "forms_detected": "Undetermined"
        }


@app.get("/")
def health_check():
    return {
        "service": "PhishLens Security Backend",
        "status": "online",
        "docs": "/docs"
    }


@app.post("/api/scan")
async def scan_target(payload: ScanRequest):
    raw_input = payload.url.strip()
    target_url, hostname = sanitize_and_parse_url(raw_input)

    # 1. Reject invalid/garbage inputs before invoking expensive socket or AI calls
    if not is_valid_domain(hostname):
        return {
            "target": raw_input,
            "hostname": hostname or "invalid",
            "risk_score": 0,
            "verdict": "Invalid",
            "xai_summary": f"'{raw_input}' is not a valid resolvable domain or URL. Please provide a valid address (e.g., github.com or https://example.com).",
            "identified_risk_indicators": ["Malformed domain syntax", "Missing Top-Level Domain (TLD)"],
            "recommended_action": "Check the spelling and enter a valid domain name.",
            "telemetry": {
                "tls_valid": False,
                "tls_issuer": "N/A",
                "domain_age_readable": "N/A",
                "page_title": "N/A",
                "http_status": "N/A",
                "forms_detected": "N/A"
            }
        }

    # 2. Extract technical telemetry
    tls_info = inspect_tls(hostname)
    whois_info = inspect_whois(hostname)
    http_info = inspect_http_metadata(target_url)

    telemetry = {
        "tls_valid": tls_info["valid"],
        "tls_issuer": tls_info["issuer"],
        "domain_age_days": whois_info["age_days"],
        "domain_age_readable": whois_info["age_readable"],
        "page_title": http_info["page_title"],
        "http_status": http_info["status_code"],
        "forms_detected": http_info["forms_detected"]
    }

    # 3. Call Gemini Explainable AI
    ai_report = generate_threat_explanation(target_url, hostname, telemetry)

    return {
        "target": target_url,
        "hostname": hostname,
        "risk_score": ai_report.get("risk_score", 15),
        "verdict": ai_report.get("verdict", "Safe"),
        "xai_summary": ai_report.get("xai_summary", ""),
        "identified_risk_indicators": ai_report.get("identified_risk_indicators", []),
        "recommended_action": ai_report.get("recommended_action", "Proceed with normal caution."),
        "telemetry": telemetry
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=True)