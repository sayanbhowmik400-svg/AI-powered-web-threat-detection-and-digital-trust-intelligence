import os
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import whois
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai

load_dotenv()

app = FastAPI(title="PhishLens Intelligence Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY", ""))

class ScanRequest(BaseModel):
    url: str

def check_tls(hostname: str):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                issuer_dict = dict(x[0] for x in cert['issuer'])
                days_left = (not_after - datetime.now(timezone.utc)).days
                return {
                    "valid": True,
                    "issuer": issuer_dict.get("organizationName", issuer_dict.get("commonName", "Standard CA")),
                    "days_remaining": days_left,
                    "expiry_date": cert['notAfter']
                }
    except Exception as e:
        return {"valid": False, "issuer": "None", "days_remaining": 0, "error": str(e)}

def check_domain_age(hostname: str):
    try:
        w = whois.whois(hostname)
        cdate = w.creation_date
        if isinstance(cdate, list):
            cdate = cdate[0]
        if cdate:
            if cdate.tzinfo is None:
                cdate = cdate.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - cdate).days
            return {"registrar": str(w.registrar), "age_days": age, "is_new": age < 30}
    except Exception:
        pass
    return {"registrar": "Private / Hidden", "age_days": 1, "is_new": True}

def inspect_page_content(target_url: str):
    has_password_field = False
    has_payment_keywords = False
    title = "Unknown"
    
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        res = requests.get(target_url, timeout=4, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        soup = BeautifulSoup(res.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
        inputs = soup.find_all("input")
        for inp in inputs:
            if inp.get("type") in ["password", "tel"]:
                has_password_field = True
        
        body_text = soup.get_text().lower()
        if any(term in body_text for term in ["cvv", "credit card", "bank account", "social security"]):
            has_payment_keywords = True
    except Exception:
        pass

    return {
        "title": title,
        "has_password_field": has_password_field,
        "has_payment_keywords": has_payment_keywords
    }

def generate_ai_explanation(hostname: str, tls_data: dict, dom_data: dict, page_data: dict, base_score: int):
    prompt = f"""
    Analyze these website security attributes and provide an explainable cybersecurity breakdown for an end user:
    - Target: {hostname}
    - TLS Certificate Valid: {tls_data.get('valid')} (Issuer: {tls_data.get('issuer')}, Days remaining: {tls_data.get('days_remaining')})
    - Domain Age (Days): {dom_data.get('age_days')} (Recent/New: {dom_data.get('is_new')})
    - Has Sensitive Form Fields: {page_data.get('has_password_field')}
    - Heuristic Risk Score: {base_score}/100

    Output strictly in this format:
    SUMMARY: (2 short sentences summarizing the risk)
    WHY_FLAGGED: (Comma-separated list of max 3 concrete technical reasons)
    USER_ADVICE: (One single instruction for a user, e.g., safe to browse, or do not input credentials)
    """
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text
    except Exception:
        return (
            "SUMMARY: Suspicious site configuration detected with risk indicators.\n"
            "WHY_FLAGGED: Missing valid high-trust certificate, Domain registered recently\n"
            "USER_ADVICE: Avoid entering any credentials or sensitive data."
        )

@app.post("/api/scan")
def scan_endpoint(payload: ScanRequest):
    raw_url = payload.url.strip()
    parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
    hostname = (parsed.netloc or parsed.path).split(":")[0].lower()

    tls = check_tls(hostname)
    domain = check_domain_age(hostname)
    content = inspect_page_content(raw_url)

    score = 10
    flags = []

    if not tls["valid"]:
        score += 35
        flags.append("Invalid or untrusted TLS certificate chain")
    if domain["is_new"]:
        score += 30
        flags.append("Domain is freshly registered (< 30 days)")
    if content["has_password_field"] and domain["is_new"]:
        score += 25
        flags.append("Credential form detected on recently created domain")

    score = min(score, 99)
    status = "SAFE" if score < 40 else "SUSPICIOUS" if score < 70 else "MALICIOUS"

    ai_raw = generate_ai_explanation(hostname, tls, domain, content, score)

    return {
        "hostname": hostname,
        "score": score,
        "status": status,
        "flags": flags,
        "tls": tls,
        "domain": domain,
        "content": content,
        "ai_explanation": ai_raw
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)