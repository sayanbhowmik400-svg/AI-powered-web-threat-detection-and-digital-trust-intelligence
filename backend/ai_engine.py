import os
import json
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)


def generate_threat_explanation(url: str, hostname: str, telemetry: dict) -> dict:
    """
    Synthesizes technical telemetry with Gemini's security knowledge base
    to generate an accurate risk assessment and explainable XAI verdict.
    """
    if not GEMINI_API_KEY:
        return {
            "risk_score": 10,
            "verdict": "Safe",
            "xai_summary": "Heuristic fallback: Gemini API key not configured.",
            "identified_risk_indicators": ["API key missing; manual review recommended."],
            "recommended_action": "Verify URL manually."
        }

    prompt = f"""
You are the lead Cyber Threat Intelligence and Explainable AI (XAI) engine for PhishLens.
Analyze the target URL and the technical telemetry collected below to determine whether this site is legitimate, suspicious, or malicious.

Target URL: {url}
Hostname: {hostname}

EXTRACTED TECHNICAL TELEMETRY:
- TLS Certificate Valid: {telemetry.get("tls_valid")}
- TLS Certificate Issuer: {telemetry.get("tls_issuer")}
- Domain Registration Age: {telemetry.get("domain_age_readable")}
- Page Title: {telemetry.get("page_title")}
- HTTP Status Code: {telemetry.get("http_status")}
- Form Fields Detected: {telemetry.get("forms_detected")}

EVALUATION & ARBITRATION RULES:
1. GLOBAL AUTHORITY RECOGNITION:
   Synthesize both the technical telemetry AND your internal cybersecurity knowledge base. If the hostname is an authentic, globally recognized service (e.g., netflix.com, instagram.com, google.com, github.com, wikipedia.org, linkedin.com, amazon.com) and the URL is clean without typosquatting or homoglyphs, evaluate it as legitimate with a low risk score (0-15).

2. TELEMETRY INTERPRETATION:
   Large CDNs (Cloudflare, Akamai, AWS CloudFront) frequently rate-limit WHOIS scrapers and return bot-mitigation responses to cloud servers. If domain age or title is 'Unknown' or 'Protected', do NOT automatically assume the domain is malicious.

3. MALICIOUS / HIGH-RISK INDICATORS:
   Reserve high risk scores (>60) and "Suspicious" or "Malicious" verdicts for genuine threat indicators:
   - Typosquatting / Brand Impersonation (e.g., paypa1, netflx-verify, login-instagram-auth, g00gle)
   - Brand names placed in third-level subdomains or free dynamic DNS services
   - High-risk TLDs (.top, .xyz, .buzz, .cc) claiming to represent known brands or financial institutions
   - Self-signed, expired, or untrusted TLS certificates paired with credential login forms

OUTPUT FORMAT:
Return strictly a valid JSON object matching this exact schema:
{{
  "risk_score": <integer from 0 to 100>,
  "verdict": "<Safe | Suspicious | Malicious>",
  "xai_summary": "<A concise 2-3 sentence explanation explaining the reasoning>",
  "identified_risk_indicators": [
    "<Indicator 1>",
    "<Indicator 2>"
  ],
  "recommended_action": "<Clear security recommendation for the user>"
}}
"""

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        result = json.loads(response.text.strip())
        return result
    except Exception as e:
        # Fallback if API fails or rate limits occur
        print(f"Gemini API Error: {e}")
        return {
            "risk_score": 15 if telemetry.get("tls_valid") else 65,
            "verdict": "Safe" if telemetry.get("tls_valid") else "Suspicious",
            "xai_summary": "Automated heuristics completed. AI synthesis fell back to telemetry baseline.",
            "identified_risk_indicators": [
                f"TLS Valid: {telemetry.get('tls_valid')}",
                f"Domain Age: {telemetry.get('domain_age_readable')}"
            ],
            "recommended_action": "Proceed with normal browsing caution."
        }