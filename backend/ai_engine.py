import os
import re
import json
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Models tried in order so deprecated model names never break execution
MODEL_CANDIDATES = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
]


def compute_lexical_signals(hostname: str, url: str) -> dict:
    """Extracts structural and lexical phishing indicators from the hostname."""
    parts = hostname.split(".")
    subdomain_depth = max(0, len(parts) - 2)
    hyphen_count = hostname.count("-")
    digit_count = sum(c.isdigit() for c in hostname)
    tld = parts[-1] if parts else ""
    high_risk_tlds = {"top", "xyz", "buzz", "cc", "tk", "ml", "ga", "cf", "gq", "icu", "cam", "rest"}

    # Detect character-substitution lookalikes (e.g., paypa1, g00gle, netfl1x)
    spoof_patterns = [
        r"paypa[l1i]",
        r"g[o0]{2}gle",
        r"netfl[i1l]x",
        r"instagr[a4]m",
        r"faceb[o0]{2}k",
        r"micr[o0]s[o0]ft",
        r"amaz[o0]n",
        r"app[l1]e",
    ]
    has_digit_substitution = bool(re.search(r"[a-z]+[0-9]+[a-z]*", hostname))
    matches_brand_pattern = any(re.search(p, hostname) for p in spoof_patterns)

    return {
        "tld": f".{tld}",
        "is_high_risk_tld": tld in high_risk_tlds,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "subdomain_depth": subdomain_depth,
        "suspicious_lexical_combo": (matches_brand_pattern and (has_digit_substitution or hyphen_count > 0 or tld in high_risk_tlds)),
        "url_length": len(url),
    }


def fallback_heuristic_evaluation(hostname: str, telemetry: dict, lexical: dict) -> dict:
    """Deterministic fallback used only if the Gemini API is unreachable."""
    score = 10
    indicators = []

    tls_valid = telemetry.get("tls_valid", False)
    age_days = telemetry.get("domain_age_days")

    if tls_valid:
        indicators.append(f"TLS Certificate: Trusted ({telemetry.get('tls_issuer', 'Valid CA')})")
    else:
        score += 45
        indicators.append("TLS Certificate: Missing or Untrusted")

    if isinstance(age_days, int):
        if age_days < 30:
            score += 35
            indicators.append(f"Domain Age: {age_days} days (Newly Registered <30d)")
        elif age_days > 365:
            score = max(5, score - 5)
            indicators.append(f"Domain Age: {telemetry.get('domain_age_readable')}")
        else:
            indicators.append(f"Domain Age: {telemetry.get('domain_age_readable')}")
    else:
        indicators.append(f"Domain Age: {telemetry.get('domain_age_readable', 'Unknown')}")

    if lexical["suspicious_lexical_combo"]:
        score += 45
        indicators.append("Lexical Analysis: Brand impersonation / typosquatting pattern detected")
    if lexical["is_high_risk_tld"]:
        score += 20
        indicators.append(f"TLD Reputation: High-abuse extension ({lexical['tld']})")
    if lexical["hyphen_count"] >= 2:
        score += 15
        indicators.append(f"Hostname Structure: Multiple hyphens ({lexical['hyphen_count']}) typical of deceptive URLs")

    score = min(98, max(2, score))
    if score >= 60:
        verdict = "MALICIOUS"
        action = "Do NOT enter credentials or sensitive data. Close this page immediately."
    elif score >= 35:
        verdict = "SUSPICIOUS"
        action = "Avoid entering credentials or sensitive personal information on this site."
    else:
        verdict = "SAFE"
        action = "Domain exhibits authentic cryptographic and registration trust signals. Safe to browse."

    return {
        "risk_score": score,
        "verdict": verdict,
        "xai_summary": f"Automated security analysis evaluated {hostname} at {score}/100 based on live TLS inspection, domain registration history, and lexical telemetry.",
        "identified_risk_indicators": indicators,
        "recommended_action": action,
    }


def generate_threat_explanation(url: str, hostname: str, telemetry: dict) -> dict:
    """Uses Gemini AI to synthesize live telemetry and lexical signals into an XAI report."""
    lexical = compute_lexical_signals(hostname, url)

    if not GEMINI_API_KEY:
        return fallback_heuristic_evaluation(hostname, telemetry, lexical)

    prompt = f"""
You are the core Cyber Threat Intelligence & Explainable AI (XAI) engine for PhishLens.
Evaluate the target URL using the live technical telemetry and lexical signals below.

TARGET DETAILS:
- Full URL: {url}
- Hostname: {hostname}

LIVE NETWORK TELEMETRY:
- DNS Resolvable: {telemetry.get("dns_resolved")}
- TLS Certificate Valid: {telemetry.get("tls_valid")}
- TLS Certificate Issuer: {telemetry.get("tls_issuer")}
- TLS Certificate Remaining Validity: {telemetry.get("tls_remaining")}
- Domain Registration Age: {telemetry.get("domain_age_readable")}
- Domain Registrar: {telemetry.get("registrar")}
- Extracted Page Title: {telemetry.get("page_title")}
- Form / Input Analysis: {telemetry.get("forms_detected")}

LEXICAL & STRUCTURAL SIGNALS:
- Top-Level Domain (TLD): {lexical["tld"]} (High-risk TLD: {lexical["is_high_risk_tld"]})
- Hyphen Count in Hostname: {lexical["hyphen_count"]}
- Digit Count in Hostname: {lexical["digit_count"]}
- Subdomain Depth: {lexical["subdomain_depth"]}
- Typosquatting / Brand Spoof Pattern Detected: {lexical["suspicious_lexical_combo"]}

INSTRUCTIONS FOR SCORING:
1. Analyze all evidence holistically. Combine the live telemetry (TLS validity, domain age, registrar, lexical structure) with your cybersecurity knowledge.
2. Established, authentic websites with valid TLS certificates, long registration histories (or protected corporate registrars), and clean domain names without typosquatting MUST receive a low threat score (0 to 15) and a verdict of "SAFE". Note that major platforms often block automated HTML title scraping with bot firewalls—do NOT penalize a domain simply because its page title is protected or rate-limited.
3. Domains exhibiting brand impersonation, homoglyphs/digit substitutions (e.g., 'paypa1', 'netfl1x'), multiple deceptive hyphens, newly registered domains (<30 days), untrusted/missing TLS certificates, or high-risk TLDs mimicking known services MUST receive a high threat score (65 to 98) and a verdict of "MALICIOUS" (or 35 to 64 for "SUSPICIOUS").

Return ONLY a valid JSON object matching this exact structure:
{{
  "risk_score": <integer between 0 and 100>,
  "verdict": "<SAFE | SUSPICIOUS | MALICIOUS>",
  "xai_summary": "<Clear, insightful 2-3 sentence cybersecurity explanation of why this domain received this score>",
  "identified_risk_indicators": [
    "<Specific finding 1 (e.g., TLS Certificate: Trusted (DigiCert))>",
    "<Specific finding 2 (e.g., Domain Age: 9,100 days / 24.9 years)>",
    "<Specific finding 3 (e.g., Lexical Analysis: Clean apex domain or Typosquatting detected)>"
  ],
  "recommended_action": "<Direct, actionable security advice for the user>"
}}
"""

    for model_name in MODEL_CANDIDATES:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(
                prompt,
                generation_config={"response_mime_type": "application/json"},
            )
            raw_text = response.text.strip()
            # Clean markdown code fences if present
            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
                raw_text = re.sub(r"\s*```$", "", raw_text)

            parsed = json.loads(raw_text)
            score = int(parsed.get("risk_score", 15))
            score = min(100, max(0, score))

            verdict = str(parsed.get("verdict", "SAFE")).upper().strip()
            if verdict not in {"SAFE", "SUSPICIOUS", "MALICIOUS"}:
                verdict = "MALICIOUS" if score >= 60 else ("SUSPICIOUS" if score >= 35 else "SAFE")

            return {
                "risk_score": score,
                "verdict": verdict,
                "xai_summary": parsed.get("xai_summary", "AI threat analysis completed."),
                "identified_risk_indicators": parsed.get("identified_risk_indicators", []),
                "recommended_action": parsed.get("recommended_action", "Proceed with standard caution."),
            }
        except Exception as e:
            print(f"[PhishLens AI] Model {model_name} attempt failed: {e}")
            continue

    return fallback_heuristic_evaluation(hostname, telemetry, lexical)