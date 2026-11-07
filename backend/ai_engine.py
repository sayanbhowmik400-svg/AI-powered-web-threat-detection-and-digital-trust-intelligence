import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# Configure API Key
api_key = os.getenv("GEMINI_API_KEY", "")
if api_key:
    genai.configure(api_key=api_key)

def generate_threat_explanation(hostname: str, tls_info: dict, domain_info: dict, content_info: dict, base_score: int) -> dict:
    prompt = f"""
    You are an expert cybersecurity investigator. Analyze this technical telemetry for a website and generate an Explainable AI (XAI) threat report:
    
    Domain: {hostname}
    TLS Valid: {tls_info.get('valid')} (Issuer: {tls_info.get('issuer')}, Days Left: {tls_info.get('days_remaining')})
    Domain Age Days: {domain_info.get('age_days')} (Is Freshly Registered: {domain_info.get('is_new')})
    Form Has Password Field: {content_info.get('has_password_field')}
    Contains Financial Keywords: {content_info.get('has_payment_keywords')}
    Calculated Heuristic Score: {base_score}/100

    Return strictly a valid JSON object matching this schema with NO markdown wrapping:
    {{
        "verdict_summary": "Two sentence executive summary explaining the risk level.",
        "key_flags": ["Flag 1", "Flag 2", "Flag 3"],
        "recommended_action": "Clear step-by-step guidance for an everyday user."
    }}
    """
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        clean_text = response.text.strip().removeprefix("```json").removesuffix("```").strip()
        return json.loads(clean_text)
    except Exception as e:
        return {
            "verdict_summary": f"Automated heuristics evaluated risk score at {base_score}/100 based on TLS and domain freshness.",
            "key_flags": [
                f"TLS Certificate: {'Trusted' if tls_info.get('valid') else 'Untrusted/Invalid'}",
                f"Domain Age: {domain_info.get('age_days', 'Unknown')} days",
                f"Form Fields: {'Sensitive login inputs detected' if content_info.get('has_password_field') else 'Standard page'}"
            ],
            "recommended_action": "Avoid entering credentials or sensitive personal information on this site."
        }