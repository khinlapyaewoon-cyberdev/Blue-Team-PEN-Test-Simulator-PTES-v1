#!/usr/bin/env python3
"""
PTES AI Penetration Testing Simulator (ETHICAL / DEFENSIVE)

- Full PTES phase simulation (1–12)
- Recon-driven (TXT input)
- Signal → Attack-path awareness (SIMULATED)
- LLaMA reasoning only (NO exploits / payloads / commands)
- SOC Playbooks for every phase
- TXT report output
"""

import os
import re
import json
import streamlit as st
from huggingface_hub import InferenceClient

# =====================================================
# PROXY CONTROL
# =====================================================
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("ALL_PROXY", None)

# =====================================================
# HUGGING FACE CONFIG
# =====================================================
HF_TOKEN = "HF_TOKEN"
MODEL_ID = "meta-llama/Llama-3.1-8B-Instruct"
llm = InferenceClient(MODEL_ID, token=HF_TOKEN)

# =====================================================
# EXPANDED MULTI-PERSPECTIVE SIGNAL EXTRACTION
# =====================================================
def extract_signals(text):
    t = text.lower()

    return {
        "network": {
            "open_ports": sorted(set(re.findall(r"(\d+)/tcp\s+open", t))),
            "admin_ports": any(p in t for p in ["22/tcp open", "3389/tcp open", "5900/tcp open"]),
            "cdn": any(x in t for x in ["cloudflare", "akamai", "fastly"]),
            "load_balancer": any(x in t for x in ["elb", "nginx", "haproxy"]),
            "waf_headers": any(h in t for h in [
                "content-security-policy",
                "x-frame-options",
                "x-xss-protection"
            ])
        },
        "web": {
            "http": "80/tcp open" in t,
            "https": "443/tcp open" in t,
            "redirects": t.count("302"),
            "error_pages": t.count("404") + t.count("500"),
            "upload_forms": "upload" in t,
            "api_paths": any(x in t for x in ["/api", "graphql", "swagger"]),
            "debug_keywords": any(x in t for x in ["debug", "trace", "stack trace"])
        },
        "auth": {
            "login_pages": any(x in t for x in ["login", "signin", "auth"]),
            "password_reset": "reset password" in t,
            "mfa_present": any(x in t for x in ["mfa", "2fa", "otp"]),
            "weak_cookie_flags": "secure" not in t or "httponly" not in t
        },
        "tls_crypto": {
            "hsts": "strict-transport-security" in t,
            "legacy_tls": any(x in t for x in ["tls 1.0", "tls 1.1"]),
            "expired_cert": "expired" in t,
            "self_signed": "self-signed" in t
        },
        "dns_email": {
            "dnssec": "dnssec" in t,
            "spf": "spf" in t,
            "dmarc": "dmarc" in t,
            "mx_records": "mail exchanger" in t,
            "email_leak": any(x in t for x in ["@", "email"])
        },
        "cloud_saas": {
            "aws": "amazonaws" in t,
            "azure": "azure" in t,
            "gcp": "google cloud" in t,
            "storage_buckets": any(x in t for x in ["s3", "blob", "bucket"])
        },
        "devops": {
            "ci_cd": any(x in t for x in ["jenkins", "gitlab", "github actions"]),
            "exposed_repos": "git" in t,
            "env_files": ".env" in t
        },
        "monitoring": {
            "ids_present": any(x in t for x in ["snort", "suricata"]),
            "edr_present": any(x in t for x in ["crowdstrike", "sentinelone"]),
            "logging_headers": "x-request-id" in t
        }
    }

# =====================================================
# PTES PHASE DEFINITIONS
# =====================================================
PTES_PHASES = [
    (1, "PRE_ENGAGEMENT", "Pre-Engagement & Scope"),
    (2, "RECON", "Reconnaissance"),
    (3, "ENUMERATION", "Enumeration"),
    (4, "VULN_ANALYSIS", "Vulnerability Analysis"),
    (5, "ATTACK_SIM", "Attack Path Simulation (Awareness)"),
    (6, "POST_EXPLOIT", "Post-Exploitation Impact"),
    (7, "LATERAL", "Lateral Movement Risk"),
    (8, "PRIV_ESC", "Privilege Escalation Indicators"),
    (9, "PERSISTENCE", "Persistence & Detection Gaps"),
    (10, "C2", "Command & Control Awareness"),
    (11, "IMPACT", "Business Impact"),
    (12, "REPORTING", "Reporting & Remediation"),
]

# =====================================================
# SOC PLAYBOOKS
# =====================================================
SOC_PLAYBOOKS = {
    "PRE_ENGAGEMENT": ["Confirm scope", "Approve ROE"],
    "RECON": ["Detect scanning behavior", "Rate-limit sources"],
    "ENUMERATION": ["Alert on enumeration patterns", "Tune IDS"],
    "VULN_ANALYSIS": ["Prioritize patching", "Threat modeling"],
    "ATTACK_SIM": ["Block suspicious paths", "WAF rule tuning"],
    "POST_EXPLOIT": ["Audit sensitive data access", "Enable DLP"],
    "LATERAL": ["Monitor auth anomalies", "Segment networks"],
    "PRIV_ESC": ["Audit privilege changes", "Harden IAM"],
    "PERSISTENCE": ["Detect config drift", "EDR rule review"],
    "C2": ["Monitor outbound traffic", "DNS filtering"],
    "IMPACT": ["Assess business impact", "Notify leadership"],
    "REPORTING": ["Executive summary", "Track remediation"]
}

# =====================================================
# LLM SIMULATION FUNCTION
# =====================================================
def simulate_phase(phase_title, signals, temperature):
    prompt = f"""
You are a DEFENSIVE security analyst performing an ETHICAL PTES simulation.

PTES Phase:
{phase_title}

Recon-Derived Signals:
{json.dumps(signals, indent=2)}

Produce a STRUCTURED REPORT:
1. Likely attacker objectives (based on signals)
2. Simulated attack paths (high-level, NO technical steps)
3. Defensive gaps & controls
4. SOC response & mitigation priorities

STRICT RULES:
- NO exploits
- NO payloads
- NO commands
- NO step-by-step instructions
- Defensive and awareness-focused only
"""
    response = llm.chat.completions.create(
        model=MODEL_ID,
        messages=[
            {"role": "system", "content": "You are a defensive PTES analyst."},
            {"role": "user", "content": prompt},
        ],
        temperature=temperature,
        max_tokens=500
    )
    return response.choices[0].message.content.strip()

# =====================================================
# STREAMLIT UI
# =====================================================
st.set_page_config(page_title="PTES AI Simulator", layout="wide")
st.title("🧠 PTES AI Penetration Testing Simulator (Defensive)")
st.caption("Recon → Signal → Simulated Attack Awareness → SOC Defense")

uploaded = st.file_uploader("Upload Recon TXT", type=["txt"])
temperature = st.slider("LLM Temperature", 0.0, 1.0, 0.3)

if uploaded:
    recon_text = uploaded.read().decode(errors="ignore")
    signals = extract_signals(recon_text)

    st.subheader("🔍 Extracted Recon Signals")
    st.json(signals)

    report = [
        "PTES AI DEFENSIVE SIMULATION REPORT",
        "=" * 70
    ]

    for pid, key, title in PTES_PHASES:
        with st.expander(f"Phase {pid}: {title}"):
            result = simulate_phase(title, signals, temperature)

            st.markdown("### 🧠 Simulated Attack Awareness")
            st.write(result)

            st.markdown("### 🛡️ SOC Playbook")
            for step in SOC_PLAYBOOKS[key]:
                st.write(f"- {step}")

            report.append(f"\nPHASE {pid}: {title}")
            report.append(result)
            report.append("SOC PLAYBOOK:")
            for step in SOC_PLAYBOOKS[key]:
                report.append(f"- {step}")

    st.download_button(
        "📄 Download PTES Simulation Report (TXT)",
        "\n".join(report),
        file_name="ptes_ai_defensive_simulation.txt"
    )
else:
    st.info("Upload recon TXT to begin PTES simulation.")
