# 🧠 PTES AI Penetration Testing Simulator (Defensive) v1.0

**Defensive Recon → Signal → Attack Awareness → SOC Response Simulator**
***Tool Completion Date***December 2025

PTES AI Simulator is a **defensive-only penetration testing awareness tool** that analyzes reconnaissance `.txt` files, extracts multi-perspective signals (network, web, auth, TLS, DNS/email, cloud/SaaS, DevOps, monitoring), and simulates high-level PTES phases with SOC playbooks — all without generating exploits, payloads, or offensive instructions.

> ⚠️ **Warning:** This tool is intended for educational, defensive, and research purposes. Only use on systems you own or are explicitly authorized to test.

---

## 🧩 Features

- **Recon Signal Extraction**: Network, web, authentication, TLS/crypto, DNS/email, cloud/SaaS, DevOps, monitoring indicators.
- **PTES Phases Simulation (1–12)**:
  1. Pre-Engagement & Scope
  2. Reconnaissance
  3. Enumeration
  4. Vulnerability Analysis
  5. Attack Path Simulation (Awareness)
  6. Post-Exploitation Impact
  7. Lateral Movement Risk
  8. Privilege Escalation Indicators
  9. Persistence & Detection Gaps
  10. Command & Control Awareness
  11. Business Impact
  12. Reporting & Remediation
- **SOC Playbooks per Phase**: Actionable, defensive steps for each PTES stage.
- **LLaMA-Powered Simulation**: Generates structured, high-level reports and awareness summaries.
- **Interactive Streamlit Dashboard**: Expander sections for each phase, real-time signal visualization.
- **Downloadable TXT Reports**: Full PTES simulation with SOC playbooks.

---

## ⚙️ Installation

```bash
pip install streamlit huggingface_hub
```

---

## ▶️ Usage

1. Run Streamlit app:
```bash
streamlit run app.py
```
2. Upload your reconnaissance `.txt` file.
3. Adjust LLM Temperature slider for response creativity.
4. View:
   - Extracted Recon Signals (JSON)
   - PTES Phases Simulation Results
   - SOC Playbooks for each phase
5. Download complete PTES AI Defensive Simulation Report as TXT.

---

## 🔍 How It Works

Recon TXT File
      ↓
Multi-Perspective Signal Extraction (Network, Web, Auth, TLS, DNS, Cloud, DevOps, Monitoring)
      ↓
PTES Phase Simulation (1–12) via LLaMA
      ↓
High-Level Simulated Attack Awareness (Defensive, No Exploits)
      ↓
SOC Playbook Generation per Phase
      ↓
Interactive Streamlit Dashboard & Downloadable TXT Report

---

## 👤 Author

Khin La Pyae Woon  
AI-Enhanced Ethical Hacking | Cybersecurity | Digital Forensics | Defensive Simulation

🌐 Portfolio: https://khinlapyaewoon-cyberdev.vercel.app  
🔗 LinkedIn: www.linkedin.com/in/khin-la-pyae-woon-ba59183a2  
💬 WhatsApp: https://wa.me/qr/MJYX74CQ5VA4D1  

---

## 📜 License & Ethics

Released for **educational, defensive, and research purposes only**.  
Any offensive or unauthorized usage is strictly prohibited.
