# 🛡️ Phalanx: Containerized Threat Intelligence

Phalanx is a full-stack, air-gapped security tool designed to safely investigate and detonate potentially malicious links. Instead of risking a host system, this application spins up an isolated Linux container to perform deep heuristic analysis and capture visual evidence of phishing attempts.

Built with a focus on zero-trust execution and persistent auditing, the system utilizes a headless browser to safely interact with threats while maintaining a secure distance. The frontend is driven by Streamlit with a custom-injected CSS architecture designed for premium, high-contrast readability.

### ⚙️ Core Architecture
* **The Air Gap (Docker):** The entire application runs inside a containerized Linux subsystem, ensuring that zero-day browser exploits or drive-by downloads cannot breach the host OS.
* **The Sandbox (Playwright):** A headless Chromium engine visits the target URL, waits for network idle, and captures a full-page screenshot without exposing the user to malicious JavaScript payloads.
* **The Analyzer (Python/WHOIS):** A custom backend engine scores the URL based on TLD reputation, punycode spoofing, SSL/TLS presence, domain age, and keyword heuristics. 
* **The Audit Trail (SQLite):** All scans are permanently logged to a local SQLite database, allowing security teams to filter and review high-risk domains over time.
