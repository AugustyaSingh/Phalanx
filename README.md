# 🛡️ Phalanx: Containerized Threat Intelligence Sandbox

**Phalanx** is an enterprise-grade, air-gapped security application designed to safely investigate, detonate, and log potentially malicious URLs. 

Instead of risking a host system by clicking unknown links, Phalanx spins up an isolated Linux container to perform deep heuristic analysis and capture visual evidence of phishing attempts. It provides a secure barrier between the user and the malicious web, built with a focus on zero-trust execution and persistent threat auditing.

## ✨ Key Features

* **Air-Gapped Detonation (Docker):** The entire application and browser engine run inside a containerized environment. Zero-day browser exploits or drive-by downloads are trapped in the container and destroyed upon shutdown, keeping the host OS completely safe.
* **Headless Visual Sandbox:** Utilizes Playwright (headless Chromium) to silently visit target URLs, wait for network idle, and capture full-page screenshots without exposing the user to malicious JavaScript payloads.
* **Heuristic Threat Engine:** Automatically scores URLs based on a custom risk matrix:
  * WHOIS Domain Age (flags newly registered, burner domains)
  * Typosquatting & Punycode detection (`xn--`)
  * Suspicious Top-Level Domains (TLDs)
  * Phishing keyword detection
  * SSL/TLS (HTTPS) validation
  * Redirect and final-destination mismatch detection
* **Persistent Security Audit Trail:** Integrates an SQLite database to permanently log all scans, allowing security teams to filter, review, and maintain a history of high-risk domains.
* **Premium Fintech UI:** Features a custom-styled, dark-mode dashboard (via injected CSS) designed for high-contrast readability and a protective, enterprise-grade aesthetic.

## ⚙️ Tech Stack

* **Backend Logic:** Python 3.12
* **Containerization:** Docker, Ubuntu/Linux Subsystem
* **Web Automation:** Playwright
* **Database:** SQLite
* **Frontend:** Streamlit (with custom HTML/CSS injections)
* **OSINT:** `python-whois`, `urllib`

## 🚀 Quick Start Deployment

Because the application is fully containerized, deployment requires zero local dependencies (other than Docker) and takes seconds.

### 1. Clone the repository
```bash
git clone [https://github.com/AugustyaSingh/Phalanx.git](https://github.com/AugustyaSingh/Phalanx.git)
cd Phalanx

## 🚀 Quick Start Deployment

Because the application is fully containerized, deployment takes seconds. 

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/your-repo-name.git](https://github.com/yourusername/your-repo-name.git)
   cd your-repo-name](https://github.com/AugustyaSingh/Phalanx)
2. Build the Docker Image: docker build -t phalanx-scanner
3. Run the Container: docker run -p 8501:8501 phalanx-scanner
4. http://localhost:8501
Gemini said
Here is the complete, professional README.md file. It is formatted specifically to catch the eye of recruiters and engineers, highlighting the security, architecture, and deployment aspects of your project.

You can copy everything inside the code block below and paste it directly into the README.md file in your GitHub repository.

Markdown
# 🛡️ Phalanx: Containerized Threat Intelligence Sandbox

**Phalanx** is an enterprise-grade, air-gapped security application designed to safely investigate, detonate, and log potentially malicious URLs. 

Instead of risking a host system by clicking unknown links, Phalanx spins up an isolated Linux container to perform deep heuristic analysis and capture visual evidence of phishing attempts. It provides a secure barrier between the user and the malicious web, built with a focus on zero-trust execution and persistent threat auditing.

## ✨ Key Features

* **Air-Gapped Detonation (Docker):** The entire application and browser engine run inside a containerized environment. Zero-day browser exploits or drive-by downloads are trapped in the container and destroyed upon shutdown, keeping the host OS completely safe.
* **Headless Visual Sandbox:** Utilizes Playwright (headless Chromium) to silently visit target URLs, wait for network idle, and capture full-page screenshots without exposing the user to malicious JavaScript payloads.
* **Heuristic Threat Engine:** Automatically scores URLs based on a custom risk matrix:
  * WHOIS Domain Age (flags newly registered, burner domains)
  * Typosquatting & Punycode detection (`xn--`)
  * Suspicious Top-Level Domains (TLDs)
  * Phishing keyword detection
  * SSL/TLS (HTTPS) validation
  * Redirect and final-destination mismatch detection
* **Persistent Security Audit Trail:** Integrates an SQLite database to permanently log all scans, allowing security teams to filter, review, and maintain a history of high-risk domains.
* **Premium Fintech UI:** Features a custom-styled, dark-mode dashboard (via injected CSS) designed for high-contrast readability and a protective, enterprise-grade aesthetic.

## ⚙️ Tech Stack

* **Backend Logic:** Python 3.12
* **Containerization:** Docker, Ubuntu/Linux Subsystem
* **Web Automation:** Playwright
* **Database:** SQLite
* **Frontend:** Streamlit (with custom HTML/CSS injections)
* **OSINT:** `python-whois`, `urllib`

## 🚀 Quick Start Deployment

Because the application is fully containerized, deployment requires zero local dependencies (other than Docker) and takes seconds.

### 1. Clone the repository
```bash
git clone [https://github.com/AugustyaSingh/Phalanx.git](https://github.com/AugustyaSingh/Phalanx.git)
cd Phalanx
2. Build the Docker Image
This step installs the OS-level dependencies, Python libraries, and the headless Chromium browser inside the container.

Bash
docker build -t phalanx-scanner .
3. Run the Container
This maps the container's web server to your local machine.

Bash
docker run -p 8501:8501 phalanx-scanner
4. Access the Dashboard
Open your web browser and navigate to:
http://localhost:8501

Developed by Augustya Singh
