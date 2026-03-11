import os
import sqlite3
import tempfile
import ipaddress
import urllib.parse
from datetime import datetime

import streamlit as st
from playwright.sync_api import sync_playwright
import whois


DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")

SUSPECT_WORDS = ["login", "bank", "secure", "account", "verify", "update", "free"]
SUSPECT_TLDS = {"ru", "cn", "tk", "ml", "ga", "cf", "gq"}
NEW_DOMAIN_DAYS_HIGH_RISK = 30
LONG_URL_THRESHOLD = 100


def init_db() -> None:
    """Ensure the SQLite database and table exist."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT,
                domain_age_days INTEGER,
                risk_level TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def save_scan(url: str, domain: str | None, domain_age_days: int | None, risk_level: str) -> None:
    """Persist a single scan result."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO scans (url, domain, domain_age_days, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                url,
                domain,
                domain_age_days if isinstance(domain_age_days, int) else None,
                risk_level,
                datetime.utcnow().isoformat(timespec="seconds"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan_history(only_dangerous: bool = True) -> list[dict]:
    """Return saved scan history; optionally filter to high‑risk only."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if only_dangerous:
            rows = conn.execute(
                "SELECT url, domain, domain_age_days, risk_level, created_at "
                "FROM scans WHERE risk_level = 'High' ORDER BY id DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT url, domain, domain_age_days, risk_level, created_at "
                "FROM scans ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def normalize_url(raw_url: str) -> str | None:
    """Normalize and validate a user‑provided URL string."""
    raw_url = raw_url.strip()
    if not raw_url:
        return None

    # Prepend https:// if user omitted the scheme
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parsed.geturl()


def extract_domain(url: str) -> str | None:
    """Best‑effort extraction of the host/domain portion of a URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.lower() or None
    except Exception:
        return None


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split(":")[0])
        return True
    except ValueError:
        return False


def get_tld(host: str) -> str | None:
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-1].lower()
    return None


# --- 1. THE SANDBOX ENGINE ---
def capture_screenshot(url: str) -> dict:
    """Open a URL in a hidden browser, take a screenshot, and return metadata."""
    browser = None
    page = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=10000, wait_until="networkidle")

            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            tmp_file.close()
            page.screenshot(path=tmp_file.name, full_page=True)

            return {"path": tmp_file.name, "final_url": page.url}
    except Exception as e:
        return {"error": f"Error capturing screenshot: {e}"}
    finally:
        try:
            if page is not None:
                page.close()
        except Exception:
            pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass


# --- 2. THE SECURITY ENGINE ---
def check_security(url: str, final_url: str | None = None) -> dict:
    """Analyze the URL string, WHOIS data, and compute an overall risk level."""
    results: dict = {}

    normalized_url = normalize_url(url) or url
    results["normalized_url"] = normalized_url
    host = extract_domain(normalized_url)
    results["domain"] = host
    results["is_ip"] = is_ip_address(host) if host else False

    # Check 1: HTTPS
    results["is_https"] = normalized_url.startswith("https://")

    # Check 2: Suspicious Keywords
    lower_url = normalized_url.lower()
    results["found_keywords"] = [word for word in SUSPECT_WORDS if word in lower_url]

    # Check 3: URL length
    results["url_length"] = len(normalized_url)

    # Check 4: Punycode & TLD heuristic
    results["has_punycode"] = "xn--" in host if host else False
    tld = get_tld(host) if host else None
    results["suspicious_tld"] = tld in SUSPECT_TLDS if tld else False

    # Check 5: Redirect / final destination mismatch
    if final_url:
        final_host = extract_domain(final_url)
        results["final_url"] = final_url
        results["final_domain"] = final_host
        if final_host and host:
            results["domain_mismatch"] = final_host.split(".")[-2:] != host.split(".")[-2:]
        else:
            results["domain_mismatch"] = False
    else:
        results["final_url"] = None
        results["final_domain"] = None
        results["domain_mismatch"] = False

    # WHOIS / Domain Age
    results["domain_age_days"] = "Unknown"
    results["registrar"] = None
    results["country"] = None
    results["expiration_date"] = None

    if host and not results["is_ip"]:
        try:
            w = whois.whois(host)

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                else:
                    # Fallback: try casting to datetime
                    age_days = (datetime.now() - datetime.strptime(str(creation_date), "%Y-%m-%d")).days
                results["domain_age_days"] = age_days
            else:
                results["domain_age_days"] = "Unknown"

            results["registrar"] = getattr(w, "registrar", None)
            results["country"] = getattr(w, "country", None)

            expiration_date = getattr(w, "expiration_date", None)
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            results["expiration_date"] = (
                expiration_date.isoformat() if isinstance(expiration_date, datetime) else str(expiration_date)
                if expiration_date
                else None
            )
        except Exception:
            results["domain_age_days"] = "Error reading WHOIS"

    # Risk scoring
    score = 0
    age = results["domain_age_days"]

    if not results["is_https"]:
        score += 2
    if results["found_keywords"]:
        score += 2
    if isinstance(age, int):
        if age < NEW_DOMAIN_DAYS_HIGH_RISK:
            score += 3
        elif age < 180:
            score += 1
    if results["is_ip"]:
        score += 2
    if results["url_length"] > LONG_URL_THRESHOLD:
        score += 1
    if results["has_punycode"] or results["suspicious_tld"]:
        score += 2
    if results["domain_mismatch"]:
        score += 2

    if score >= 6:
        risk_level = "High"
    elif score >= 3:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    results["risk_score"] = score
    results["risk_level"] = risk_level

    return results


# --- 3. THE DASHBOARD UI ---
def main():
    # Custom CSS theme: "Exquisite, Protective, and Warm"
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        html, body, [data-testid="stAppViewContainer"], .stApp {
            background: #1A1817;
            color: #F5F1E8;
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }

        #MainMenu {visibility: hidden;}
        header {visibility: hidden;}
        footer {visibility: hidden;}

        h1, h2, h3, h4, h5, h6 {
            color: #F5F1E8;
        }

        .exquisite-title {
            font-weight: 600;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-size: 0.9rem;
            color: #D4AF37;
            margin-bottom: -0.5rem;
        }

        .vault-card {
            background: rgba(39, 36, 34, 0.96);
            border-radius: 16px;
            border: 1px solid rgba(212, 175, 55, 0.65);
            box-shadow: 0 18px 45px rgba(0, 0, 0, 0.65);
            padding: 1.25rem 1.5rem;
            backdrop-filter: blur(18px);
        }

        .vault-card h2, .vault-card h3 {
            color: #F7F3E8;
        }

        .stTextInput > div > div > input {
            background-color: #272422;
            color: #F5F1E8;
            border-radius: 999px;
            border: 1px solid rgba(212, 175, 55, 0.4);
        }

        .stTextInput > div > div > input:focus {
            border-color: #D4AF37;
            box-shadow: 0 0 0 1px #D4AF37;
        }

        .stTabs [data-baseweb="tab-list"] {
            border-bottom: 1px solid rgba(212, 175, 55, 0.25);
        }

        .stTabs [data-baseweb="tab"] {
            color: #E6E0D0;
        }

        .stTabs [aria-selected="true"] {
            color: #F5F1E8 !important;
            border-bottom: 2px solid #D4AF37 !important;
        }

        .stButton > button {
            background: linear-gradient(135deg, #D4AF37, #ECCB6F);
            color: #1A1817;
            font-weight: 600;
            border-radius: 999px;
            border: none;
            padding: 0.6rem 1.8rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
            transition: all 0.18s ease-out;
        }

        .stButton > button:hover {
            box-shadow: 0 0 18px rgba(212, 175, 55, 0.8);
            transform: translateY(-1px);
        }

        /* Alert cards tuned for dark theme */
        div.stAlert {
            border-radius: 12px;
            border-width: 1px;
            border-style: solid;
            background-color: #221F1D;
        }

        div.stAlert.stSuccess {
            border-color: rgba(46, 160, 67, 0.7);
            background: rgba(22, 61, 37, 0.95);
        }

        div.stAlert.stWarning {
            border-color: rgba(230, 168, 80, 0.8);
            background: rgba(77, 51, 24, 0.95);
        }

        div.stAlert.stError {
            border-color: rgba(220, 76, 76, 0.85);
            background: rgba(79, 25, 25, 0.95);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.set_page_config(page_title="URL Scanner", layout="wide")
    init_db()

    st.markdown('<div class="exquisite-title">Fintech Threat Intelligence</div>', unsafe_allow_html=True)
    st.title("🛡️ URL Security Checker")
    st.markdown("Enter a URL below to safely analyze it, and review a history of dangerous links.")

    tab_scan, tab_history = st.tabs(["Scan URL", "Scan History"])

    with tab_scan:
        target_url = st.text_input("Enter URL (e.g., https://google.com):")

        if st.button("Analyze URL"):
            normalized = normalize_url(target_url)
            if not normalized:
                st.error("Please enter a valid URL (e.g. example.com or https://example.com).")
            else:
                col1, col2 = st.columns([2, 1])

                # Left Column: The Screenshot
                with col1:
                    st.markdown('<div class="vault-card">', unsafe_allow_html=True)
                    st.subheader("🌐 Sandboxed View")
                    with st.spinner("Capturing screenshot safely..."):
                        shot = capture_screenshot(normalized)
                        if "error" in shot:
                            st.error(shot["error"])
                            final_url = None
                        else:
                            st.image(shot["path"], caption="Isolated browser view")
                            final_url = shot.get("final_url")
                    st.markdown("</div>", unsafe_allow_html=True)

                # Right Column: The Security Report
                with col2:
                    st.markdown('<div class="vault-card">', unsafe_allow_html=True)
                    st.subheader("📊 Security Report")
                    with st.spinner("Analyzing domain details..."):
                        sec_data = check_security(normalized, final_url=final_url)

                        # Overall Risk
                        risk_level = sec_data["risk_level"]
                        if risk_level == "High":
                            st.error(f"Overall Risk: HIGH (score {sec_data['risk_score']})")
                            st.caption("This link has multiple phishing or safety red flags and should be treated as dangerous.")
                        elif risk_level == "Medium":
                            st.warning(f"Overall Risk: MEDIUM (score {sec_data['risk_score']})")
                            st.caption("Some signals look suspicious. Be cautious before entering passwords or personal data.")
                        else:
                            st.success(f"Overall Risk: LOW (score {sec_data['risk_score']})")
                            st.caption("We did not find strong phishing indicators, but always double‑check the URL yourself.")

                        # Save scan to database
                        save_scan(
                            url=sec_data["normalized_url"],
                            domain=sec_data.get("domain"),
                            domain_age_days=sec_data.get("domain_age_days")
                            if isinstance(sec_data.get("domain_age_days"), int)
                            else None,
                            risk_level=risk_level,
                        )

                        st.markdown("---")

                        # Display HTTPS Status
                        if sec_data["is_https"]:
                            st.success("✅ Uses HTTPS (encrypted connection).")
                            st.caption("HTTPS helps protect data in transit, but it does not guarantee the site is trustworthy.")
                        else:
                            st.error("❌ No HTTPS (unencrypted & risky!).")
                            st.caption("Attackers can intercept or modify data sent to this site.")

                        # Display Keyword Status
                        if sec_data["found_keywords"]:
                            st.warning(
                                f"⚠️ Suspicious words found in URL: {', '.join(sec_data['found_keywords'])}"
                            )
                            st.caption(
                                "Phishing links often include words like 'login', 'verify', or 'secure' to trick users."
                            )
                        else:
                            st.success("✅ No obvious phishing keywords detected in the URL.")

                        # Display Domain Age
                        age = sec_data["domain_age_days"]
                        if isinstance(age, int):
                            if age < NEW_DOMAIN_DAYS_HIGH_RISK:
                                st.error(f"❌ Domain is very new! ({age} days old) - High risk.")
                                st.caption(
                                    "Scammers frequently register fresh domains and abandon them quickly after attacks."
                                )
                            else:
                                st.info(f"ℹ️ Domain age: {age} days.")
                        else:
                            st.warning(f"⚠️ Domain age could not be determined: {age}")

                        # Display redirect / final domain info
                        if sec_data.get("final_url") and sec_data.get("domain_mismatch"):
                            st.error(
                                f"❌ Redirects to a different domain: {sec_data['final_domain']} "
                                f"(initial: {sec_data['domain']})."
                            )
                            st.caption(
                                "Phishing links sometimes send you through multiple domains to hide the final destination."
                            )
                        elif sec_data.get("final_url"):
                            st.info(f"Final destination after redirects: {sec_data['final_url']}")

                        # WHOIS extras
                        whois_lines = []
                        if sec_data.get("registrar"):
                            whois_lines.append(f"Registrar: {sec_data['registrar']}")
                        if sec_data.get("country"):
                            whois_lines.append(f"Country: {sec_data['country']}")
                        if sec_data.get("expiration_date"):
                            whois_lines.append(f"Expires: {sec_data['expiration_date']}")
                        if whois_lines:
                            st.markdown("**WHOIS Summary**")
                            for line in whois_lines:
                                st.caption(line)
                    st.markdown("</div>", unsafe_allow_html=True)

    with tab_history:
        st.subheader("📜 Scan History")
        st.markdown('<div class="vault-card">', unsafe_allow_html=True)
        only_dangerous = st.checkbox("Show only dangerous (High‑risk) links", value=True)

        history = get_scan_history(only_dangerous=only_dangerous)
        if history:
            st.dataframe(history, use_container_width=True)
        else:
            if only_dangerous:
                st.info("No dangerous links have been recorded yet.")
            else:
                st.info("No scans recorded yet. Analyze a URL to start building history.")
        st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()