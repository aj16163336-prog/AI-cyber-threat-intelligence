from datetime import datetime, timezone
from io import BytesIO, StringIO
from email.message import EmailMessage
from email.utils import parseaddr
import hashlib
import hmac
import ipaddress
import json
import os
import re
import smtplib
import sqlite3
import tomllib
import socket
import ssl
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier

from live_capture import capture_summary, list_interfaces

BASE_DIR = Path(__file__).parent
REPORT_PATH = BASE_DIR / "threat_report.csv"
DATABASE_PATH = BASE_DIR / "security_center.db"
LOCAL_EMAIL_SETTINGS_PATH = BASE_DIR / ".streamlit" / "email_settings.toml"
FEODO_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
VT_API_BASE = "https://www.virustotal.com/api/v3"
FEED_COLUMNS = [
    "first_seen_utc",
    "dst_ip",
    "dst_port",
    "c2_status",
    "last_online",
    "malware",
]

MITRE_ROWS = [
    {
        "Signal": "High packet-rate heuristic",
        "Technique ID": "T1498.001",
        "Technique": "Direct Network Flood",
        "Reference": "https://attack.mitre.org/techniques/T1498/001/",
    },
    {
        "Signal": "UNSW category: DoS",
        "Technique ID": "T1498",
        "Technique": "Network Denial of Service",
        "Reference": "https://attack.mitre.org/techniques/T1498/",
    },
    {
        "Signal": "UNSW category: Reconnaissance",
        "Technique ID": "T1595",
        "Technique": "Active Scanning",
        "Reference": "https://attack.mitre.org/techniques/T1595/",
    },
]


def connect_db():
    return sqlite3.connect(DATABASE_PATH)


def setting(name, default=""):
    if name == "EMAIL_ALERTS_ENABLED":
        return "false"
    if os.environ.get("CTI_DESKTOP_MODE") == "1" and LOCAL_EMAIL_SETTINGS_PATH.exists():
        try:
            local_settings = tomllib.loads(LOCAL_EMAIL_SETTINGS_PATH.read_text(encoding="utf-8"))
            if name in local_settings:
                return str(local_settings[name] or "").strip()
        except (OSError, tomllib.TOMLDecodeError):
            pass
    try:
        value = st.secrets.get(name, default)
    except Exception:
        value = default
    return str(value or os.environ.get(name, default)).strip()


def save_local_email_settings(values):
    """Persist SMTP settings only for the localhost desktop app, outside Git."""
    if os.environ.get("CTI_DESKTOP_MODE") != "1":
        raise RuntimeError("Local email settings can only be saved by the desktop app.")
    allowed = {
        "EMAIL_ALERTS_ENABLED", "ALERT_NOTIFY_MINIMUM", "SMTP_HOST", "SMTP_PORT",
        "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "ALERT_EMAIL_TO",
        "SMTP_USE_STARTTLS", "SMTP_USE_SSL",
    }
    if set(values) - allowed:
        raise ValueError("Unexpected local email setting.")
    LOCAL_EMAIL_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(f"{key} = {json.dumps(str(value))}" for key, value in values.items()) + "\n"
    LOCAL_EMAIL_SETTINGS_PATH.write_text(content, encoding="utf-8")


def apply_theme():
    st.markdown(
        """
        <style>
        :root {
            --cti-bg: #0b0d0c;
            --cti-panel: #141715;
            --cti-panel-raised: #191d1a;
            --cti-border: #2a302c;
            --cti-ink: #f2f3ef;
            --cti-muted: #9ba29b;
            --cti-lime: #cede62;
            --cti-olive: #8a852b;
            --cti-red: #e67d73;
        }
        @keyframes cti-arrive {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes cti-signal-pulse {
            0%, 100% { box-shadow: 0 0 0 0 #cede6220, 0 0 12px #cede6270; }
            50% { box-shadow: 0 0 0 5px #cede6208, 0 0 18px #cede6280; }
        }
        html, body, [data-testid="stAppViewContainer"] {
            background: radial-gradient(ellipse at 80% 0%, #171a15 0%, var(--cti-bg) 42%);
            color: var(--cti-ink);
            font-family: Inter, "Segoe UI", sans-serif;
            color-scheme: dark;
        }
        [data-testid="stHeader"] { background: transparent; }
        [data-testid="stMainBlockContainer"] {
            max-width: 1500px;
            padding: 2.1rem 2.5rem 3rem;
        }
        [data-testid="stMainBlockContainer"] > div > div > div[data-testid="stVerticalBlock"] {
            animation: cti-arrive .34s ease-out both;
        }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #131614 0%, #101211 100%);
            border-right: 1px solid var(--cti-border);
        }
        [data-testid="stSidebar"] [data-testid="stMainBlockContainer"],
        [data-testid="stSidebar"] .block-container { padding: 1.35rem 1rem 2rem; }
        [data-testid="stSidebar"] hr, hr { border-color: var(--cti-border); }
        h1, h2, h3, h4 { color: var(--cti-ink); letter-spacing: -0.035em; }
        h1 { font-size: clamp(1.8rem, 2.5vw, 2.45rem); font-weight: 650; }
        h2 { font-size: 1.25rem; font-weight: 620; }
        p, label, [data-testid="stCaptionContainer"] { color: var(--cti-muted); }
        [data-testid="stMetric"] {
            min-height: 122px;
            padding: 1.05rem 1.15rem;
            border: 1px solid var(--cti-border);
            border-radius: 14px;
            background: linear-gradient(145deg, #191d1a 0%, #131614 100%);
            transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
        }
        [data-testid="stMetric"]:hover {
            transform: translateY(-2px);
            border-color: #505a3e;
            box-shadow: 0 10px 28px #00000025;
        }
        [data-testid="stMetricLabel"] p {
            color: #aab0a8; font-size: .76rem; font-weight: 600;
            letter-spacing: .075em; text-transform: uppercase;
        }
        [data-testid="stMetricValue"] { color: var(--cti-ink); font-weight: 650; }
        [data-testid="stMetricDelta"] { font-size: .78rem; }
        [data-testid="stVerticalBlockBorderWrapper"] {
            border-color: var(--cti-border) !important;
            border-radius: 14px;
            background: linear-gradient(145deg, #171a18 0%, #131614 100%);
            transition: border-color .2s ease, box-shadow .2s ease;
        }
        [data-testid="stVerticalBlockBorderWrapper"]:hover {
            border-color: #3b4436 !important;
            box-shadow: 0 8px 24px #0000001e;
        }
        [data-testid="stDataFrame"] {
            border: 1px solid var(--cti-border);
            border-radius: 12px;
            overflow: hidden;
            background: var(--cti-panel);
        }
        [data-testid="stVegaLiteChart"], [data-testid="stArrowVegaLiteChart"] {
            border: 1px solid var(--cti-border);
            border-radius: 12px;
            background: var(--cti-panel);
            padding: .5rem;
        }
        [data-testid="stAlert"] {
            border: 1px solid var(--cti-border);
            border-radius: 12px;
            background: #171a18;
        }
        [data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea,
        [data-testid="stNumberInput"] input, [data-testid="stDateInput"] input {
            color: var(--cti-ink);
            background: #111412;
            border-color: #343b35;
            border-radius: 10px;
        }
        [data-baseweb="select"] > div {
            color: var(--cti-ink); background: #111412;
            border-color: #343b35; border-radius: 10px;
        }
        input[type="radio"], input[type="checkbox"] { accent-color: var(--cti-lime); }
        [data-testid="stSidebar"] [role="radiogroup"] { gap: .15rem; }
        [data-testid="stSidebar"] [role="radiogroup"] label {
            margin: 0; padding: .52rem .68rem; border-radius: 9px;
            transition: background .15s ease, color .15s ease;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label:hover { background: #202520; }
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
            background: #24291f; color: var(--cti-lime);
            box-shadow: inset 2px 0 0 var(--cti-lime);
        }
        [data-testid="stSidebar"] [role="radiogroup"] label p { color: inherit; }
        [data-testid="stButton"] button, [data-testid="stDownloadButton"] button,
        [data-testid="stFormSubmitButton"] button {
            min-height: 2.55rem; border-radius: 10px;
            border: 1px solid #414840; background: #202520;
            color: var(--cti-ink); font-weight: 600;
        }
        [data-testid="stButton"] button:hover, [data-testid="stDownloadButton"] button:hover {
            border-color: var(--cti-lime); color: var(--cti-lime);
            transform: translateY(-1px);
            box-shadow: 0 5px 16px #cede6215;
        }
        [data-testid="stButton"] button, [data-testid="stDownloadButton"] button,
        [data-testid="stFormSubmitButton"] button {
            transition: transform .16s ease, border-color .16s ease, color .16s ease, box-shadow .16s ease;
        }
        [data-testid="stFormSubmitButton"] button[kind="primary"],
        [data-testid="stButton"] button[kind="primary"] {
            color: #11130c; background: var(--cti-lime); border-color: var(--cti-lime);
        }
        [data-testid="stForm"] {
            padding: 1.15rem; border: 1px solid var(--cti-border);
            border-radius: 14px; background: #151816;
        }
        .cti-brand { display:flex; align-items:center; gap:.75rem; padding:.2rem .15rem 1.25rem; }
        .cti-brand-mark {
            display:grid; place-items:center; width:2.45rem; height:2.45rem;
            border-radius:.75rem; background:var(--cti-lime); color:#11130c;
            font-size:.78rem; font-weight:800; letter-spacing:-.04em;
        }
        .cti-brand-name { color:var(--cti-ink); font-size:.9rem; font-weight:750; letter-spacing:.04em; }
        .cti-brand-sub { display:block; color:var(--cti-muted); font-size:.62rem; letter-spacing:.12em; margin-top:.15rem; }
        .cti-sidebar-label, .cti-eyebrow {
            color:#a7ad9f; font-size:.67rem; font-weight:700; letter-spacing:.15em;
            text-transform:uppercase;
        }
        .cti-session {
            display:flex; align-items:center; gap:.55rem; margin:.5rem 0 1rem;
            padding:.65rem .75rem; border:1px solid #303a2b; border-radius:10px;
            background:#1b2118; color:#d5e28a; font-size:.78rem; font-weight:600;
        }
        .cti-dot { width:.48rem; height:.48rem; border-radius:50%; background:var(--cti-lime); animation:cti-signal-pulse 2.4s ease-in-out infinite; }
        .cti-page-heading {
            display:flex; justify-content:space-between; align-items:flex-end; gap:1rem;
            padding:0 0 1.4rem; margin-bottom:1.1rem; border-bottom:1px solid var(--cti-border);
        }
        .cti-page-heading h1 { margin:.35rem 0 .35rem; }
        .cti-page-heading h1 { animation:cti-arrive .42s ease-out both; }
        .cti-page-heading p { margin:0; max-width:52rem; color:#a3aaa2; }
        .cti-status {
            flex:0 0 auto; display:flex; align-items:center; gap:.5rem;
            padding:.5rem .72rem; border:1px solid #333a2e; border-radius:999px;
            color:#d5e28a; background:#171c15; font-size:.67rem; font-weight:700; letter-spacing:.09em;
        }
        .cti-hero {
            display:flex; justify-content:space-between; align-items:center; gap:1rem;
            padding:1.5rem 1.6rem; margin-bottom:1.15rem; border:1px solid #323a2f;
            border-radius:16px; background:linear-gradient(115deg,#1b2018 0%,#141715 70%);
            box-shadow:inset 3px 0 0 #cede6240, 0 12px 35px #00000015;
            transition:transform .2s ease, border-color .2s ease;
        }
        .cti-hero:hover { transform:translateY(-2px); border-color:#596137; }
        .cti-hero h2 { margin:.35rem 0 .45rem; font-size:1.45rem; }
        .cti-hero p { margin:0; max-width:48rem; }
        .cti-hero-mark {
            display:grid; place-items:center; flex:0 0 3.5rem; height:3.5rem;
            border:1px solid #596137; border-radius:1rem; color:var(--cti-lime);
            background:#272b1d; font-size:1.35rem;
        }
        .cti-section-label { margin:.35rem 0 .7rem; color:#a7ad9f; font-size:.68rem; font-weight:700; letter-spacing:.14em; text-transform:uppercase; }
        .cti-login-title { margin:.55rem 0 1rem; color:var(--cti-ink); font-size:clamp(2.2rem,4vw,3.7rem); font-weight:700; line-height:1.05; letter-spacing:-.06em; }
        .cti-login-title span { color:var(--cti-lime); }
        .cti-login-copy { max-width:34rem; color:#a6ada5; font-size:1rem; line-height:1.7; }
        .cti-login-points { margin-top:2rem; color:#c4c9c1; font-size:.86rem; line-height:2.2; }
        @media (max-width: 760px) {
            [data-testid="stMainBlockContainer"] { padding:1.2rem 1rem 2rem; }
            .cti-page-heading { align-items:flex-start; flex-direction:column; }
            .cti-hero { align-items:flex-start; }
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { animation-duration:.01ms !important; animation-iteration-count:1 !important; scroll-behavior:auto !important; transition-duration:.01ms !important; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_page_heading(title):
    descriptions = {
        "Live Network Monitor": "Observe network traffic and review the latest capture signals.",
        "Live Endpoint Security": "Review file, process, and connection activity from the local sensor.",
        "Threat Feed": "Browse threat intelligence signals collected for investigation.",
        "IOC Analysis": "Inspect indicators of compromise and their related findings.",
        "Analytics Dashboard": "Explore risk trends and attack-category patterns across detections.",
        "AI Engine": "Review the detection models and their latest analysis results.",
        "Explainable AI Assistant": "Understand each live event's score, evidence, and suggested investigation steps.",
        "AI Model Evaluation Lab": "Measure model performance on labeled holdout data and inspect its errors.",
        "MITRE ATT&CK Map": "Connect observed activity with known adversary techniques.",
        "Alert System": "Triage security alerts and prioritize follow-up actions.",
        "Incident Management": "Track investigations, ownership, and response progress.",
        "Report Generator": "Prepare and download security reports for review.",
    }
    description = descriptions.get(title, "Review signals and manage your security workflows.")
    st.markdown(
        f"""
        <div class="cti-page-heading">
          <div>
            <div class="cti-eyebrow">Security operations / workspace</div>
            <h1>{title}</h1>
            <p>{description}</p>
          </div>
          <div class="cti-status"><span class="cti-dot"></span> SECURITY CONSOLE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def init_database():
    with connect_db() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                mitre_id TEXT,
                source_event_id TEXT,
                status TEXT NOT NULL DEFAULT 'Open'
            )"""
        )
        alert_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(alerts)")
        }
        if "source_event_id" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN source_event_id TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_event_id "
            "ON alerts(source_event_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                notes TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL
            )"""
        )


def audit_event(action, details="", username=None):
    """Record security-relevant app actions without storing credentials."""
    actor = username or st.session_state.get("username", "anonymous")
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO audit_log (occurred_at, username, action, details) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), str(actor), str(action), str(details)[:1000]),
        )


def load_alerts():
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY id DESC", connection
        )


def hide_cleared_notifications(alerts):
    """Hide active alerts created before the last clear-all action, while retaining history."""
    if alerts.empty or "created_at" not in alerts.columns:
        return alerts
    with connect_db() as connection:
        row = connection.execute(
            "SELECT value FROM app_state WHERE key = 'notifications_cleared_at'"
        ).fetchone()
    if not row:
        return alerts
    cleared_at = pd.to_datetime(row[0], utc=True, errors="coerce")
    if pd.isna(cleared_at):
        return alerts
    active = alerts["status"].isin(["Open", "Acknowledged"])
    created = pd.to_datetime(alerts["created_at"], utc=True, errors="coerce")
    keep = ~active | (created > cleared_at)
    return alerts.loc[keep].copy()


def clear_all_notifications():
    """Close current active alerts and set a cutoff so old events cannot repopulate the inbox."""
    cleared_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    with connect_db() as connection:
        cursor = connection.execute(
            "UPDATE alerts SET status = 'Closed' WHERE status IN ('Open', 'Acknowledged')"
        )
        connection.execute(
            "INSERT INTO app_state (key, value) VALUES ('notifications_cleared_at', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (cleared_at,),
        )
    count = max(int(cursor.rowcount), 0)
    # Keep the Alert System focused on active items after clearing, even if the user
    # previously selected Closed/Resolved in its status filter.
    st.session_state["alert_status_filter"] = ["Open", "Acknowledged"]
    audit_event("alerts_cleared_in_bulk", f"count={count}; status=Closed")
    return count


def load_incidents():
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT * FROM incidents ORDER BY id DESC", connection
        )


def notify_security_alert(severity, title):
    """Show an in-app notification and email qualifying new alerts."""
    ranks = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    threshold = st.session_state.get("alert_notification_threshold", setting("ALERT_NOTIFY_MINIMUM", "High"))
    if ranks.get(str(severity), 0) < ranks.get(str(threshold), 3):
        return
    st.toast(f"{severity} alert: {title}", icon="🚨")
    if setting("EMAIL_ALERTS_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        return
    try:
        recipient = send_security_email(
            f"{severity} security alert: {title[:100]}",
            f"A security alert requires review.\n\nSeverity: {severity}\nAlert: {title}\n\nSign in to the AI Cyber Threat Intelligence app for details.",
        )
        audit_event("email_alert_sent", f"severity={severity}; recipient={recipient}")
    except Exception as error:
        audit_event("email_alert_failed", f"severity={severity}; error={str(error)[:300]}")
        st.warning(f"Email alert could not be sent: {error}")


def send_security_email(subject, body):
    """Send email through a provider API or SMTP, using private settings."""
    recipient = setting("ALERT_EMAIL_TO")
    username, password = setting("SMTP_USERNAME"), setting("SMTP_PASSWORD")
    provider = setting("EMAIL_PROVIDER", "smtp").strip().lower()
    sender = setting("RESEND_FROM", setting("SMTP_FROM", username)) if provider == "resend" else setting("SMTP_FROM", username)
    if not all((recipient, sender)):
        raise ValueError("Email settings are incomplete. Configure SMTP_FROM and ALERT_EMAIL_TO in app Secrets.")
    parsed_sender = parseaddr(sender)[1]
    parsed_recipient = parseaddr(recipient)[1]
    if "@" not in parsed_sender or "." not in parsed_sender.rsplit("@", 1)[-1]:
        raise ValueError("Set a valid sender email address. Resend requires a verified sender domain for regular delivery.")
    if "@" not in parsed_recipient or "." not in parsed_recipient.rsplit("@", 1)[-1]:
        raise ValueError("Set a real alert recipient email address in ALERT_EMAIL_TO.")
    if provider == "resend":
        api_key = setting("RESEND_API_KEY")
        if not api_key:
            raise ValueError("EMAIL_PROVIDER is set to resend, but RESEND_API_KEY is missing from app Secrets.")
        try:
            response = requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"from": sender, "to": [recipient], "subject": subject[:180], "text": body},
                timeout=20,
            )
            if not response.ok:
                try:
                    error_message = response.json().get("message", "Email API rejected the request")
                except (ValueError, AttributeError):
                    error_message = "Email API rejected the request"
                raise RuntimeError(f"Resend API returned HTTP {response.status_code}: {error_message}")
        except requests.RequestException as error:
            raise ConnectionError("Could not reach the Resend email API over HTTPS. Check the app's internet access and try again.") from error
        return recipient
    if provider != "smtp":
        raise ValueError("EMAIL_PROVIDER must be either 'smtp' or 'resend'.")
    host = setting("SMTP_HOST")
    if not host:
        raise ValueError("SMTP_HOST is missing from app Secrets.")
    try:
        port = int(setting("SMTP_PORT", "587"))
    except ValueError as error:
        raise ValueError("SMTP port must be 587 (STARTTLS) or 465 (SSL), unless your provider specifies another port.") from error
    use_ssl = setting("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}
    use_starttls = setting("SMTP_USE_STARTTLS", "true").lower() in {"1", "true", "yes"}
    if use_ssl and use_starttls:
        raise ValueError("Choose one secure mode: turn on SSL for port 465, or STARTTLS for port 587—not both.")
    if port == 465:
        use_ssl, use_starttls = True, False
    elif port == 587:
        use_ssl, use_starttls = False, True
    message = EmailMessage()
    message["Subject"] = subject[:180]
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=20) as server:
                if username:
                    if not password:
                        raise ValueError("SMTP password is missing for the configured username.")
                    server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if use_starttls:
                    server.starttls()
                    server.ehlo()
                if username:
                    if not password:
                        raise ValueError("SMTP password is missing for the configured username.")
                    server.login(username, password)
                server.send_message(message)
    except (smtplib.SMTPServerDisconnected, TimeoutError, OSError, ssl.SSLError) as error:
        mode = "SSL" if use_ssl else "STARTTLS" if use_starttls else "plain SMTP"
        if os.environ.get("CTI_DESKTOP_MODE") != "1":
            guidance = (
                "The hosted app's network may block outbound SMTP. Use the local desktop app with the endpoint sensor, "
                "or configure an email delivery API such as Resend/SendGrid instead of Gmail SMTP."
            )
        else:
            guidance = (
                "Check that this network allows outbound SMTP. If port 587 is blocked, try port 465 with SSL only; "
                "if both fail, try another trusted network or an email delivery API."
            )
        raise ConnectionError(
            f"SMTP connection to {host}:{port} closed unexpectedly ({mode}). "
            f"{guidance} For Gmail or Outlook, use an app password."
        ) from error
    return recipient


def add_alert(title, severity, details, mitre_id=""):
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO alerts
               (created_at, title, severity, details, mitre_id, status)
               VALUES (?, ?, ?, ?, ?, 'Open')""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                title,
                severity,
                details,
                mitre_id,
            ),
        )
    audit_event("alert_created", f"severity={severity}; title={title[:150]}")
    notify_security_alert(severity, title)


def sync_endpoint_alerts(events):
    """Turn endpoint events marked for review into deduplicated alerts."""
    if events is None or events.empty or "severity" not in events.columns:
        return 0

    severity_map = {"Review": "Medium", "High": "High", "Critical": "Critical"}

    def value(event, key, default=""):
        result = event.get(key, default)
        if result is None or pd.isna(result):
            return default
        return str(result).strip()

    inserted = 0
    notifications = []
    audit_rows = []
    with connect_db() as connection:
        for event in events.to_dict("records"):
            event_severity = value(event, "severity").title()
            if event_severity not in severity_map:
                continue

            event_id = value(event, "event_id")
            if not event_id:
                event_id = value(event, "event_uid") or value(event, "id")
            if not event_id:
                continue

            summary = value(event, "summary", "Endpoint event needs review")
            event_type = value(event, "event_type", "endpoint_event")
            occurred_at = value(
                event,
                "occurred_at",
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
            risk_score = value(event, "risk_score", "0")
            details = [
                "Source: Windows endpoint sensor",
                f"Event type: {event_type}",
                f"Risk score: {risk_score}/100",
                f"Signal: {summary}",
            ]
            for key, label in (
                ("file_name", "File"),
                ("folder", "Folder"),
                ("process_name", "Process"),
                ("remote_ip", "Remote IP"),
                ("remote_port", "Remote port"),
                ("details", "Assessment"),
            ):
                item = value(event, key)
                if item:
                    details.append(f"{label}: {item}")
            candidates = map_signal_to_mitre(" ".join([event_type, summary, *details]))
            mitre_id = candidates[0]["Technique ID"] if candidates else ""

            cursor = connection.execute(
                """INSERT OR IGNORE INTO alerts
                   (created_at, title, severity, details, mitre_id,
                    source_event_id, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'Open')""",
                (
                    occurred_at,
                    f"Endpoint signal: {summary}",
                    severity_map[event_severity],
                    "\n".join(details),
                    mitre_id,
                    f"endpoint:{event_id}",
                ),
            )
            inserted += max(cursor.rowcount, 0)
            if cursor.rowcount > 0:
                notifications.append((severity_map[event_severity], f"Endpoint signal: {summary}"))
                audit_rows.append(f"severity={severity_map[event_severity]}; event_id={event_id}")
    for detail in audit_rows:
        audit_event("endpoint_alert_created", detail)
    for severity, title in notifications:
        notify_security_alert(severity, title)
    return inserted


def add_incident(title, severity, notes):
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO incidents
               (created_at, title, severity, status, notes)
               VALUES (?, ?, ?, 'Open', ?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                title,
                severity,
                notes,
            ),
        )


def load_report():
    if REPORT_PATH.exists():
        try:
            return pd.read_csv(REPORT_PATH)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()


@st.cache_data(ttl=3, show_spinner=False)
def load_sensor_events(limit=500):
    """Read endpoint events from the cloud API, or local sensor database."""
    api_url = setting("API_BASE_URL").rstrip("/")
    api_token = setting("API_TOKEN")
    if api_url and api_token:
        response = requests.get(
            f"{api_url}/v1/events?limit={int(limit)}",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=12,
        )
        response.raise_for_status()
        return pd.DataFrame(response.json().get("events", [])), "cloud"

    if not DATABASE_PATH.exists():
        return pd.DataFrame(), "local"
    with connect_db() as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='endpoint_events'"
        ).fetchone()
        if not table:
            return pd.DataFrame(), "local"
        return pd.read_sql_query(
            "SELECT * FROM endpoint_events ORDER BY id DESC LIMIT ?",
            connection,
            params=(int(limit),),
        ), "local"


def sensor_health_status(events, source):
    """Report local sensor process health, or cloud telemetry recency without guessing process state."""
    if source == "cloud":
        if events.empty:
            return "Waiting for telemetry", "The cloud API has not received an endpoint event yet."
        time_column = next((name for name in ("occurred_at", "created_at") if name in events.columns), None)
        if not time_column:
            return "Telemetry available", "Endpoint events are available, but their timestamps are missing."
        timestamps = pd.to_datetime(events[time_column], utc=True, errors="coerce").dropna()
        if timestamps.empty:
            return "Telemetry available", "Endpoint events are available, but their timestamps could not be read."
        latest = timestamps.max()
        age_seconds = max(0, (datetime.now(timezone.utc) - latest.to_pydatetime()).total_seconds())
        age_minutes = int(age_seconds // 60)
        if age_seconds <= 120:
            return "Recent telemetry", "The cloud received an endpoint event within the last 2 minutes."
        return "No recent telemetry", f"Last cloud event was about {age_minutes} minute(s) ago; quiet activity does not prove the sensor is stopped."

    if os.name != "nt" and os.environ.get("CTI_DESKTOP_MODE") != "1":
        return "Laptop sensor not visible", "A hosted dashboard cannot inspect the laptop process directly. Use the local desktop app or connect the endpoint API."

    try:
        import psutil
        expected_script = os.path.normcase(os.path.abspath(BASE_DIR / "endpoint_monitor.py"))
        running = False
        for process in psutil.process_iter(["cmdline"]):
            try:
                for argument in process.info.get("cmdline") or []:
                    if os.path.normcase(os.path.abspath(str(argument))) == expected_script:
                        running = True
                        break
            except (psutil.Error, OSError, TypeError, ValueError):
                continue
            if running:
                break
    except (ImportError, OSError):
        return "Status unavailable", "Process monitoring is unavailable on this computer."
    if running:
        return "Running", "The local endpoint sensor process is active on this computer."
    return "Stopped", "The local endpoint sensor process is not running. Start the desktop app to launch it."


@st.fragment(run_every="5s")
def render_dashboard_alert_inbox():
    """Show persistent in-app alerts and let the analyst acknowledge one quickly."""
    alerts = hide_cleared_notifications(load_alerts())
    open_alerts = alerts[alerts["status"] == "Open"] if not alerts.empty else alerts
    active_alerts = alerts[alerts["status"].isin(["Open", "Acknowledged"])] if not alerts.empty else alerts
    st.markdown('<div class="cti-section-label">In-app alert inbox</div>', unsafe_allow_html=True)
    controls = st.columns([3, 1])
    with controls[1]:
        if st.button(
            "Clear all",
            key="dashboard_clear_all_notifications",
            disabled=active_alerts.empty,
            type="secondary",
            width="stretch",
        ):
            cleared_count = clear_all_notifications()
            st.session_state["notifications_cleared_message"] = (
                f"Cleared {cleared_count} notification(s). New alerts will still appear."
            )
            st.rerun()
    cleared_message = st.session_state.pop("notifications_cleared_message", None)
    if cleared_message:
        st.success(cleared_message)
    if active_alerts.empty:
        st.caption("No active in-app alerts. New alerts will appear here and in the Alert System.")
        return
    st.caption(f"{len(open_alerts)} need acknowledgement · {len(active_alerts)} active")
    shown = active_alerts.head(5)
    columns = [name for name in ("created_at", "title", "severity", "status") if name in shown.columns]
    st.dataframe(shown[columns], hide_index=True, width="stretch")
    if not open_alerts.empty:
        alert_options = {
            f"#{row.id} · {row.severity} · {str(row.title)[:80]}": int(row.id)
            for row in open_alerts.itertuples()
        }
        selected_label = st.selectbox(
            "Alert to acknowledge", list(alert_options), key="dashboard_alert_ack_selection"
        )
        if st.button("Acknowledge alert", key="dashboard_acknowledge_alert"):
            selected_id = alert_options[selected_label]
            with connect_db() as connection:
                connection.execute(
                    "UPDATE alerts SET status = 'Acknowledged' WHERE id = ? AND status = 'Open'",
                    (selected_id,),
                )
            audit_event("alert_status_changed", f"alert_id={selected_id}; status=Acknowledged")
            st.rerun()


@st.cache_data(ttl=900, show_spinner=False)
def load_feodo_feed():
    response = requests.get(
        FEODO_FEED_URL,
        timeout=15,
        headers={"User-Agent": "Local-CTI/1.0"},
    )
    response.raise_for_status()
    try:
        feed = pd.read_csv(
            StringIO(response.text),
            comment="#",
            header=None,
            names=FEED_COLUMNS,
        )
    except pd.errors.EmptyDataError:
        feed = pd.DataFrame(columns=FEED_COLUMNS)

    if "dst_ip" in feed.columns:
        feed["dst_ip"] = feed["dst_ip"].astype(str).str.strip()
    return feed


def make_pdf(report):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    _, page_height = letter
    y = page_height - 50

    pdf.setTitle("AI Cyber Threat Intelligence Report")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(45, y, "AI Cyber Threat Intelligence Report")
    y -= 28
    pdf.setFont("Helvetica", 10)
    pdf.drawString(
        45,
        y,
        "Generated: " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    y -= 24
    pdf.drawString(45, y, f"Records: {len(report)} (showing up to 100)")
    y -= 25
    columns = list(report.columns[:7])
    def pdf_safe(value):
        return str(value).encode("latin-1", "replace").decode("latin-1")

    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(45, y, pdf_safe(" | ".join(str(column)[:18] for column in columns)[:112]))
    y -= 14
    pdf.setFont("Helvetica", 7)
    for _, row in report[columns].head(100).iterrows():
        values = [pdf_safe(str(row.get(column, "")).replace("\n", " ")[:22]) for column in columns]
        pdf.drawString(45, y, " | ".join(values)[:112])
        y -= 11
        if y < 45:
            pdf.showPage()
            y = page_height - 45
            pdf.setFont("Helvetica", 7)

    pdf.save()
    return buffer.getvalue()


def render_dashboard(report):
    endpoint_events = pd.DataFrame()
    event_source = "local"
    try:
        endpoint_events, event_source = load_sensor_events(limit=500)
    except Exception as error:
        st.warning(f"Endpoint events could not be loaded: {error}")

    alerts = load_alerts()
    incidents = load_incidents()
    live = st.session_state.get("live_summary", {})
    total_records = len(report)
    critical = (
        int((report["risk_level"].astype(str) == "Critical").sum())
        if "risk_level" in report.columns
        else 0
    )
    open_alerts = int((alerts["status"] == "Open").sum()) if not alerts.empty else 0
    open_incidents = int((incidents["status"] == "Open").sum()) if not incidents.empty else 0

    st.markdown(
        """
        <div class="cti-page-heading">
          <div>
            <div class="cti-eyebrow">Security operations / overview</div>
            <h1>Threat operations</h1>
            <p>Endpoint activity, network signals, and model findings in one workspace.</p>
          </div>
          <div class="cti-status"><span class="cti-dot"></span> SECURITY CONSOLE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="cti-hero">
          <div>
            <div class="cti-eyebrow">Operations snapshot</div>
            <h2>Stay ahead of suspicious activity</h2>
            <p>Review new endpoint events, prioritize critical findings, and track the response queue.</p>
          </div>
          <div class="cti-hero-mark">⌁</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Recent endpoint events", len(endpoint_events))
    col2.metric("Open alerts", open_alerts)
    col3.metric("Critical model risks", critical)
    col4.metric("Open incidents", open_incidents)

    @st.fragment(run_every="5s")
    def sensor_health_tile():
        try:
            latest_events, latest_source = load_sensor_events(limit=500)
            health, explanation = sensor_health_status(latest_events, latest_source)
            st.metric("Endpoint sensor", health, help=explanation)
        except Exception:
            st.metric("Endpoint sensor", "Unavailable", help="Could not read sensor status or recent telemetry.")

    sensor_health_tile()

    if not report.empty and "risk_level" in report.columns:
        left, right = st.columns(2)
        with left:
            with st.container(border=True):
                st.subheader("Risk distribution")
                counts = report["risk_level"].astype(str).value_counts().reindex(
                    ["Low", "Medium", "High", "Critical"], fill_value=0
                )
                st.bar_chart(counts, color="#CEDE62")
        with right:
            with st.container(border=True):
                st.subheader("Attack categories")
                if "predicted_category" in report.columns:
                    st.bar_chart(report["predicted_category"].value_counts().head(8), color="#8A852B")
                else:
                    st.info("Attack-category predictions are not available in this report.")

    left, right = st.columns([1.1, 0.9], gap="large")
    with left:
        with st.container(border=True):
            st.subheader("Recent endpoint activity")
            st.caption("Source: deployed API" if event_source == "cloud" else "Source: this computer")
            if endpoint_events.empty:
                st.info("No endpoint events yet. Start the local sensor to begin collecting events.")
            else:
                recent = endpoint_events.head(8).copy()
                if "created_at" in recent.columns and "occurred_at" not in recent.columns:
                    recent = recent.rename(columns={"created_at": "occurred_at"})
                columns = [
                    name for name in
                    ("occurred_at", "event_type", "severity", "summary", "risk_score")
                    if name in recent.columns
                ]
                st.dataframe(recent[columns], hide_index=True, width="stretch")
    with right:
        with st.container(border=True):
            st.subheader("Live network monitor")
            if live:
                a, b = st.columns(2)
                a.metric("Packets captured", live["packets"])
                b.metric("Packets / second", live["packets_per_second"])
                st.caption(f"Unique destination ports: {len(live['destination_ports'])}")
            else:
                st.info("No capture summary yet. Start a capture from Live Monitor.")

            render_dashboard_alert_inbox()


def render_live_monitor():
    render_page_heading("Live Network Monitor")
    st.write("Capture packet headers on a selected network adapter on this computer.")
    if os.name != "nt":
        st.warning(
            "This dashboard is running on a cloud or Linux host, so packet capture here "
            "uses the server's adapter. To monitor this Windows laptop, run the local "
            "Endpoint Security sensor."
        )
    st.caption(
        "Packet payloads are not stored. Rate and port rules generate heuristic signals "
        "that require review; they do not confirm an attack."
    )

    try:
        interfaces = list_interfaces()
        interface_names = list(dict.fromkeys(name for name, _ in interfaces))
    except Exception as error:
        st.error(f"Could not read network adapters: {error}")
        return

    if not interface_names:
        st.error("No network adapters were found.")
        return

    default_index = interface_names.index("Wi-Fi") if "Wi-Fi" in interface_names else 0
    selected_interface = st.selectbox(
        "Network adapter",
        interface_names,
        index=default_index,
    )
    seconds = st.slider("Capture duration (seconds)", 10, 60, 20, step=10)

    if st.button("Start live capture", type="primary"):
        try:
            with st.spinner(f"Capturing on {selected_interface} for {seconds} seconds..."):
                summary = capture_summary(selected_interface, seconds)
            st.session_state["live_summary"] = summary

            possible_alerts = []
            if summary["packets_per_second"] >= 100:
                possible_alerts.append(
                    (
                        "High packet-rate signal",
                        "High",
                        f"{summary['packets_per_second']} packets/second observed.",
                        "T1498.001",
                    )
                )
            if len(summary["destination_ports"]) >= 30:
                possible_alerts.append(
                    (
                        "High destination-port diversity",
                        "Medium",
                        f"{len(summary['destination_ports'])} unique destination ports observed.",
                        "T1595",
                    )
                )

            try:
                feed = load_feodo_feed()
                bad_ips = set(feed["dst_ip"].astype(str)) if not feed.empty else set()
                matched_ips = set(summary["destination_ips"]) & bad_ips
                if matched_ips:
                    possible_alerts.append(
                        (
                            "Destination matched Feodo Tracker",
                            "Critical",
                            f"{len(matched_ips)} destination IP matched the current feed.",
                            "",
                        )
                    )
            except Exception:
                st.warning("Threat-feed check skipped: source is temporarily unavailable.")

            for alert in possible_alerts:
                add_alert(*alert)

            st.success("Capture complete.")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Packets", summary["packets"])
            c2.metric("Bytes", summary["bytes"])
            c3.metric("Packets / second", summary["packets_per_second"])
            c4.metric("Unique destination ports", len(summary["destination_ports"]))

            if summary["protocols"]:
                st.subheader("Protocol counts")
                st.bar_chart(pd.Series(summary["protocols"]).sort_values(ascending=False), color="#CEDE62")
            else:
                st.info("No IP packets were observed during this capture.")

            if possible_alerts:
                st.warning(f"{len(possible_alerts)} possible signal(s) saved in Alert System.")
            else:
                st.success("No configured alert thresholds were reached during this capture.")
        except Exception as error:
            st.error(f"Could not start packet capture: {error}")
            st.info("Npcap is required. If access is denied, run VS Code as an administrator.")

    previous = st.session_state.get("live_summary")
    if previous and not st.button("Hide last capture summary"):
        st.caption(
            f"Last capture: {previous['duration_seconds']} seconds on "
            f"{previous['interface']}."
        )


def render_endpoint_security():
    render_page_heading("Live Endpoint Security")
    st.write(
        "The local sensor records event metadata for files in Downloads, Desktop, and "
        "Documents, newly started processes, installed applications, and public "
        "outbound connections."
    )
    st.caption(
        "File contents and packet payloads are never uploaded. Full file paths stay in "
        "the local database; cloud sync sends only the folder label, filename, and SHA-256."
    )
    if os.environ.get("CTI_DESKTOP_MODE") == "1":
        st.info(
            "The local sensor starts automatically with this desktop app and runs "
            "in the background. New file, process, and connection events appear "
            "when you revisit this page or choose `Refresh events`."
        )
    else:
        st.info(
            "The hosted dashboard cannot inspect files on this laptop. Start the "
            "`Start AI CTI Sensor` shortcut on the laptop, then select `Refresh events`."
        )

    @st.fragment(run_every="5s")
    def endpoint_panel():
        try:
            events, source = load_sensor_events()
        except Exception as error:
            st.error(f"Could not load sensor events: {error}")
            return

        if st.button("Refresh events", key="refresh_endpoint_events"):
            load_sensor_events.clear()
            st.rerun()

        st.caption("Event source: " + ("deployed API" if source == "cloud" else "this computer") + " · Auto-refresh: 5 sec")
        sensor_state, sensor_explanation = sensor_health_status(events, source)
        st.metric("Sensor health", sensor_state, help=sensor_explanation)
        st.caption(sensor_explanation)
        if events.empty:
            st.info("No events have arrived yet. Start the sensor; this list refreshes automatically.")
            return

        new_alerts = sync_endpoint_alerts(events)
        if new_alerts:
            st.success(f"Added {new_alerts} endpoint review alert(s) to Alert System.")

        review_count = int(events["severity"].isin(["Review", "High", "Critical"]).sum())
        file_count = int(events["event_type"].astype(str).str.startswith("file_").sum())
        process_count = int((events["event_type"] == "process_started").sum())
        connection_count = int((events["event_type"] == "network_connection").sum())
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Events", len(events))
        c2.metric("Needs review", review_count)
        c3.metric("File events", file_count)
        c4.metric("Process / connection events", process_count + connection_count)

        if source == "local" and "synced" in events.columns:
            st.caption(
                f"Cloud-synced events: {int(events['synced'].fillna(0).astype(int).sum())} / {len(events)}"
            )
        st.dataframe(events, hide_index=True, width="stretch")

    endpoint_panel()


def render_threat_feed():
    render_page_heading("Threat Feed")
    st.write("Botnet command-and-control IP indicators from Feodo Tracker.")
    st.caption("Source: abuse.ch Feodo Tracker. Feed is cached for 15 minutes.")

    if st.button("Refresh threat feed"):
        load_feodo_feed.clear()

    try:
        with st.spinner("Loading threat feed..."):
            feed = load_feodo_feed()
        st.metric("Indicators received", len(feed))
        if feed.empty:
            st.info("The feed is currently empty. Try refreshing it later.")
        else:
            columns = ["first_seen_utc", "dst_ip", "dst_port", "c2_status", "last_online", "malware"]
            st.dataframe(feed[columns].head(500), hide_index=True, width="stretch")
    except Exception as error:
        st.error(f"Could not load the threat feed: {error}")
        st.write("Check the internet connection, then select Refresh threat feed.")


def render_ioc_analysis():
    render_page_heading("IOC Analysis")
    st.write("Check an IP, domain, or file hash against available reputation sources.")
    ioc_type = st.selectbox("Indicator type", ["IP address", "Domain", "File hash (MD5 / SHA-1 / SHA-256)"])
    placeholder = {"IP address": "203.0.113.10", "Domain": "example.org", "File hash (MD5 / SHA-1 / SHA-256)": "Paste a file hash; do not upload the file"}[ioc_type]
    ioc_text = st.text_input("Indicator", placeholder=placeholder)
    vt_key = setting("VT_API_KEY")
    st.caption("VirusTotal API key is optional. The indicator text is sent to VirusTotal only when you select Check IOC and a key is configured. File contents are never uploaded.")
    if st.button("Check IOC", type="primary"):
        try:
            value = ioc_text.strip()
            if not value:
                st.error("Enter an indicator first.")
                return
            if ioc_type == "IP address":
                address = ipaddress.ip_address(value)
                normalized = str(address)
                if vt_key:
                    result = query_virustotal("ip_addresses", normalized, vt_key)
                    show_virustotal_result(result, normalized)
                else:
                    if address.version != 4:
                        st.info("Feodo Tracker fallback supports IPv4 only. Configure VT_API_KEY for IPv6 reputation checks.")
                        return
                    feed = load_feodo_feed()
                    matches = feed[feed["dst_ip"] == normalized] if not feed.empty else pd.DataFrame()
                    if matches.empty:
                        st.success("No match for this IP was found in the current Feodo Tracker feed.")
                    else:
                        st.error("Feodo Tracker match found. Review this indicator before taking action.")
                        st.dataframe(matches, hide_index=True, width="stretch")
                        add_alert("IOC match from manual analysis", "High", f"IPv4 {normalized} matched {len(matches)} Feodo Tracker record(s).")
            else:
                if not vt_key:
                    st.warning("Configure VT_API_KEY in app Secrets to check domains and hashes with VirusTotal.")
                    return
                if ioc_type == "Domain":
                    normalized = value.rstrip(".").lower()
                    if len(normalized) > 253 or not all(part and len(part) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", part) for part in normalized.split(".")):
                        st.error("Enter a valid domain name.")
                        return
                    endpoint = "domains"
                else:
                    normalized = value.lower()
                    if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", normalized):
                        st.error("Enter a valid MD5, SHA-1, or SHA-256 hash.")
                        return
                    endpoint = "files"
                result = query_virustotal(endpoint, normalized, vt_key)
                show_virustotal_result(result, normalized)
            audit_event("ioc_lookup", f"type={ioc_type}; indicator={normalized}")
        except ValueError:
            st.error("Enter a valid IP address.")
        except Exception as error:
            st.error(f"Could not check the indicator: {error}")


def query_virustotal(object_type, indicator, api_key):
    response = requests.get(
        f"{VT_API_BASE}/{object_type}/{indicator}",
        headers={"x-apikey": api_key},
        timeout=15,
    )
    response.raise_for_status()
    payload = response.json().get("data", {}).get("attributes", {})
    stats = payload.get("last_analysis_stats", {})
    return {"malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)), "harmless": int(stats.get("harmless", 0)), "undetected": int(stats.get("undetected", 0)), "reputation": payload.get("reputation", 0), "country": payload.get("country", ""), "as_owner": payload.get("as_owner", ""), "type_description": payload.get("type_description", "")}


def show_virustotal_result(result, indicator):
    malicious = result["malicious"]
    suspicious = result["suspicious"]
    columns = st.columns(4)
    columns[0].metric("Malicious", malicious)
    columns[1].metric("Suspicious", suspicious)
    columns[2].metric("Harmless", result["harmless"])
    columns[3].metric("Undetected", result["undetected"])
    st.caption(f"VirusTotal reputation for {indicator}. Reputation results are third-party signals and need analyst review.")
    if malicious or suspicious:
        severity = "Critical" if malicious >= 5 else "High"
        st.error("Reputation engines reported suspicious activity.")
        add_alert("Threat-intelligence IOC reputation match", severity, f"Indicator: {indicator}\nMalicious detections: {malicious}\nSuspicious detections: {suspicious}\nSource: VirusTotal reputation API")
    else:
        st.success("No malicious or suspicious detections were returned. This does not prove the indicator is safe.")


def render_analytics(report):
    render_page_heading("Analytics Dashboard")
    try:
        events, source = load_sensor_events(limit=5000)
    except Exception as error:
        events, source = pd.DataFrame(), "unavailable"
        st.warning(f"Live event analytics unavailable: {error}")
    alerts = load_alerts()
    critical_alerts = int(alerts["severity"].eq("Critical").sum()) if not alerts.empty else 0
    anomaly_alerts = int(alerts["title"].astype(str).str.startswith("AI anomaly:").sum()) if not alerts.empty else 0
    a, b, c, d = st.columns(4)
    a.metric("Endpoint events", len(events))
    b.metric("AI anomaly alerts", anomaly_alerts)
    c.metric("Critical alerts", critical_alerts)
    d.metric("Open alerts", int(alerts["status"].eq("Open").sum()) if not alerts.empty else 0)
    st.caption(f"Live source: {source} · Recent data window: up to 5,000 events")

    if not events.empty:
        time_col = "occurred_at" if "occurred_at" in events else "created_at"
        if time_col in events:
            timeline = events.copy()
            timeline["Day"] = pd.to_datetime(timeline[time_col], errors="coerce", utc=True).dt.strftime("%Y-%m-%d")
            timeline = timeline.dropna(subset=["Day"])
            if not timeline.empty:
                st.subheader("Daily endpoint activity by severity")
                if "severity" in timeline:
                    daily = timeline.groupby(["Day", "severity"]).size().unstack(fill_value=0)
                    st.bar_chart(daily)
                else:
                    st.bar_chart(timeline.groupby("Day").size())
        if "severity" in events:
            left, right = st.columns(2)
            with left:
                st.subheader("Event severity distribution")
                st.bar_chart(events["severity"].astype(str).value_counts().reindex(["Info", "Review", "High", "Critical"], fill_value=0), color="#CEDE62")
            with right:
                st.subheader("Event types")
                if "event_type" in events:
                    st.bar_chart(events["event_type"].astype(str).value_counts().head(10), color="#8A852B")
    else:
        st.info("No endpoint events are available to chart yet.")
    if not report.empty:
        with st.expander("Offline dataset analytics"):
            left, right = st.columns(2)
            if "risk_level" in report:
                left.bar_chart(report["risk_level"].astype(str).value_counts(), color="#CEDE62")
            if "predicted_category" in report:
                right.bar_chart(report["predicted_category"].value_counts().head(10), color="#8A852B")
            if "risk_score" in report:
                st.write(report["risk_score"].describe())


def live_event_features(events):
    """Build numeric, metadata-only features for the rolling endpoint model."""
    frame = pd.DataFrame(index=events.index)
    risk = pd.to_numeric(events.get("risk_score", pd.Series(0, index=events.index)), errors="coerce")
    frame["sensor_risk"] = risk.fillna(0).clip(0, 100)

    severity = events.get("severity", pd.Series("Info", index=events.index))
    frame["severity_level"] = severity.astype(str).str.lower().map(
        {"info": 0, "review": 1, "high": 2, "critical": 3}
    ).fillna(0)

    event_type = events.get("event_type", pd.Series("unknown", index=events.index)).astype(str).str.lower()
    frame["is_file_event"] = event_type.str.startswith("file_").astype(int)
    frame["is_process_event"] = event_type.str.startswith("process_").astype(int)
    frame["is_network_event"] = event_type.str.contains("connection|network", regex=True).astype(int)

    process = events.get("process_name", pd.Series("", index=events.index)).fillna("").astype(str).str.lower()
    process_counts = process[process.ne("")].value_counts()
    frame["process_frequency"] = process.map(process_counts).fillna(0).clip(0, 50)

    remote_ip = events.get("remote_ip", pd.Series("", index=events.index)).fillna("").astype(str)
    frame["has_remote_ip"] = remote_ip.ne("").astype(int)
    remote_port = pd.to_numeric(events.get("remote_port", pd.Series(0, index=events.index)), errors="coerce").fillna(0)
    frame["uncommon_remote_port"] = (remote_port.ne(0) & ~remote_port.isin([53, 80, 123, 443, 8080])).astype(int)
    summary = events.get("summary", pd.Series("", index=events.index)).fillna("").astype(str).str.lower()
    details = events.get("details", pd.Series("", index=events.index)).fillna("").astype(str).str.lower()
    frame["ioc_match"] = (summary.str.contains("threat-feed match", regex=False) | details.str.contains("threat-feed match", regex=False)).astype(int)
    frame["has_file_hash"] = events.get("file_sha256", pd.Series("", index=events.index)).fillna("").astype(str).str.len().gt(0).astype(int)
    return frame.astype(float)


@st.cache_data(ttl=30, show_spinner=False)
def analyze_live_events(events, model_minimum=20):
    events = events.copy()
    features = live_event_features(events)
    if len(events) >= model_minimum:
        model = IsolationForest(n_estimators=40, contamination="auto", random_state=42, n_jobs=1)
        predictions = model.fit_predict(features)
        decision = model.decision_function(features)
        events["AI anomaly"] = predictions == -1
        events["AI anomaly score"] = (pd.Series(-decision, index=events.index).rank(pct=True) * 100).round().astype(int)
        model_label = "Isolation Forest · rolling endpoint baseline"
    else:
        events["AI anomaly"] = False
        events["AI anomaly score"] = 0
        model_label = f"Collecting baseline · {len(events)}/{model_minimum} events"

    if "summary" not in events:
        events["summary"] = ""
    ioc_match = events["summary"].fillna("").astype(str).str.lower().str.contains("threat-feed match", regex=False)
    if "details" in events:
        ioc_match = ioc_match | events["details"].fillna("").astype(str).str.lower().str.contains("threat-feed match", regex=False)
    events["Threat-intel IOC"] = ioc_match

    sensor_risk = pd.to_numeric(events.get("risk_score", pd.Series(0, index=events.index)), errors="coerce").fillna(0).clip(0, 100)
    events["Model risk contribution"] = (60 + events["AI anomaly score"] * 0.2).where(events["AI anomaly"], 0).round().astype(int)
    ai_risk = pd.concat([sensor_risk.rename("sensor"), events["Model risk contribution"].rename("model")], axis=1).max(axis=1)
    severity_text = events.get("severity", pd.Series("Info", index=events.index)).fillna("Info").astype(str).str.lower()
    ai_risk = ai_risk.where(~severity_text.isin(["review"]), ai_risk.clip(lower=55))
    ai_risk = ai_risk.where(~severity_text.isin(["high"]), ai_risk.clip(lower=80))
    ai_risk = ai_risk.where(~severity_text.isin(["critical"]), ai_risk.clip(lower=95))
    ai_risk = ai_risk.where(~events["Threat-intel IOC"], ai_risk.clip(lower=95)).round().astype(int)
    events["AI risk score"] = ai_risk
    events["AI severity"] = pd.cut(ai_risk, bins=[-1, 24, 49, 79, 100], labels=["Low", "Medium", "High", "Critical"]).astype(str)

    port_flag = features["uncommon_remote_port"].gt(0)
    process_name = events.get("process_name", pd.Series("", index=events.index)).fillna("").astype(str)
    process_rare = features["process_frequency"].le(1) & process_name.ne("")
    reasons = []
    for index in events.index:
        signals = []
        if bool(events.at[index, "Threat-intel IOC"]):
            signals.append("Threat-feed IOC match")
        if sensor_risk.at[index] >= 60:
            signals.append("High sensor risk")
        if severity_text.at[index] in {"review", "high", "critical"}:
            signals.append(f"Sensor severity: {severity_text.at[index].title()}")
        if bool(port_flag.at[index]):
            signals.append("Uncommon remote port")
        if bool(process_rare.at[index]):
            signals.append("Process is rare in this event window")
        if bool(events.at[index, "AI anomaly"]):
            signals.append("ML model marked this event as an outlier")
        reasons.append("; ".join(signals) if signals else "No elevated signal in current metadata")
    events["AI indicators"] = reasons
    return events, model_label


def render_live_ai_panel(show_assistant=False):
    """Refresh endpoint events and run a cached rolling Isolation Forest."""
    try:
        events, source = load_sensor_events(limit=500)
    except Exception as error:
        st.error(f"Live endpoint events could not be loaded: {error}")
        return

    if events.empty:
        st.warning("No endpoint events are available yet. Start the endpoint sensor and create normal activity to build a live baseline.")
        return

    model_minimum = 20
    events, model_label = analyze_live_events(events, model_minimum)

    occurred_col = "occurred_at" if "occurred_at" in events else "created_at"
    latest = "Unavailable"
    if occurred_col in events and events[occurred_col].notna().any():
        latest = str(events[occurred_col].dropna().astype(str).max())
    st.caption(f"Source: {source} endpoint sensor · Updated {datetime.now().astimezone().strftime('%H:%M:%S')} · Latest event: {latest}")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events in rolling window", len(events))
    c2.metric("AI anomalies", int(events["AI anomaly"].sum()))
    c3.metric("Threat-feed IOC matches", int(events["Threat-intel IOC"].sum()))
    c4.metric("Highest AI risk", f"{events['AI risk score'].max():.0f}/100")
    st.caption(f"Live model: {model_label}. The anomaly score is a relative ranking within this window, not a malware probability or verdict.")

    display_columns = [column for column in [occurred_col, "event_type", "AI severity", "AI risk score", "AI anomaly", "AI anomaly score", "AI indicators", "process_name", "remote_ip", "summary"] if column in events]
    st.dataframe(events[display_columns].head(50), hide_index=True, width="stretch")
    anomalies = events[events["AI anomaly"]]
    if not anomalies.empty:
        if st.button("Create review alerts for AI anomalies", key="create_ai_anomaly_alerts"):
            inserted = create_ai_anomaly_alerts(anomalies)
            st.success(f"Created {inserted} new alert(s). Existing alerts were skipped.")
    if show_assistant:
        st.subheader("Explainable AI Assistant")
        event_options = {}
        for position, (index, row) in enumerate(events.head(100).iterrows(), start=1):
            identity = row.get("event_id")
            if identity is None or pd.isna(identity) or not str(identity).strip():
                identity = row.get("event_uid")
            if identity is None or pd.isna(identity) or not str(identity).strip():
                identity = row.get("id", position)
            if identity is None or pd.isna(identity):
                identity = position
            label = f"{identity} · {row.get('AI severity', 'Unknown')} · {str(row.get('summary', row.get('event_type', 'Endpoint event')))[:90]}"
            event_options[label] = index
        selected_label = st.selectbox("Select an event to explain", list(event_options), key="explainable_ai_event")
        selected = events.loc[event_options[selected_label]]
        left, right = st.columns([1, 2])
        with left:
            st.metric("Risk score", f"{int(selected['AI risk score'])}/100", str(selected["AI severity"]))
            st.caption("This score prioritizes review; it is not a probability of compromise.")
        with right:
            st.markdown("**Why it was scored this way**")
            st.write(f"Sensor risk: {selected.get('risk_score', 0)} · Model risk contribution: {selected.get('Model risk contribution', 0)} · Rolling-model relative outlier rank: {selected.get('AI anomaly score', 0)} · Threat-feed match: {'yes' if selected['Threat-intel IOC'] else 'no'}")
            factors = [part.strip() for part in str(selected["AI indicators"]).split(";") if part.strip()]
            if factors:
                for factor in factors:
                    st.markdown(f"- {factor}")
            else:
                st.write("No elevated metadata signal was recorded for this event.")
        event_type = str(selected.get("event_type", "")).lower()
        if event_type.startswith("network"):
            next_steps = "Review the remote IP and port in IOC Analysis, then verify whether the named process is expected to contact that destination."
        elif event_type.startswith("file_"):
            next_steps = "Check the file hash with an authorized reputation source and verify the file's origin. The sensor does not upload or execute file contents."
        elif event_type.startswith("process_") or event_type == "application_installed":
            next_steps = "Verify the process or application publisher and installation path with the device owner; a user-writable path alone is not proof of malware."
        else:
            next_steps = "Compare related events and timestamps, then document the analyst's conclusion in Incident Management."
        st.info("**Suggested investigation:** " + next_steps)
    if len(events) < model_minimum:
        st.info("The live ML model starts after 20 endpoint events. Until then, the table shows sensor detections and IOC matches without inventing AI results.")


def create_ai_anomaly_alerts(events):
    """Promote model outliers into deduplicated analyst-review alerts."""
    if events is None or events.empty:
        return 0
    inserted = 0
    notifications = []
    audit_rows = []
    with connect_db() as connection:
        for event in events.to_dict("records"):
            event_id = str(event.get("event_id") or event.get("event_uid") or event.get("id") or "").strip()
            if not event_id:
                continue
            score = int(event.get("AI risk score", event.get("AI anomaly score", 0)) or 0)
            sensor_severity = str(event.get("severity") or "").title()
            severity = str(event.get("AI severity") or ("Critical" if sensor_severity == "Critical" else "High" if score >= 70 or sensor_severity == "High" else "Medium"))
            summary = str(event.get("summary") or event.get("event_type") or "Endpoint anomaly")
            details = "\n".join([
                "Source: live endpoint metadata anomaly model",
                f"Combined AI risk score: {score}/100",
                f"Sensor severity: {sensor_severity or 'Unknown'}",
                f"AI indicators: {event.get('AI indicators', 'Review event metadata')}",
                f"Event: {summary}",
                "Analyst review is required; an anomaly score is not a malware verdict.",
            ])
            candidates = map_signal_to_mitre(f"{summary} {details}")
            mitre_id = candidates[0]["Technique ID"] if candidates else ""
            cursor = connection.execute(
                """INSERT OR IGNORE INTO alerts
                   (created_at, title, severity, details, mitre_id, source_event_id, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'Open')""",
                (
                    str(event.get("occurred_at") or event.get("created_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")),
                    f"AI anomaly: {summary[:120]}",
                    severity,
                    details,
                    mitre_id,
                    f"ai-endpoint:{event_id}",
                ),
            )
            inserted += max(cursor.rowcount, 0)
            if cursor.rowcount > 0:
                notifications.append((severity, f"AI anomaly: {summary[:120]}"))
                audit_rows.append(f"severity={severity}; event_id={event_id}; score={score}")
    for detail in audit_rows:
        audit_event("ai_anomaly_alert_created", detail)
    for severity, title in notifications:
        notify_security_alert(severity, title)
    return inserted


def render_ai_engine(report):
    render_page_heading("AI Engine")
    st.write("Live AI analysis of endpoint sensor metadata, refreshed automatically every 5 seconds.")

    @st.fragment(run_every="5s")
    def live_panel():
        render_live_ai_panel()

    live_panel()
    with st.expander("Historical UNSW-NB15 model output"):
        st.write("This is a separate offline dataset report. It is not used to label live files or endpoint activity.")
        if report.empty:
            st.info("No historical threat_report.csv is available.")
        else:
            st.write(f"Historical report rows: {len(report)}")
            st.dataframe(report.head(10), hide_index=True, width="stretch")


def render_explainable_ai_assistant():
    render_page_heading("Explainable AI Assistant")
    st.write("Select a live endpoint event to see the exact signals behind its risk score and suggested analyst checks.")
    st.caption("This assistant explains the sensor and model evidence available in the event; it does not invent conclusions or label the score as a probability.")

    @st.fragment(run_every="10s")
    def assistant_panel():
        render_live_ai_panel(show_assistant=True)

    assistant_panel()


@st.cache_data(show_spinner=False)
def read_evaluation_csv(payload):
    return pd.read_csv(BytesIO(payload))


def stratified_cap(frame, target, row_limit):
    if len(frame) <= row_limit:
        return frame
    try:
        sample, _ = train_test_split(
            frame,
            train_size=row_limit,
            random_state=42,
            stratify=frame[target].astype(str),
        )
        return sample
    except ValueError:
        return frame.sample(n=row_limit, random_state=42)


def evaluate_dataset(train_frame, test_frame, target, row_limit):
    train_frame = train_frame.dropna(subset=[target]).copy()
    test_frame = test_frame.dropna(subset=[target]).copy()
    if target == "attack_cat":
        if "label" in train_frame:
            label_values = train_frame["label"].astype(str).str.lower()
            numeric_labels = pd.to_numeric(train_frame["label"], errors="coerce")
            train_frame = train_frame[numeric_labels.eq(1) | label_values.isin(["attack"])]
        if "label" in test_frame:
            label_values = test_frame["label"].astype(str).str.lower()
            numeric_labels = pd.to_numeric(test_frame["label"], errors="coerce")
            test_frame = test_frame[numeric_labels.eq(1) | label_values.isin(["attack"])]
    train_frame = stratified_cap(train_frame, target, row_limit)
    test_frame = stratified_cap(test_frame, target, row_limit)
    excluded = {target, "id"}
    if target == "label":
        excluded.add("attack_cat")
    elif target == "attack_cat":
        excluded.add("label")
    feature_columns = [column for column in train_frame.columns if column not in excluded and column in test_frame.columns]
    if not feature_columns:
        raise ValueError("No shared feature columns were found after removing target and identifier columns.")
    x_train = train_frame[feature_columns]
    y_train = train_frame[target].astype(str)
    x_test = test_frame[feature_columns]
    y_test = test_frame[target].astype(str)
    categorical = x_train.select_dtypes(include=["object", "category", "bool"]).columns.tolist()
    numeric = [column for column in feature_columns if column not in categorical]
    transformers = []
    if categorical:
        transformers.append(("categorical", Pipeline([("imputer", SimpleImputer(strategy="most_frequent")), ("encoder", OneHotEncoder(handle_unknown="ignore"))]), categorical))
    if numeric:
        transformers.append(("numeric", SimpleImputer(strategy="median"), numeric))
    preprocessor = ColumnTransformer(transformers, remainder="drop")
    classifier = RandomForestClassifier(
        n_estimators=60,
        max_depth=16,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    pipeline = Pipeline([("features", preprocessor), ("model", classifier)])
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    labels = sorted(set(y_test) | set(predictions))
    report = pd.DataFrame(classification_report(y_test, predictions, labels=labels, output_dict=True, zero_division=0)).T
    matrix = pd.DataFrame(confusion_matrix(y_test, predictions, labels=labels), index=labels, columns=labels)
    names = pipeline.named_steps["features"].get_feature_names_out()
    importances = pipeline.named_steps["model"].feature_importances_
    top_features = pd.DataFrame({"Feature": names, "Importance": importances}).sort_values("Importance", ascending=False).head(15)
    return {
        "accuracy": accuracy_score(y_test, predictions),
        "balanced_accuracy": balanced_accuracy_score(y_test, predictions),
        "macro_f1": f1_score(y_test, predictions, average="macro", zero_division=0),
        "weighted_f1": f1_score(y_test, predictions, average="weighted", zero_division=0),
        "report": report,
        "confusion": matrix,
        "top_features": top_features,
        "train_rows": len(train_frame),
        "test_rows": len(test_frame),
        "classes": len(labels),
    }


def render_model_evaluation_lab():
    render_page_heading("AI Model Evaluation Lab")
    st.write("Train and evaluate a Random Forest on a labeled dataset using held-out test data.")
    st.caption("Evaluation runs only when you press Run evaluation. Uploaded dataset contents are processed in app memory and are not saved or sent to a threat-intelligence provider.")
    train_path = BASE_DIR / "Data" / "UNSW_NB15_training-set.csv"
    test_path = BASE_DIR / "Data" / "UNSW_NB15_testing-set.csv"
    has_bundled = train_path.exists() and test_path.exists()
    sources = (["Bundled UNSW-NB15", "Upload a labeled CSV"] if has_bundled else ["Upload a labeled CSV"])
    source = st.selectbox("Dataset", sources)
    uploaded = None
    if source == "Upload a labeled CSV":
        if os.environ.get("CTI_DESKTOP_MODE") != "1":
            st.warning("For data privacy, upload-based evaluation is available only in the local desktop app. The hosted dashboard can evaluate a dataset only when its data files are deployed with the app.")
            return
        uploaded = st.file_uploader("Upload labeled CSV (maximum 50 MB)", type=["csv"], key="evaluation_dataset_upload")
        if uploaded is None:
            st.info("CSV needs a target column such as `label` or `attack_cat`.")
            return
        payload = uploaded.getvalue()
        if len(payload) > 50 * 1024 * 1024:
            st.error("The dataset is larger than 50 MB.")
            return
        try:
            full = read_evaluation_csv(payload)
        except Exception as error:
            st.error(f"Could not read the CSV: {error}")
            return
        dataset_id = hashlib.sha256(payload).hexdigest()
        target_candidates = [column for column in ("label", "attack_cat") if column in full.columns]
        if not target_candidates:
            st.error("The CSV must include `label` or `attack_cat` as its target column.")
            return
        target = st.selectbox("Target to evaluate", target_candidates)
        full = full.dropna(subset=[target])
        try:
            train_frame, test_frame = train_test_split(
                full,
                test_size=0.25,
                random_state=42,
                stratify=full[target].astype(str) if full[target].value_counts().min() >= 2 else None,
            )
        except ValueError as error:
            st.error(f"Could not make a stratified train/test split: {error}")
            return
    else:
        train_payload = train_path.read_bytes()
        test_payload = test_path.read_bytes()
        dataset_id = hashlib.sha256(train_payload + test_payload).hexdigest()
        train_frame = read_evaluation_csv(train_payload)
        test_frame = read_evaluation_csv(test_payload)
        targets = [column for column in ("label", "attack_cat") if column in train_frame.columns and column in test_frame.columns]
        target = st.selectbox("Target to evaluate", targets)
    row_limit = st.slider("Maximum rows per split", 2000, 50000, 10000, step=2000)
    eval_key = f"{dataset_id}:{source}:{target}:{row_limit}"
    if st.button("Run evaluation", type="primary"):
        try:
            with st.spinner("Training and evaluating the model on the held-out split..."):
                result = evaluate_dataset(train_frame, test_frame, target, row_limit)
            st.session_state["model_evaluation_result"] = {"key": eval_key, "result": result}
            audit_event("model_evaluation_run", f"source={source}; target={target}; train_rows={result['train_rows']}; test_rows={result['test_rows']}")
        except Exception as error:
            st.error(f"Model evaluation failed: {error}")
            return
    stored = st.session_state.get("model_evaluation_result", {})
    if stored.get("key") != eval_key:
        st.info("Select a dataset and target, then run an evaluation to see measured results.")
        return
    result = stored["result"]
    st.caption(f"Measured on {result['test_rows']:,} held-out rows from {source}. Training rows: {result['train_rows']:,}; classes: {result['classes']}.")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Accuracy", f"{result['accuracy']:.1%}")
    c2.metric("Balanced accuracy", f"{result['balanced_accuracy']:.1%}")
    c3.metric("Macro F1", f"{result['macro_f1']:.3f}")
    c4.metric("Weighted F1", f"{result['weighted_f1']:.3f}")
    left, right = st.columns(2)
    with left:
        st.subheader("Per-class evaluation")
        st.dataframe(result["report"].round(3), width="stretch")
    with right:
        st.subheader("Confusion matrix")
        st.dataframe(result["confusion"], width="stretch")
    st.subheader("Most influential features")
    st.bar_chart(result["top_features"].set_index("Feature"), color="#CEDE62")
    metrics_export = pd.DataFrame([
        {"Metric": "Accuracy", "Value": result["accuracy"]},
        {"Metric": "Balanced accuracy", "Value": result["balanced_accuracy"]},
        {"Metric": "Macro F1", "Value": result["macro_f1"]},
        {"Metric": "Weighted F1", "Value": result["weighted_f1"]},
        {"Metric": "Train rows", "Value": result["train_rows"]},
        {"Metric": "Test rows", "Value": result["test_rows"]},
    ])
    if st.download_button("Download evaluation metrics CSV", metrics_export.to_csv(index=False).encode("utf-8-sig"), "model_evaluation_metrics.csv", "text/csv"):
        audit_event("model_evaluation_exported", f"source={source}; target={target}")
    st.caption("Feature importance shows model influence, not causality. Results are specific to this dataset and split; they do not represent live endpoint detection accuracy.")


def render_mitre_map():
    render_page_heading("MITRE ATT&CK Map")
    st.write("Candidate ATT&CK techniques are mapped from observed event text and sensor signals for analyst review.")
    st.caption("These are possible technique associations, not proof of attacker behavior.")
    try:
        events, source = load_sensor_events(limit=2000)
    except Exception as error:
        events, source = pd.DataFrame(), "unavailable"
        st.warning(f"Could not load live events: {error}")
    alerts = load_alerts()
    mapped = []
    for record in events.to_dict("records") if not events.empty else []:
        signal = " ".join(str(record.get(key, "")) for key in ("event_type", "summary", "details"))
        for technique in map_signal_to_mitre(signal):
            mapped.append({"Time": record.get("occurred_at", record.get("created_at", "")), "Source": "Endpoint event", "Observed signal": str(record.get("summary", record.get("event_type", "")))[:180], **technique})
    for record in alerts.to_dict("records") if not alerts.empty else []:
        signal = " ".join(str(record.get(key, "")) for key in ("title", "details"))
        for technique in map_signal_to_mitre(signal):
            mapped.append({"Time": record.get("created_at", ""), "Source": "Alert", "Observed signal": str(record.get("title", ""))[:180], **technique})
    report = load_report()
    if not report.empty and "predicted_category" in report:
        for category, count in report["predicted_category"].astype(str).value_counts().items():
            for technique in map_signal_to_mitre(category):
                mapped.append({"Time": "Historical dataset", "Source": "UNSW-NB15 report", "Observed signal": f"{category} · {count} records", **technique})
    st.caption(f"Live event source: {source}")
    if mapped:
        mapping = pd.DataFrame(mapped).drop_duplicates(subset=["Source", "Observed signal", "Technique ID"])
        st.dataframe(mapping, hide_index=True, width="stretch", column_config={"Reference": st.column_config.LinkColumn("ATT&CK reference")})
    else:
        st.info("No current signals matched the configured ATT&CK mapping rules.")


def map_signal_to_mitre(signal):
    text = str(signal).lower()
    rules = [
        (r"threat-feed match|command.?and.?control|\bc2\b", "T1071", "Application Layer Protocol", "Observed destination matched a command-and-control threat feed; protocol behavior is not confirmed.", "https://attack.mitre.org/techniques/T1071/"),
        (r"failed authentication|failed login|invalid user|logon failure|event\s*id\s*:?\s*4625|repeated failed", "T1110.001", "Password Guessing", "Authentication failures or repeated attempts were present in the observed log text.", "https://attack.mitre.org/techniques/T1110/001/"),
        (r"powershell|encodedcommand|downloadstring|frombase64string", "T1059.001", "PowerShell", "PowerShell or encoded/script-download indicators appeared in the event text.", "https://attack.mitre.org/techniques/T1059/001/"),
        (r"high packet.?rate|packet.?rate signal|denial.of.service|\bdos\b", "T1498.001", "Direct Network Flood", "A packet-rate or denial-of-service-like signal was recorded.", "https://attack.mitre.org/techniques/T1498/001/"),
        (r"destination.?port diversity|port scan|unique destination ports|network service discovery", "T1046", "Network Service Discovery", "Many destination ports or an explicit port-scan signal was observed.", "https://attack.mitre.org/techniques/T1046/"),
        (r"reconnaissance|active scanning|vulnerability scanning", "T1595", "Active Scanning", "Reconnaissance or scanning was predicted or reported by the source signal.", "https://attack.mitre.org/techniques/T1595/"),
        (r"suspicious file|malicious file|user-writable folder|credential dump|mimikatz", "T1204.002", "Malicious File", "File or process context warrants checking for user execution; location or keyword alone is inconclusive.", "https://attack.mitre.org/techniques/T1204/002/"),
    ]
    matches = []
    for pattern, technique_id, technique, rationale, reference in rules:
        if re.search(pattern, text, flags=re.I):
            matches.append({"Technique ID": technique_id, "Technique": technique, "Mapping rationale": rationale, "Confidence": "Possible", "Reference": reference})
    return matches


def render_local_email_settings():
    """Let the local desktop app configure SMTP without editing a file by hand."""
    if os.environ.get("CTI_DESKTOP_MODE") != "1":
        return
    with st.expander("Configure desktop email alerts", expanded=False):
        st.caption("Settings stay on this computer and are not uploaded. The SMTP password is stored in a local, Git-ignored settings file; use an email app password where your provider supports it.")
        with st.form("local_email_settings_form"):
            threshold_options = ["Critical", "High", "Medium", "Low"]
            current_threshold = setting("ALERT_NOTIFY_MINIMUM", "High").title()
            threshold_index = threshold_options.index(current_threshold) if current_threshold in threshold_options else 1
            st.selectbox("Minimum alert severity", threshold_options, index=threshold_index, key="local_email_threshold")
            host = st.text_input("SMTP host", value=setting("SMTP_HOST", "smtp.gmail.com"), placeholder="smtp.your-provider.com")
            port = st.text_input("SMTP port", value=setting("SMTP_PORT", "587"))
            username = st.text_input("SMTP username", value=setting("SMTP_USERNAME"))
            saved_password = bool(setting("SMTP_PASSWORD"))
            password = st.text_input("SMTP password or app password", type="password", help="Leave blank to keep the saved password." if saved_password else "Enter the password or app password for your SMTP account.")
            if saved_password:
                st.caption("A password is already saved locally; leave the password field blank to keep it.")
            sender = st.text_input("From email", value=setting("SMTP_FROM", setting("SMTP_USERNAME")))
            recipient = st.text_input("Alert recipient email", value=setting("ALERT_EMAIL_TO"))
            starttls = st.checkbox("Use STARTTLS (usually port 587)", value=setting("SMTP_USE_STARTTLS", "true").lower() in {"1", "true", "yes"})
            use_ssl = st.checkbox("Use SSL (usually port 465)", value=setting("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"})
            st.caption("Gmail is prefilled. Create a Google App Password and enter it above; your regular Gmail password will not work. The app password is stored locally on this computer and never uploaded. Gmail → smtp.gmail.com, port 587, STARTTLS.")
            submitted = st.form_submit_button("Save local email settings")
        if submitted:
            try:
                port_number = int(port.strip())
                if not 1 <= port_number <= 65535:
                    raise ValueError("SMTP port must be between 1 and 65535.")
                if not all((host.strip(), sender.strip(), recipient.strip())):
                    raise ValueError("Enter an SMTP host, sender address, and recipient address.")
                effective_password = password or setting("SMTP_PASSWORD")
                if bool(username.strip()) != bool(effective_password):
                    raise ValueError("Enter both SMTP username and password, or leave both blank if the server does not require sign-in.")
                save_local_email_settings({
                    "EMAIL_ALERTS_ENABLED": "false",
                    "ALERT_NOTIFY_MINIMUM": st.session_state.get("local_email_threshold", "High"),
                    "SMTP_HOST": host.strip(),
                    "SMTP_PORT": str(port_number),
                    "SMTP_USERNAME": username.strip(),
                    "SMTP_PASSWORD": effective_password,
                    "SMTP_FROM": sender.strip(),
                    "ALERT_EMAIL_TO": recipient.strip(),
                    "SMTP_USE_STARTTLS": "true" if starttls else "false",
                    "SMTP_USE_SSL": "true" if use_ssl else "false",
                })
                audit_event("local_email_settings_saved", "SMTP configuration updated on this computer")
                st.success("SMTP settings saved locally. Use the Email notifications switch above when you want alerts.")
                st.rerun()
            except (OSError, ValueError, RuntimeError) as error:
                st.error(f"Could not save local email settings: {error}")


@st.fragment(run_every="5s")
def render_alert_system():
    render_page_heading("Alert System")
    severity_levels = ["Critical", "High", "Medium", "Low"]
    configured_threshold = setting("ALERT_NOTIFY_MINIMUM", "High").title()
    default_index = severity_levels.index(configured_threshold) if configured_threshold in severity_levels else 1
    notification_minimum = st.selectbox("Notification threshold (in-app and email)", severity_levels, index=default_index, key="alert_notification_threshold")
    render_local_email_settings()
    email_provider = setting("EMAIL_PROVIDER", "smtp").strip().lower()
    sender_setting = setting("RESEND_FROM", setting("SMTP_FROM")) if email_provider == "resend" else setting("SMTP_FROM")
    sender_address = parseaddr(sender_setting)[1]
    recipient_address = parseaddr(setting("ALERT_EMAIL_TO"))[1]
    sender_valid = "@" in sender_address and "." in sender_address.rsplit("@", 1)[-1]
    recipient_valid = "@" in recipient_address and "." in recipient_address.rsplit("@", 1)[-1]
    provider_ready = (
        bool(setting("RESEND_API_KEY")) if email_provider == "resend" else bool(setting("SMTP_HOST"))
    ) and sender_valid and recipient_valid
    configured_for_email = provider_ready
    email_enabled = st.toggle(
        "Email notifications",
        key="email_alerts_enabled_this_session",
        disabled=not configured_for_email,
        help="This switch resets to OFF whenever you restart the app or sign in again.",
    )
    if configured_for_email:
        st.caption("Email notifications start OFF each session. Turn this on only when you want email alerts; restart or sign out to switch them off.")
    else:
        st.caption("Configure the selected email provider first. For Streamlit Cloud, Gmail SMTP may be blocked; use EMAIL_PROVIDER='resend' with a Resend API key. Email remains OFF by default.")
    if email_enabled and configured_for_email:
        st.success(f"Email notifications are enabled for alerts at or above {notification_minimum} severity.")
        if st.button("Send test email"):
            try:
                recipient = send_security_email(
                    "AI Cyber Threat Intelligence — test notification",
                    "This is a test email. SMTP is configured and email notifications are ready.",
                )
                audit_event("email_alert_test_sent", f"recipient={recipient}")
                st.success(f"Test email sent to {recipient}.")
            except Exception as error:
                audit_event("email_alert_test_failed", str(error)[:300])
                st.error(f"Test email failed: {error}")
                if isinstance(error, (ConnectionError, OSError, TimeoutError, ssl.SSLError)):
                    try:
                        with socket.create_connection((setting("SMTP_HOST"), int(setting("SMTP_PORT", "587"))), timeout=4):
                            st.caption("Network check: the SMTP port accepts a TCP connection; failure is occurring during SMTP/TLS negotiation or authentication.")
                    except (OSError, ValueError) as network_error:
                        st.caption(f"Network check: this environment cannot reach the configured SMTP host and port ({type(network_error).__name__}). This is usually a firewall or hosting-network restriction.")
    else:
        if os.environ.get("CTI_DESKTOP_MODE") == "1":
            st.info("Desktop email alerts are off. Open **Configure desktop email alerts** above and save your SMTP settings.")
        else:
            st.info("Email notifications are off. Enable EMAIL_ALERTS_ENABLED and configure SMTP in your app's private Secrets, then restart/redeploy the app.")
    st.caption("Every new alert at or above the selected level triggers an in-app notification and, when configured, an email. Repeated records are deduplicated by the alert engine.")
    try:
        endpoint_events, _ = load_sensor_events(limit=1000)
        new_alerts = sync_endpoint_alerts(endpoint_events)
        if len(endpoint_events) >= 20:
            analyzed_events, _ = analyze_live_events(endpoint_events)
            ai_anomalies = analyzed_events[analyzed_events["AI anomaly"]]
            new_alerts += create_ai_anomaly_alerts(ai_anomalies)
        if new_alerts:
            st.success(f"Added {new_alerts} new endpoint/AI review alert(s).")
    except Exception as error:
        st.warning(f"Could not check live endpoint events: {error}")

    alerts = hide_cleared_notifications(load_alerts())
    cleared_message = st.session_state.pop("notifications_cleared_message", None)
    if cleared_message:
        st.success(cleared_message)
    if alerts.empty:
        st.info(
            "No alerts have been recorded. Endpoint events marked Review, High, or Critical "
            "are added here automatically when this page is opened."
        )
        return

    active_count = int(alerts["status"].isin(["Open", "Acknowledged"]).sum())
    if st.button("Clear all notifications", disabled=active_count == 0, type="secondary"):
        cleared_count = clear_all_notifications()
        st.session_state["notifications_cleared_message"] = (
            f"Cleared {cleared_count} notification(s). New alerts will still appear."
        )
        st.rerun()

    severity_order = ["Critical", "High", "Medium", "Low"]
    chosen_severities = st.multiselect("Filter severity", severity_order, default=severity_order)
    chosen_statuses = st.multiselect(
        "Filter status",
        ["Open", "Acknowledged", "Closed", "Resolved"],
        default=["Open", "Acknowledged"],
        key="alert_status_filter",
    )
    visible = alerts[alerts["severity"].isin(chosen_severities) & alerts["status"].isin(chosen_statuses)]
    st.dataframe(visible, hide_index=True, width="stretch")
    if visible.empty:
        st.info("No alerts match these filters.")
        return
    alert_options = {f"#{row.id} · {row.severity} · {row.title[:90]}": int(row.id) for row in visible.itertuples()}
    selected_label = st.selectbox("Alert to update", list(alert_options))
    selected_id = alert_options[selected_label]
    new_status = st.selectbox("New alert status", ["Open", "Acknowledged", "Resolved", "Closed"])
    if st.button("Save alert status"):
        with connect_db() as connection:
            connection.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (new_status, int(selected_id)),
            )
        audit_event("alert_status_changed", f"alert_id={selected_id}; status={new_status}")
        st.success("Alert status updated.")
        st.rerun()


def render_incident_management():
    render_page_heading("Incident Management")
    open_alerts = load_alerts()
    if not open_alerts.empty:
        candidates = open_alerts[open_alerts["status"].isin(["Open", "Acknowledged"])]
        if not candidates.empty:
            alert_labels = {f"#{row.id} · {row.severity} · {row.title[:90]}": row for row in candidates.itertuples()}
            selected_related = st.multiselect("Group related alerts into an incident", list(alert_labels))
            if st.button("Create incident from selected alerts", disabled=not selected_related):
                selected_rows = [alert_labels[label] for label in selected_related]
                ranks = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
                severity = max((row.severity for row in selected_rows), key=lambda item: ranks.get(item, 0))
                notes = "Related alert IDs: " + ", ".join(str(row.id) for row in selected_rows) + "\n\n" + "\n".join(f"[{row.severity}] {row.title}" for row in selected_rows)
                add_incident(f"Grouped investigation ({len(selected_rows)} alerts)", severity, notes)
                audit_event("incident_created_from_alerts", f"alert_ids={','.join(str(row.id) for row in selected_rows)}")
                st.success("Incident created with the selected alerts linked in its notes.")
                st.rerun()
    with st.form("new_incident_form"):
        title = st.text_input("Incident title")
        severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
        notes = st.text_area("What happened / analyst notes")
        submitted = st.form_submit_button("Create incident")

    if submitted:
        if not title.strip():
            st.error("Enter an incident title.")
        else:
            add_incident(title.strip(), severity, notes.strip())
            audit_event("incident_created", f"severity={severity}; title={title.strip()[:120]}")
            st.success("Incident saved.")
            st.rerun()

    incidents = load_incidents()
    st.subheader("Incident register")
    if incidents.empty:
        st.info("No incidents have been recorded.")
        return

    st.dataframe(incidents, hide_index=True, width="stretch")
    incident_ids = incidents["id"].astype(int).tolist()
    selected_id = st.selectbox("Incident to update", incident_ids)
    status = st.selectbox(
        "Incident status",
        ["Open", "Investigating", "Contained", "Resolved"],
    )
    if st.button("Update incident status"):
        with connect_db() as connection:
            connection.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (status, int(selected_id)),
            )
        audit_event("incident_status_changed", f"incident_id={selected_id}; status={status}")
        st.success("Incident status updated.")
        st.rerun()


def analyze_log_text(contents):
    """Extract security-relevant log lines locally without storing the source log."""
    ip_pattern = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    failed_pattern = re.compile(r"failed password|failed login|authentication failure|invalid user|logon failure|event\s*id\s*[:=]?\s*4625", re.I)
    suspicious_pattern = re.compile(r"encodedcommand|(?:^|\s)-enc(?:odedcommand)?\b|downloadstring|invoke-webrequest|frombase64string|mimikatz|lsass|credential dump", re.I)
    malware_pattern = re.compile(r"malware|trojan|ransomware|quarantin|virus detected", re.I)
    detections = []
    failed_counts = {}
    for line_number, line in enumerate(contents.splitlines(), start=1):
        failed = bool(failed_pattern.search(line))
        suspicious_match = suspicious_pattern.search(line)
        if failed:
            ips = ip_pattern.findall(line)
            key = ips[0] if ips else "unknown source"
            failed_counts[key] = failed_counts.get(key, 0) + 1
        if failed or suspicious_match or malware_pattern.search(line):
            reasons = []
            severity = "Medium"
            if failed:
                reasons.append("Failed authentication pattern")
            if suspicious_match:
                reasons.append(f"Suspicious script or credential-access keyword: {suspicious_match.group(0)}")
                severity = "High"
            if malware_pattern.search(line):
                reasons.append("Malware or quarantine keyword")
                severity = "High"
            ips = ip_pattern.findall(line)
            source_ip = ""
            for candidate in ips:
                try:
                    source_ip = str(ipaddress.ip_address(candidate))
                    break
                except ValueError:
                    continue
            detections.append({"line_number": line_number, "severity": severity, "reason": "; ".join(reasons), "source_ip": source_ip, "log_excerpt": line.strip()[:240]})
    for source, count in failed_counts.items():
        if count >= 5:
            detections.append({"line_number": "multiple", "severity": "High", "reason": f"Repeated failed authentication: {count} attempts from {source}", "source_ip": source if source != "unknown source" else "", "log_excerpt": "Correlated across uploaded log lines"})
    return pd.DataFrame(detections)


def render_log_analyzer():
    render_page_heading("Log Analyzer")
    st.write("Scan an authorized text or CSV log for failed sign-ins and suspicious activity patterns.")
    if os.environ.get("CTI_DESKTOP_MODE") != "1":
        st.warning("For privacy, log uploads are enabled only in the local desktop app. Uploaded log text is not sent to the cloud or saved as a file.")
        return
    upload = st.file_uploader("Choose a log file", type=["log", "txt", "csv"])
    if upload is None:
        st.info("Supported input: up to 5 MB of plain-text logs. No file is executed.")
        return
    content = upload.getvalue()
    if len(content) > 5 * 1024 * 1024:
        st.error("The selected log exceeds the 5 MB limit.")
        return
    text = content.decode("utf-8", errors="replace")
    findings = analyze_log_text(text)
    content_id = hashlib.sha256(content).hexdigest()
    if st.session_state.get("last_audited_log_hash") != content_id:
        audit_event("log_analyzed", f"filename={Path(upload.name).name}; bytes={len(content)}; findings={len(findings)}")
        st.session_state["last_audited_log_hash"] = content_id
    if findings.empty:
        st.success("No configured log patterns were found.")
        return
    st.metric("Findings", len(findings))
    st.dataframe(findings.drop(columns=["log_excerpt"]), hide_index=True, width="stretch")
    with st.expander("Review matched log excerpts"):
        st.dataframe(findings[["line_number", "log_excerpt"]], hide_index=True, width="stretch")
    findings_downloaded = st.download_button("Download findings CSV", findings.to_csv(index=False).encode("utf-8-sig"), "log_findings.csv", "text/csv")
    if findings_downloaded:
        audit_event("log_findings_exported", f"filename={Path(upload.name).name}; findings={len(findings)}")
    if st.button("Create alerts from log findings"):
        inserted = 0
        notifications = []
        with connect_db() as connection:
            for row in findings.to_dict("records"):
                title = f"Log finding: {row['reason']}"
                candidates = map_signal_to_mitre(str(row["reason"]))
                mitre_id = candidates[0]["Technique ID"] if candidates else ""
                cursor = connection.execute(
                    """INSERT OR IGNORE INTO alerts
                       (created_at, title, severity, details, mitre_id, source_event_id, status)
                       VALUES (?, ?, ?, ?, ?, ?, 'Open')""",
                    (datetime.now(timezone.utc).isoformat(timespec="seconds"), title[:250], row["severity"], f"Source file: {Path(upload.name).name}\nLine: {row['line_number']}\nSource IP: {row['source_ip'] or 'not found'}\nReason: {row['reason']}", mitre_id, f"log:{content_id}:{row['line_number']}:{row['reason'][:80]}"),
                )
                inserted += max(cursor.rowcount, 0)
                if cursor.rowcount > 0:
                    notifications.append((row["severity"], title[:120]))
        for severity, title in notifications:
            notify_security_alert(severity, title)
        audit_event("log_findings_promoted", f"filename={Path(upload.name).name}; findings={len(findings)}; new_alerts={inserted}")
        st.success(f"Created {inserted} new alert(s); repeated imports were deduplicated.")


def render_audit_log():
    render_page_heading("Audit Log & Access")
    st.write("Review login attempts, alert and incident updates, IOC lookups, log scans, and report exports.")
    with connect_db() as connection:
        audit = pd.read_sql_query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1000", connection)
    if audit.empty:
        st.info("No audit activity has been recorded yet.")
    else:
        actions = sorted(audit["action"].astype(str).unique())
        selected = st.multiselect("Action types", actions, default=actions)
        filtered = audit[audit["action"].isin(selected)]
        st.dataframe(filtered, hide_index=True, width="stretch")
        st.download_button("Download audit CSV", filtered.to_csv(index=False).encode("utf-8-sig"), "audit_log.csv", "text/csv")
    st.caption("Access is controlled by the configured app login. This deployment currently uses one configured account; separate admin/analyst roles are not set up.")


def render_reports(report):
    render_page_heading("Report Generator")
    try:
        endpoint_events, event_source = load_sensor_events(limit=5000)
    except Exception as error:
        endpoint_events, event_source = pd.DataFrame(), "unavailable"
        st.warning(f"Live events could not be loaded: {error}")
    alerts = load_alerts()
    sources = {"Live endpoint events": endpoint_events, "Security alerts": alerts, "Offline threat report": report}
    selected_source = st.selectbox("Report data", list(sources))
    data = sources[selected_source].copy()
    key_suffix = re.sub(r"\W+", "_", selected_source.lower())
    if data.empty:
        st.info(f"No records are available for {selected_source}.")
        return

    date_column = next((name for name in ("occurred_at", "created_at", "timestamp", "date") if name in data.columns), None)
    if date_column:
        parsed = pd.to_datetime(data[date_column], errors="coerce", utc=True)
        valid = parsed.dropna()
        if not valid.empty:
            min_date = valid.min().date()
            max_date = valid.max().date()
            left, right = st.columns(2)
            start_date = left.date_input("From date", value=min_date, key=f"report_start_date_{key_suffix}")
            end_date = right.date_input("To date", value=max_date, key=f"report_end_date_{key_suffix}")
            if start_date > end_date:
                st.error("From date must be on or before To date.")
                return
            data = data[(parsed.dt.date >= start_date) & (parsed.dt.date <= end_date)]
    severity_column = "severity" if "severity" in data else "risk_level" if "risk_level" in data else None
    if severity_column:
        severities = sorted(data[severity_column].dropna().astype(str).unique())
        chosen = st.multiselect("Severity", severities, default=severities, key=f"report_severity_{key_suffix}")
        data = data[data[severity_column].astype(str).isin(chosen)]
    detection_column = next((name for name in ("event_type", "predicted_category", "attack_category") if name in data.columns), None)
    if detection_column:
        detection_types = sorted(data[detection_column].dropna().astype(str).unique())
        chosen_types = st.multiselect("Detection type", detection_types, default=detection_types, key=f"report_type_{key_suffix}")
        data = data[data[detection_column].astype(str).isin(chosen_types)]

    st.write(f"Filtered records: {len(data)} · Source: {selected_source}" + (f" ({event_source})" if selected_source == "Live endpoint events" else ""))
    st.dataframe(data.head(500), hide_index=True, width="stretch")
    if data.empty:
        return
    csv_data = data.to_csv(index=False).encode("utf-8-sig")
    try:
        pdf_data = make_pdf(data)
    except ImportError:
        pdf_data = None
        st.warning("PDF export requires reportlab.")
    csv_downloaded = st.download_button("Download filtered CSV", data=csv_data, file_name="filtered_security_report.csv", mime="text/csv", width="stretch")
    pdf_downloaded = False
    if pdf_data is not None:
        pdf_downloaded = st.download_button("Download filtered PDF", data=pdf_data, file_name="filtered_security_report.pdf", mime="application/pdf")
    if csv_downloaded or pdf_downloaded:
        audit_event("report_exported", f"source={selected_source}; rows={len(data)}; formats={'CSV' if csv_downloaded else ''}{'+PDF' if pdf_downloaded else ''}")
    if os.environ.get("CTI_DESKTOP_MODE") == "1" and st.button("Save filtered CSV and PDF to Downloads"):
        output_dir = Path.home() / "Downloads" / "AI Cyber Threat Intelligence"
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        (output_dir / f"filtered_report_{timestamp}.csv").write_bytes(csv_data)
        if pdf_data is not None:
            (output_dir / f"filtered_report_{timestamp}.pdf").write_bytes(pdf_data)
        audit_event("report_saved_to_downloads", f"source={selected_source}; rows={len(data)}")
        st.success(f"Filtered reports saved to {output_dir}")


def main():
    st.set_page_config(
        page_title="AI Cyber Threat Intelligence",
        page_icon="⬢",
        layout="wide",
    )
    apply_theme()
    init_database()

    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if not st.session_state["authenticated"]:
        st.session_state["email_alerts_enabled_this_session"] = False

    if not st.session_state["authenticated"]:
        intro, access = st.columns([1.1, 0.9], gap="large")
        with intro:
            st.markdown('<div class="cti-eyebrow">Private security workspace</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="cti-login-title">AI Cyber Threat<br><span>Intelligence</span></div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div class="cti-login-copy">A focused command center for endpoint activity, threat signals, and incident response.</div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div class="cti-login-points">◉ &nbsp; Endpoint and network visibility<br>◇ &nbsp; Prioritized security alerts<br>⌁ &nbsp; Investigation and reporting tools</div>',
                unsafe_allow_html=True,
            )

        with access:
            with st.container(border=True):
                st.markdown('<div class="cti-eyebrow">Secure access</div>', unsafe_allow_html=True)
                st.subheader("Welcome back")
                st.caption("Sign in with the account configured for this workspace.")
                expected_username = setting("APP_USERNAME")
                expected_password = setting("APP_PASSWORD")
                if not expected_username or not expected_password:
                    st.error("Authentication is not configured.")
                    st.code(
                        'APP_USERNAME = "analyst"\n'
                        'APP_PASSWORD = "choose-a-long-unique-password"'
                    )
                    st.caption(
                        "For local use, add these values to `.streamlit/secrets.toml`. "
                        "For deployment, add them to the app's Secrets settings in Streamlit Community Cloud."
                    )
                    st.stop()
                with st.form("login_form"):
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
                if submitted:
                    if hmac.compare_digest(username.strip(), expected_username) and hmac.compare_digest(password, expected_password):
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = username.strip()
                        audit_event("login_success", "Configured account authenticated.", username.strip())
                        st.rerun()
                    else:
                        audit_event("login_failure", f"Invalid sign-in attempt for username: {username.strip()[:80]}", username.strip() or "anonymous")
                        st.error("The username or password is incorrect.")
        st.stop()

    report = load_report()
    st.sidebar.markdown(
        '<div class="cti-brand"><div class="cti-brand-mark">CTI</div>'
        '<div><div class="cti-brand-name">CYBER INTEL</div>'
        '<span class="cti-brand-sub">THREAT OPERATIONS</span></div></div>',
        unsafe_allow_html=True,
    )
    st.sidebar.markdown(
        '<div class="cti-session"><span class="cti-dot"></span> Analyst session active</div>',
        unsafe_allow_html=True,
    )
    if st.sidebar.button("Log out", width="stretch"):
        audit_event("logout", "User signed out.")
        st.session_state["authenticated"] = False
        st.session_state["email_alerts_enabled_this_session"] = False
        st.session_state.pop("username", None)
        st.rerun()

    pages = [
        "Main Dashboard",
        "Live Monitor",
        "Endpoint Security",
        "Threat Feed",
        "IOC Analysis",
        "Analytics Dashboard",
        "AI Engine",
        "Explainable AI Assistant",
        "AI Model Evaluation Lab",
        "MITRE ATT&CK Map",
        "Alert System",
        "Incident Management",
        "Report Generator",
        "Log Analyzer",
        "Audit Log & Access",
    ]
    nav_symbols = {
        "Main Dashboard": "⌂",
        "Live Monitor": "◉",
        "Endpoint Security": "⬡",
        "Threat Feed": "◌",
        "IOC Analysis": "⌕",
        "Analytics Dashboard": "▥",
        "AI Engine": "✦",
        "Explainable AI Assistant": "◎",
        "AI Model Evaluation Lab": "◫",
        "MITRE ATT&CK Map": "⌘",
        "Alert System": "⚑",
        "Incident Management": "▣",
        "Report Generator": "▤",
        "Log Analyzer": "⌁",
        "Audit Log & Access": "◷",
    }
    st.sidebar.markdown('<div class="cti-sidebar-label">Modules</div>', unsafe_allow_html=True)
    page = st.sidebar.radio(
        "Open module",
        pages,
        label_visibility="collapsed",
        format_func=lambda item: f"{nav_symbols.get(item, '◦')}  {item}",
    )

    if page == "Main Dashboard":
        render_dashboard(report)
    elif page == "Live Monitor":
        render_live_monitor()
    elif page == "Endpoint Security":
        render_endpoint_security()
    elif page == "Threat Feed":
        render_threat_feed()
    elif page == "IOC Analysis":
        render_ioc_analysis()
    elif page == "Analytics Dashboard":
        render_analytics(report)
    elif page == "AI Engine":
        render_ai_engine(report)
    elif page == "Explainable AI Assistant":
        render_explainable_ai_assistant()
    elif page == "AI Model Evaluation Lab":
        render_model_evaluation_lab()
    elif page == "MITRE ATT&CK Map":
        render_mitre_map()
    elif page == "Alert System":
        render_alert_system()
    elif page == "Incident Management":
        render_incident_management()
    elif page == "Report Generator":
        render_reports(report)
    elif page == "Log Analyzer":
        render_log_analyzer()
    elif page == "Audit Log & Access":
        render_audit_log()


if __name__ == "__main__":
    main()
