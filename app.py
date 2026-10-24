from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO
from email.message import EmailMessage
from email.utils import parseaddr
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import smtplib
import sqlite3
import tomllib
import socket
import ssl
import uuid
import zipfile
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import (
        accuracy_score,
        balanced_accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder

    SKLEARN_AVAILABLE = True
    SKLEARN_IMPORT_ERROR = ""
except Exception as error:
    # Some managed Windows systems block compiled SciPy extensions. Keep the
    # desktop dashboard usable and use the metadata-only fallback for live events.
    SKLEARN_AVAILABLE = False
    SKLEARN_IMPORT_ERROR = str(error)

from ai_copilot import (
    AICopilotError,
    DEFAULT_MODEL as DEFAULT_OPENAI_MODEL,
    build_event_context,
    build_evaluation_context,
    build_handover_context,
    generate_review,
)
from live_capture import capture_summary, list_interfaces

BASE_DIR = Path(__file__).parent
REPORT_PATH = BASE_DIR / "threat_report.csv"
DATABASE_PATH = BASE_DIR / "security_center.db"
LOCAL_EMAIL_SETTINGS_PATH = BASE_DIR / ".streamlit" / "email_settings.toml"
FEODO_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
VT_API_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ALERT_CHECKLIST_ITEMS = (
    ("validate_context", "Verify the event time, affected host, account, and process."),
    ("correlate_activity", "Review nearby events and related alerts for the same host or indicator."),
    ("check_reputation", "Check relevant IPs, domains, and file hashes in IOC Analysis."),
    ("contain_if_confirmed", "If the threat is confirmed, follow your approved process to contain the host or block the indicator."),
    ("document_decision", "Record evidence and the investigation outcome before updating the alert status."),
)
RESPONSE_PLAYBOOKS = {
    "network": (
        "Confirm the destination IP, port, process, and connection time.",
        "Check the destination with the configured threat intelligence sources.",
        "Review nearby DNS, process, and authentication events for the same time window.",
        "If confirmed, follow your approved network containment procedure.",
        "Record the evidence, owner, and final disposition in the incident timeline.",
    ),
    "file": (
        "Verify the file path, signer, creation time, and SHA-256 hash locally.",
        "Check the hash using an approved reputation source; do not upload confidential files.",
        "Review the process that created or launched the file and nearby events.",
        "If confirmed, follow your approved quarantine and recovery procedure.",
        "Record evidence and final disposition in the incident timeline.",
    ),
    "process": (
        "Verify the process name, parent process, user, and start time.",
        "Check its executable location and signature using trusted local tools.",
        "Review its network connections and related file or login events.",
        "If confirmed, follow your approved host containment procedure.",
        "Record evidence and final disposition in the incident timeline.",
    ),
    "default": (
        "Confirm the event time, affected sensor, and alert evidence.",
        "Correlate related events, alerts, and indicators for the same period.",
        "Check the alert's MITRE ATT&CK mapping and validate it against evidence.",
        "Escalate or contain only under your approved incident response process.",
        "Document the investigation result and notify the assigned analyst.",
    ),
}
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


def render_optional_ai_review(*, payload, review_type, key_suffix, disclosure):
    """Render a manual, consent-gated generative AI review for bounded context."""
    api_key = setting("OPENAI_API_KEY")
    model = setting("OPENAI_MODEL", DEFAULT_OPENAI_MODEL) or DEFAULT_OPENAI_MODEL
    with st.expander("Generative AI review (optional)"):
        st.caption(disclosure)
        if not api_key:
            st.info(
                "Add `OPENAI_API_KEY` to local `.streamlit/secrets.toml` or your "
                "Streamlit Cloud app's private Secrets. ChatGPT sign-in is not an API key. "
                "API usage may be billed separately."
            )
            return

        context_json = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        context_digest = hashlib.sha256(context_json.encode("utf-8")).hexdigest()
        state_key = f"openai_review_{review_type}_{key_suffix}"
        result_key = f"openai_review_result_{review_type}_{key_suffix}"
        consent = st.checkbox(
            "I understand and allow sending the data described above to OpenAI for this review.",
            value=False,
            key=state_key,
        )
        if consent and st.button("Generate AI review", key=f"openai_review_button_{review_type}_{key_suffix}"):
            try:
                with st.spinner("Requesting a one-time AI review..."):
                    answer = generate_review(
                        payload=payload,
                        api_key=api_key,
                        model=model,
                        review_type=review_type,
                    )
                st.session_state[result_key] = {"digest": context_digest, "text": answer}
                audit_event("openai_ai_review_generated", f"type={review_type}; model={model}")
            except AICopilotError as error:
                st.error(str(error))
        saved = st.session_state.get(result_key, {})
        if saved.get("digest") == context_digest:
            st.markdown("**AI-generated analyst aid**")
            st.markdown(saved.get("text", ""))
            st.caption("Advisory only. Verify the evidence and conclusions before acting.")


LIVE_AI_MIN_INTERVAL_SECONDS = 60
LIVE_AI_MAX_REQUESTS_PER_HOUR = 10
LIVE_AI_RETRY_COOLDOWN_MINUTES = 15
LIVE_AI_OUTPUT_TOKENS = 220


@st.cache_resource
def live_ai_executor():
    """Keep one background API worker across Streamlit reruns."""
    return ThreadPoolExecutor(max_workers=1, thread_name_prefix="cti-live-ai")


def _finish_live_ai_review(review_id, api_key, model, payload):
    updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        answer = generate_review(
            payload=payload,
            api_key=api_key,
            model=model,
            review_type="event",
            max_output_tokens=LIVE_AI_OUTPUT_TOKENS,
            timeout=(4, 12),
        )
        status, review_text, error = "complete", answer, ""
    except AICopilotError as exc:
        status, review_text, error = "error", "", str(exc)
    except Exception as exc:
        status, review_text, error = "error", "", f"Unexpected AI review error ({type(exc).__name__})."

    with connect_db() as connection:
        connection.execute(
            """UPDATE ai_live_reviews
               SET status = ?, updated_at = ?, review_text = ?, error = ?
               WHERE id = ?""",
            (status, updated_at, review_text, error[:500], review_id),
        )
        if status == "error":
            retry_after = (
                datetime.now(timezone.utc) + timedelta(minutes=LIVE_AI_RETRY_COOLDOWN_MINUTES)
            ).isoformat(timespec="seconds")
            connection.execute(
                "INSERT INTO app_state (key, value) VALUES ('openai_live_retry_after', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (retry_after,),
            )
        connection.execute(
            "INSERT INTO audit_log (occurred_at, username, action, details) VALUES (?, ?, ?, ?)",
            (updated_at, "system", "openai_live_review_" + status, f"model={model}; error={error[:250]}"),
        )


def _queue_live_ai_review(events, enabled):
    """Queue one bounded OpenAI review for a new high-risk live event."""
    if not enabled:
        return "paused"
    api_key = setting("OPENAI_API_KEY")
    if not api_key:
        return "missing_key"
    if "AI risk score" not in events:
        return "no_candidate"

    anomaly = events.get("AI anomaly", pd.Series(False, index=events.index)).fillna(False).astype(bool)
    ioc_match = events.get("Threat-intel IOC", pd.Series(False, index=events.index)).fillna(False).astype(bool)
    risk = pd.to_numeric(events["AI risk score"], errors="coerce").fillna(0)
    candidates = events.loc[(risk >= 70) & (anomaly | ioc_match)].copy()
    if candidates.empty:
        return "waiting"

    occurred_col = "occurred_at" if "occurred_at" in candidates else "created_at"
    candidates["_live_ai_risk"] = risk.loc[candidates.index]
    time_values = candidates[occurred_col] if occurred_col in candidates else pd.Series("", index=candidates.index)
    candidates["_live_ai_time"] = pd.to_datetime(time_values, utc=True, errors="coerce")
    recent_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    candidates = candidates.loc[candidates["_live_ai_time"] >= recent_cutoff]
    if candidates.empty:
        return "waiting"
    def event_identity(row):
        for field in ("event_id", "event_uid", "id"):
            value = row.get(field)
            if value is not None and not pd.isna(value) and str(value).strip():
                return str(value).strip()[:160]
        return ""

    candidates["_live_event_id"] = candidates.apply(event_identity, axis=1)
    candidates = candidates.loc[candidates["_live_event_id"].ne("")]
    if candidates.empty:
        return "missing_event_id"
    candidates = candidates.sort_values(
        ["_live_ai_risk", "_live_ai_time"], ascending=[False, False], kind="stable"
    )
    model = setting("OPENAI_MODEL", DEFAULT_OPENAI_MODEL) or DEFAULT_OPENAI_MODEL
    now = datetime.now(timezone.utc)
    now_text = now.isoformat(timespec="seconds")
    hour_ago = (now - timedelta(hours=1)).isoformat(timespec="seconds")

    with connect_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """UPDATE ai_live_reviews
               SET status = 'error', updated_at = ?, error = 'Previous review worker did not finish.'
               WHERE status = 'pending' AND requested_at < ?""",
            (
                now_text,
                (now - timedelta(minutes=2)).isoformat(timespec="seconds"),
            ),
        )
        retry_row = connection.execute(
            "SELECT value FROM app_state WHERE key = 'openai_live_retry_after'"
        ).fetchone()
        if retry_row:
            retry_at = pd.to_datetime(retry_row[0], utc=True, errors="coerce")
            if not pd.isna(retry_at) and retry_at.to_pydatetime() > now:
                connection.commit()
                return "cooldown"

        reviewed_ids = {
            row[0]
            for row in connection.execute(
                """SELECT review.event_id FROM ai_live_reviews AS review
                   WHERE review.status IN ('pending', 'complete')
                     AND review.id = (
                         SELECT MAX(latest.id) FROM ai_live_reviews AS latest
                         WHERE latest.event_id = review.event_id
                     )"""
            ).fetchall()
        }
        candidates = candidates.loc[~candidates["_live_event_id"].isin(reviewed_ids)]
        if candidates.empty:
            connection.commit()
            return "already_reviewed"

        selected = candidates.iloc[0]
        event_id = selected["_live_event_id"]
        payload = build_event_context(selected.to_dict())

        recent_count = connection.execute(
            "SELECT COUNT(*) FROM ai_live_reviews WHERE requested_at >= ?",
            (hour_ago,),
        ).fetchone()[0]
        if recent_count >= LIVE_AI_MAX_REQUESTS_PER_HOUR:
            connection.commit()
            return "hourly_cap"
        last_request = connection.execute(
            "SELECT requested_at FROM ai_live_reviews ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if last_request:
            last_at = pd.to_datetime(last_request[0], utc=True, errors="coerce")
            if not pd.isna(last_at) and (now - last_at.to_pydatetime()).total_seconds() < LIVE_AI_MIN_INTERVAL_SECONDS:
                connection.commit()
                return "interval"

        cursor = connection.execute(
            """INSERT INTO ai_live_reviews
               (event_id, status, requested_at, updated_at, model)
               VALUES (?, 'pending', ?, ?, ?)""",
            (event_id, now_text, now_text, model),
        )
        review_id = cursor.lastrowid
        connection.execute(
            "DELETE FROM ai_live_reviews WHERE id NOT IN "
            "(SELECT id FROM ai_live_reviews ORDER BY id DESC LIMIT 250)"
        )
        connection.commit()

    try:
        live_ai_executor().submit(_finish_live_ai_review, review_id, api_key, model, payload)
    except RuntimeError:
        with connect_db() as connection:
            connection.execute(
                "UPDATE ai_live_reviews SET status = 'error', updated_at = ?, error = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), "Live AI worker is unavailable.", review_id),
            )
        return "worker_error"
    return "queued"


def _render_live_ai_review(enabled, queue_state):
    with connect_db() as connection:
        row = connection.execute(
            """SELECT event_id, status, updated_at, model, review_text, error
               FROM ai_live_reviews ORDER BY id DESC LIMIT 1"""
        ).fetchone()
    if row and row[1] == "complete":
        st.markdown("**Live OpenAI analyst review**")
        st.caption(f"Event {row[0]} · {row[3]} · {row[2]}")
        st.write(row[4])
        st.caption("Advisory only. Verify the event; this does not change the detector's risk score or verdict.")
    elif row and row[1] == "pending":
        st.info(f"OpenAI live review is processing high-risk event {row[0]} in the background.")
    elif row and row[1] == "error":
        st.warning(f"OpenAI live review is unavailable: {row[5]}")
        if queue_state == "cooldown" and st.button("Retry live AI now", key="retry_live_openai_now"):
            with connect_db() as connection:
                connection.execute("DELETE FROM app_state WHERE key = 'openai_live_retry_after'")
            st.rerun()
    elif queue_state == "queued":
        st.info("A new high-risk event was queued for live OpenAI review.")
    elif queue_state == "hourly_cap":
        st.info("Live OpenAI review paused after reaching its 10-request hourly safety limit.")
    elif queue_state == "cooldown":
        st.info("Live OpenAI review is paused temporarily after a provider error. The app will retry after the cooldown.")
    elif queue_state == "paused" or not enabled:
        st.info("Live OpenAI review is turned off. The local anomaly detector remains active.")
    elif queue_state == "missing_key":
        st.info("Add OPENAI_API_KEY to this app's private settings to enable live OpenAI reviews.")
    elif queue_state == "waiting":
        st.caption("Waiting for a new high-risk anomaly or threat-feed match before sending metadata to OpenAI.")


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
            --cti-bg: #080e16;
            --cti-panel: #101923;
            --cti-panel-raised: #152230;
            --cti-border: #263746;
            --cti-ink: #e8f0f7;
            --cti-muted: #8fa1b1;
            --cti-lime: #56d9cf;
            --cti-olive: #3d83b6;
            --cti-red: #f27a83;
        }
        @keyframes cti-arrive {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes cti-signal-pulse {
            0%, 100% { box-shadow: 0 0 0 0 #56d9cf20, 0 0 12px #56d9cf70; }
            50% { box-shadow: 0 0 0 5px #56d9cf08, 0 0 18px #56d9cf80; }
        }
        html, body, [data-testid="stAppViewContainer"] {
            background: radial-gradient(ellipse at 80% 0%, #132332 0%, var(--cti-bg) 42%);
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
            background: #12313a; color: var(--cti-lime);
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
            box-shadow: 0 5px 16px #56d9cf15;
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
            background:#102b31; color:#a7f0e8; font-size:.78rem; font-weight:600;
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
            color:#a7f0e8; background:#10232c; font-size:.67rem; font-weight:700; letter-spacing:.09em;
        }
        .cti-hero {
            display:flex; justify-content:space-between; align-items:center; gap:1rem;
            padding:1.5rem 1.6rem; margin-bottom:1.15rem; border:1px solid #323a2f;
            border-radius:16px; background:linear-gradient(115deg,#1b2018 0%,#141715 70%);
            box-shadow:inset 3px 0 0 #56d9cf55, 0 12px 35px #00000025;
            transition:transform .2s ease, border-color .2s ease;
        }
        .cti-hero:hover { transform:translateY(-2px); border-color:#337a81; }
        .cti-hero h2 { margin:.35rem 0 .45rem; font-size:1.45rem; }
        .cti-hero p { margin:0; max-width:48rem; }
        .cti-hero-mark {
            display:grid; place-items:center; flex:0 0 3.5rem; height:3.5rem;
            border:1px solid #337a81; border-radius:1rem; color:var(--cti-lime);
            background:#102b36; font-size:1.35rem;
        }
        .cti-section-label { margin:.35rem 0 .7rem; color:#a7ad9f; font-size:.68rem; font-weight:700; letter-spacing:.14em; text-transform:uppercase; }
        .cti-workbench-rail {
            display:flex; flex-wrap:wrap; justify-content:space-between; gap:.65rem 1.2rem;
            margin:-.25rem 0 1rem; padding:.68rem .9rem;
            border:1px solid #263b4b; border-radius:10px;
            background:linear-gradient(90deg,#0d1b27,#0c1721 70%,#10232b);
            color:#9db1c0; font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
            font-size:.68rem; letter-spacing:.055em;
        }
        .cti-workbench-rail span { display:flex; align-items:center; gap:.48rem; }
        .cti-rail-live { width:.45rem; height:.45rem; border-radius:50%; background:#56d9cf; box-shadow:0 0 10px #56d9cf90; }
        .cti-login-title { margin:.55rem 0 1rem; color:var(--cti-ink); font-size:clamp(2.2rem,4vw,3.7rem); font-weight:700; line-height:1.05; letter-spacing:-.06em; }
        .cti-login-title span { color:var(--cti-lime); }
        .cti-login-copy { max-width:34rem; color:#a6ada5; font-size:1rem; line-height:1.7; }
        .cti-login-points { margin-top:2rem; color:#c4c9c1; font-size:.86rem; line-height:2.2; }
        /* Refined command-center styling: clearer hierarchy and consistent
           interaction states across the dashboard widgets. */
        ::selection { color:#081217; background:#56d9cf; }
        [data-testid="stAppViewContainer"] {
            background:
                radial-gradient(ellipse at 88% 4%, #163045 0%, transparent 34%),
                radial-gradient(ellipse at 8% 100%, #102a32 0%, transparent 30%),
                #080e16;
        }
        [data-testid="stMainBlockContainer"] { padding-top:2.35rem; }
        [data-testid="stHeader"] { backdrop-filter:blur(14px); }
        [data-testid="stSidebar"] {
            background:linear-gradient(180deg,#101b27 0%,#0b141e 58%,#080f17 100%);
            box-shadow:12px 0 36px #00000018;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label {
            min-height:2.45rem; border:1px solid transparent;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
            border-color:#56d9cf44;
            background:linear-gradient(100deg,#16333c 0%,#14232e 100%);
            box-shadow:inset 3px 0 0 var(--cti-lime),0 5px 16px #00000020;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label p {
            font-size:.84rem; line-height:1.25rem;
        }
        h1,h2,h3,h4 { text-wrap:balance; }
        h2 { margin-top:1.35rem; padding-bottom:.45rem; }
        [data-testid="stMetric"] {
            position:relative; overflow:hidden;
            box-shadow:0 8px 24px #00000018;
        }
        [data-testid="stMetric"]::after {
            content:""; position:absolute; inset:0 0 auto; height:2px;
            background:linear-gradient(90deg,#56d9cf90,transparent 78%);
            opacity:.65;
        }
        [data-testid="stMetricValue"] { font-size:clamp(1.45rem,2vw,2rem); }
        [data-testid="stDataFrame"], [data-testid="stTable"] {
            box-shadow:0 10px 26px #0000001a;
        }
        [data-testid="stDataFrame"] th { color:#cce4ec !important; }
        [data-testid="stDataFrame"] tr:hover td { background:#56d9cf0b !important; }
        [data-testid="stVerticalBlockBorderWrapper"] {
            background:linear-gradient(145deg,#111f2b 0%,#0d1721 100%);
            box-shadow:inset 0 1px #ffffff06,0 10px 28px #00000020;
        }
        [data-testid="stVerticalBlockBorderWrapper"] h2,
        [data-testid="stVerticalBlockBorderWrapper"] h3 {
            color:#cde3ec; letter-spacing:.015em;
        }
        [data-testid="stMetric"] {
            background:linear-gradient(150deg,#142330 0%,#0f1923 100%);
            border-color:#273b4b;
        }
        [data-testid="stMetric"]:has([data-testid="stMetricValue"]) { border-top:2px solid #56d9cf38; }
        [data-testid="stExpander"] {
            border:1px solid var(--cti-border); border-radius:12px;
            background:#121513;
        }
        [data-testid="stTabs"] [role="tablist"] {
            gap:.35rem; border-bottom:1px solid var(--cti-border);
        }
        [data-testid="stTabs"] button[role="tab"] {
            border-radius:9px 9px 0 0; color:#aeb5aa;
        }
        [data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
            color:var(--cti-lime); background:#56d9cf0c;
        }
        [data-testid="stTextInput"] input:focus,
        [data-testid="stTextArea"] textarea:focus,
        [data-testid="stNumberInput"] input:focus,
        [data-testid="stDateInput"] input:focus {
            border-color:#56d9cf !important;
            box-shadow:0 0 0 2px #56d9cf22 !important;
        }
        [data-testid="stButton"] button:focus-visible,
        [data-testid="stDownloadButton"] button:focus-visible,
        [data-testid="stFormSubmitButton"] button:focus-visible {
            outline:2px solid var(--cti-lime); outline-offset:2px;
        }
        [data-testid="stAlert"] { box-shadow:0 6px 18px #00000016; }
        ::-webkit-scrollbar { width:10px; height:10px; }
        ::-webkit-scrollbar-track { background:#0d100e; }
        ::-webkit-scrollbar-thumb { background:#343a31; border:2px solid #0d100e; border-radius:99px; }
        ::-webkit-scrollbar-thumb:hover { background:#3d83b6; }
        @media (max-width: 760px) {
            [data-testid="stMainBlockContainer"] { padding:1.2rem 1rem 2rem; }
            .cti-page-heading { align-items:flex-start; flex-direction:column; }
            .cti-hero { align-items:flex-start; }
            .cti-workbench-rail { justify-content:flex-start; }
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
        "AI Engine": "Review live anomaly scores, device baselines, attack-chain signals, analyst feedback, and drift warnings.",
        "Explainable AI Assistant": "Understand each live event's score, evidence, and suggested investigation steps.",
        "AI Model Evaluation Lab": "Measure model performance on labeled holdout data and inspect its errors.",
        "MITRE ATT&CK Map": "Connect observed activity with known adversary techniques.",
        "Alert System": "Triage security alerts and prioritize follow-up actions.",
        "Incident Management": "Track investigations, ownership, and response progress.",
        "Report Generator": "Prepare and download security reports for review.",
        "Custom Detection Rule Builder": "Create and manage metadata-based rules that generate deduplicated alerts.",
        "Event Correlation Graph": "Visualize endpoint events that share a device, process, IP address, or file hash.",
        "Multi-device Fleet View": "Track sensor heartbeats and activity across enrolled endpoint devices.",
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
                status TEXT NOT NULL DEFAULT 'Open',
                assigned_to TEXT NOT NULL DEFAULT '',
                due_at TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                last_seen_at TEXT,
                dedupe_key TEXT
            )"""
        )
        alert_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(alerts)")
        }
        if "source_event_id" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN source_event_id TEXT")
        if "assigned_to" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN assigned_to TEXT NOT NULL DEFAULT ''")
        if "due_at" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN due_at TEXT")
        if "occurrence_count" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1")
        if "last_seen_at" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN last_seen_at TEXT")
        if "dedupe_key" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN dedupe_key TEXT")
        connection.execute("UPDATE alerts SET last_seen_at = created_at WHERE last_seen_at IS NULL")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_due_at ON alerts(due_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(dedupe_key, last_seen_at)")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_event_id "
            "ON alerts(source_event_id)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS suppression_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL,
                rule_value TEXT NOT NULL,
                reason TEXT NOT NULL,
                expires_at TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                UNIQUE(rule_type, rule_value)
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_suppression_rules_expiry ON suppression_rules(expires_at)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS suppression_matches (
                event_id TEXT PRIMARY KEY,
                rule_id INTEGER NOT NULL,
                first_seen_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS alert_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT ''
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_timeline_alert_time "
            "ON alert_timeline(alert_id, occurred_at DESC, id DESC)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ai_live_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                model TEXT NOT NULL,
                review_text TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT ''
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_live_reviews_requested_at "
            "ON ai_live_reviews(requested_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_live_reviews_event_id "
            "ON ai_live_reviews(event_id, id DESC)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS alert_checklist (
                alert_id INTEGER NOT NULL,
                item_key TEXT NOT NULL,
                label TEXT NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (alert_id, item_key)
            )"""
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
            """CREATE TABLE IF NOT EXISTS saved_hunt_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                query_text TEXT NOT NULL DEFAULT '',
                filters_json TEXT NOT NULL DEFAULT '{}',
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS investigation_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'Medium',
                status TEXT NOT NULL DEFAULT 'Open',
                owner TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS investigation_case_alerts (
                case_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                linked_at TEXT NOT NULL,
                PRIMARY KEY (case_id, alert_id)
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS investigation_case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS safe_test_events (
                event_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                scenario TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                alert_id INTEGER,
                status TEXT NOT NULL DEFAULT 'Active'
            )"""
        )
        test_event_columns = {row[1] for row in connection.execute("PRAGMA table_info(safe_test_events)")}
        if "status" not in test_event_columns:
            connection.execute("ALTER TABLE safe_test_events ADD COLUMN status TEXT NOT NULL DEFAULT 'Active'")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ioc_watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL DEFAULT 'Analyst supplied',
                expires_at TEXT,
                UNIQUE(indicator_type, indicator_value)
            )"""
        )
        watchlist_columns = {row[1] for row in connection.execute("PRAGMA table_info(ioc_watchlist)")}
        if "source" not in watchlist_columns:
            connection.execute("ALTER TABLE ioc_watchlist ADD COLUMN source TEXT NOT NULL DEFAULT 'Analyst supplied'")
        if "expires_at" not in watchlist_columns:
            connection.execute("ALTER TABLE ioc_watchlist ADD COLUMN expires_at TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_ioc_watchlist_expiry ON ioc_watchlist(expires_at)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS incident_alert_links (
                incident_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, alert_id)
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT ''
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS response_playbook_progress (
                alert_id INTEGER NOT NULL,
                step_key TEXT NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (alert_id, step_key)
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scheduled_reports (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                cadence TEXT NOT NULL DEFAULT 'Daily',
                send_time_utc TEXT NOT NULL DEFAULT '09:00',
                recipient TEXT NOT NULL DEFAULT '',
                last_sent_at TEXT,
                last_attempt_slot TEXT,
                last_error TEXT NOT NULL DEFAULT ''
            )"""
        )
        connection.execute("INSERT OR IGNORE INTO scheduled_reports (id) VALUES (1)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS custom_detection_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL DEFAULT '',
                process_contains TEXT NOT NULL DEFAULT '',
                remote_ip TEXT NOT NULL DEFAULT '',
                file_extension TEXT NOT NULL DEFAULT '',
                min_risk INTEGER NOT NULL DEFAULT 0,
                output_severity TEXT NOT NULL DEFAULT 'High',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS sensor_registry (
                sensor_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '',
                criticality TEXT NOT NULL DEFAULT 'Unclassified',
                updated_at TEXT NOT NULL
            )"""
        )
        registry_columns = {row[1] for row in connection.execute("PRAGMA table_info(sensor_registry)")}
        if "criticality" not in registry_columns:
            connection.execute("ALTER TABLE sensor_registry ADD COLUMN criticality TEXT NOT NULL DEFAULT 'Unclassified'")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ai_baseline_events (
                sensor_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL DEFAULT '',
                process_name TEXT NOT NULL DEFAULT '',
                risk_score REAL NOT NULL DEFAULT 0,
                occurred_at TEXT NOT NULL,
                baseline_score INTEGER NOT NULL DEFAULT 0,
                baseline_reason TEXT NOT NULL DEFAULT '',
                sample_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (sensor_id, event_id)
            )"""
        )
        baseline_columns = {row[1] for row in connection.execute("PRAGMA table_info(ai_baseline_events)")}
        for column, declaration in (("baseline_score", "INTEGER NOT NULL DEFAULT 0"), ("baseline_reason", "TEXT NOT NULL DEFAULT ''"), ("sample_count", "INTEGER NOT NULL DEFAULT 0")):
            if column not in baseline_columns:
                connection.execute(f"ALTER TABLE ai_baseline_events ADD COLUMN {column} {declaration}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_ai_baseline_sensor_time ON ai_baseline_events(sensor_id, occurred_at)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ai_analyst_feedback (
                event_id TEXT PRIMARY KEY,
                sensor_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                process_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                verdict TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_ai_feedback_fingerprint ON ai_analyst_feedback(fingerprint)")
        rule_columns = {row[1] for row in connection.execute("PRAGMA table_info(custom_detection_rules)")}
        if "source" not in rule_columns:
            connection.execute("ALTER TABLE custom_detection_rules ADD COLUMN source TEXT NOT NULL DEFAULT 'Analyst'")


def audit_event(action, details="", username=None):
    """Record security-relevant app actions without storing credentials."""
    actor = username or st.session_state.get("username", "anonymous")
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO audit_log (occurred_at, username, action, details) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), str(actor), str(action), str(details)[:1000]),
        )


def save_app_state(key, value):
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(key), str(value)),
        )


def read_app_state(key, default=""):
    with connect_db() as connection:
        row = connection.execute("SELECT value FROM app_state WHERE key = ?", (str(key),)).fetchone()
    return row[0] if row else default


def alert_group_window_minutes():
    try:
        return max(1, min(1440, int(read_app_state("alert_group_window_minutes", "15"))))
    except (TypeError, ValueError):
        return 15


def load_saved_hunt_queries():
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT id, name, query_text, filters_json, created_by, created_at, updated_at "
            "FROM saved_hunt_queries ORDER BY name COLLATE NOCASE",
            connection,
        )


def save_hunt_query(name, query_text, filters):
    clean_name = str(name).strip()[:100]
    if not clean_name:
        raise ValueError("Enter a name for this saved search.")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    encoded = json.dumps(filters, ensure_ascii=True, separators=(",", ":"))
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO saved_hunt_queries (name, query_text, filters_json, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET query_text=excluded.query_text,
                 filters_json=excluded.filters_json, created_by=excluded.created_by, updated_at=excluded.updated_at""",
            (clean_name, str(query_text).strip()[:300], encoded,
             str(st.session_state.get("username", "Analyst"))[:120], now, now),
        )
    audit_event("threat_hunt_query_saved", f"name={clean_name[:100]}")


def load_retention_counts(days):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat(timespec="seconds")
    counts = {}
    with connect_db() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        queries = {
            "Closed / resolved alerts": ("alerts", "created_at < ? AND status IN ('Closed','Resolved')"),
            "Local endpoint events": ("endpoint_events", "created_at < ?"),
            "AI baseline observations": ("ai_baseline_events", "occurred_at < ?"),
            "AI analyst feedback": ("ai_analyst_feedback", "updated_at < ?"),
            "Audit records": ("audit_log", "occurred_at < ?"),
            "Old AI reviews": ("ai_live_reviews", "requested_at < ?"),
            "Suppression match history": ("suppression_matches", "first_seen_at < ?"),
            "Synthetic test records": ("safe_test_events", "created_at < ?"),
        }
        for label, (table, condition) in queries.items():
            if table in tables:
                if table == "endpoint_events":
                    columns = {row[1] for row in connection.execute("PRAGMA table_info(endpoint_events)")}
                    if "synced" in columns:
                        condition = "created_at < ? AND COALESCE(synced, 0) = 1"
                counts[label] = int(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {condition}", (cutoff,)).fetchone()[0])
    return cutoff, counts


def purge_local_retention_records(days):
    cutoff, preview = load_retention_counts(days)
    removed = {}
    with connect_db() as connection:
        connection.execute("BEGIN")
        expired_alert_ids = [row[0] for row in connection.execute(
            "SELECT id FROM alerts WHERE created_at < ? AND status IN ('Closed','Resolved')", (cutoff,)
        ).fetchall()]
        if expired_alert_ids:
            marks = ",".join("?" for _ in expired_alert_ids)
            for table in ("alert_timeline", "alert_checklist", "response_playbook_progress", "incident_alert_links", "investigation_case_alerts"):
                connection.execute(f"DELETE FROM {table} WHERE alert_id IN ({marks})", expired_alert_ids)
            connection.execute(f"DELETE FROM alerts WHERE id IN ({marks})", expired_alert_ids)
        removed["Closed / resolved alerts"] = len(expired_alert_ids)
        all_tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cleanup = {
            "Local endpoint events": ("endpoint_events", "created_at"),
            "AI baseline observations": ("ai_baseline_events", "occurred_at"),
            "AI analyst feedback": ("ai_analyst_feedback", "updated_at"),
            "Audit records": ("audit_log", "occurred_at"),
            "Old AI reviews": ("ai_live_reviews", "requested_at"),
            "Suppression match history": ("suppression_matches", "first_seen_at"),
            "Synthetic test records": ("safe_test_events", "created_at"),
        }
        for label, (table, time_column) in cleanup.items():
            if table in all_tables:
                condition = f"{time_column} < ?"
                if table == "endpoint_events":
                    columns = {row[1] for row in connection.execute("PRAGMA table_info(endpoint_events)")}
                    if "synced" in columns:
                        condition += " AND COALESCE(synced, 0) = 1"
                cursor = connection.execute(f"DELETE FROM {table} WHERE {condition}", (cutoff,))
                removed[label] = max(int(cursor.rowcount), 0)
        connection.commit()
    return removed


def call_api_retention(days, *, apply=False):
    api_url = setting("API_BASE_URL").strip().rstrip("/")
    token = setting("API_TOKEN").strip()
    if not api_url or not token:
        raise ValueError("Cloud event retention needs API_BASE_URL and API_TOKEN in the app's private settings.")
    route = "/v1/maintenance/events/retention" if apply else "/v1/maintenance/events/retention-preview"
    response = requests.post(
        f"{api_url}{route}",
        json={"days": int(days)},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def load_alerts():
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY id DESC", connection
        )


def configured_accounts():
    """Read role accounts from private app settings; never persist passwords."""
    accounts = []
    admin_user = setting("APP_ADMIN_USERNAME")
    admin_password = setting("APP_ADMIN_PASSWORD")
    if not (admin_user and admin_password):
        admin_user, admin_password = setting("APP_USERNAME"), setting("APP_PASSWORD")
    if admin_user and admin_password:
        accounts.append((admin_user, admin_password, "Admin"))
    analyst_user, analyst_password = setting("APP_ANALYST_USERNAME"), setting("APP_ANALYST_PASSWORD")
    if analyst_user and analyst_password and analyst_user != admin_user:
        accounts.append((analyst_user, analyst_password, "Analyst"))
    return accounts


def is_admin():
    return str(st.session_state.get("user_role", "Analyst")).lower() == "admin"


def require_admin():
    if is_admin():
        return True
    st.error("Administrator access is required for this settings page.")
    st.info("Sign in with an Admin account, or ask the workspace administrator to configure this change.")
    return False


def load_suppression_rules(active_only=False):
    query = "SELECT * FROM suppression_rules"
    if active_only:
        query += " WHERE enabled = 1 AND (expires_at IS NULL OR expires_at = '' OR expires_at >= date('now'))"
    query += " ORDER BY id DESC"
    with connect_db() as connection:
        return pd.read_sql_query(query, connection)


def matching_suppression_rule(event, rules=None):
    rules = rules if rules is not None else load_suppression_rules(active_only=True)
    if rules.empty:
        return None
    event = event if isinstance(event, dict) else dict(event)
    file_name = str(event.get("file_name") or event.get("file_path") or "").strip()
    actual = {
        "process": str(event.get("process_name") or "").strip().lower(),
        "remote_ip": str(event.get("remote_ip") or "").strip().lower(),
        "extension": Path(file_name).suffix.lower(),
        "event_type": str(event.get("event_type") or "").strip().lower(),
    }
    for rule in rules.to_dict("records"):
        kind = str(rule.get("rule_type") or "")
        value = str(rule.get("rule_value") or "").strip().lower()
        if kind in actual and value and actual[kind] == value:
            return rule
    return None


def record_suppression_match(event_id, rule):
    if not event_id or not rule:
        return False
    with connect_db() as connection:
        cursor = connection.execute(
            "INSERT OR IGNORE INTO suppression_matches (event_id, rule_id, first_seen_at) VALUES (?, ?, ?)",
            (str(event_id)[:200], int(rule["id"]), datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        if cursor.rowcount:
            row = connection.execute("SELECT value FROM app_state WHERE key='suppressed_event_total'").fetchone()
            total = int(row[0]) if row and str(row[0]).isdigit() else 0
            connection.execute(
                "INSERT INTO app_state (key, value) VALUES ('suppressed_event_total', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(total + 1),),
            )
            return True
    return False


def alert_fingerprint(title, severity):
    normalized = str(title or "").strip().lower()
    normalized = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", normalized)
    normalized = re.sub(r"\b[a-f0-9]{32,128}\b", "<hash>", normalized)
    normalized = re.sub(r"\b\d+\b", "<n>", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return hashlib.sha256(f"{str(severity).lower()}|{normalized}".encode("utf-8")).hexdigest()


def record_alert_timeline(alert_id, event_type, note="", actor=None):
    """Append an investigation event to one alert's permanent timeline."""
    username = str(actor or st.session_state.get("username", "system"))[:120]
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO alert_timeline "
            "(alert_id, occurred_at, event_type, actor, note) VALUES (?, ?, ?, ?, ?)",
            (
                int(alert_id),
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                str(event_type)[:80],
                username,
                str(note)[:4000],
            ),
        )


def load_alert_timeline(alert_id):
    with connect_db() as connection:
        timeline = pd.read_sql_query(
            "SELECT occurred_at, event_type, actor, note FROM alert_timeline "
            "WHERE alert_id = ? ORDER BY occurred_at DESC, id DESC",
            connection,
            params=(int(alert_id),),
        )
        if timeline.empty:
            alert = connection.execute(
                "SELECT created_at, severity, title, details FROM alerts WHERE id = ?",
                (int(alert_id),),
            ).fetchone()
            if alert:
                connection.execute(
                    "INSERT INTO alert_timeline "
                    "(alert_id, occurred_at, event_type, actor, note) VALUES (?, ?, ?, ?, ?)",
                    (
                        int(alert_id),
                        str(alert[0]),
                        "Alert created",
                        "system",
                        f"{alert[1]}: {alert[2]}\n{alert[3]}",
                    ),
                )
                timeline = pd.read_sql_query(
                    "SELECT occurred_at, event_type, actor, note FROM alert_timeline "
                    "WHERE alert_id = ? ORDER BY occurred_at DESC, id DESC",
                    connection,
                    params=(int(alert_id),),
                )
        return timeline


def update_alert_status(alert_id, new_status):
    """Persist an alert status change and record it in the investigation timeline."""
    with connect_db() as connection:
        previous = connection.execute(
            "SELECT status FROM alerts WHERE id = ?", (int(alert_id),)
        ).fetchone()
        if not previous or previous[0] == new_status:
            return False
        connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (str(new_status), int(alert_id)),
        )
    record_alert_timeline(
        alert_id,
        "Status changed",
        f"{previous[0]} → {new_status}",
    )
    audit_event("alert_status_changed", f"alert_id={alert_id}; status={new_status}")
    return True


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
        active_ids = [
            int(row[0]) for row in connection.execute(
                "SELECT id FROM alerts WHERE status IN ('Open', 'Acknowledged')"
            ).fetchall()
        ]
        cursor = connection.execute(
            "UPDATE alerts SET status = 'Closed' WHERE status IN ('Open', 'Acknowledged')"
        )
        connection.execute(
            "INSERT INTO app_state (key, value) VALUES ('notifications_cleared_at', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (cleared_at,),
        )
    count = max(int(cursor.rowcount), 0)
    for alert_id in active_ids:
        record_alert_timeline(alert_id, "Status changed", "Open notification cleared; status set to Closed.")
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


def record_incident_timeline(incident_id, event_type, note="", actor=None):
    username = str(actor or st.session_state.get("username", "system"))[:120]
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO incident_timeline (incident_id, occurred_at, event_type, actor, note) VALUES (?, ?, ?, ?, ?)",
            (int(incident_id), datetime.now(timezone.utc).isoformat(timespec="seconds"), str(event_type)[:80], username, str(note)[:4000]),
        )


def load_incident_timeline(incident_id):
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT occurred_at, event_type, actor, note FROM incident_timeline WHERE incident_id = ? ORDER BY occurred_at DESC, id DESC",
            connection, params=(int(incident_id),),
        )


def get_detection_settings():
    defaults = {"endpoint_alert_min_risk": 45, "ai_anomaly_min_score": 40}
    with connect_db() as connection:
        rows = connection.execute(
            "SELECT key, value FROM app_state WHERE key IN ('endpoint_alert_min_risk', 'ai_anomaly_min_score')"
        ).fetchall()
    for key, value in rows:
        try:
            defaults[key] = max(0, min(100, int(value)))
        except (TypeError, ValueError):
            pass
    return defaults


def save_detection_settings(endpoint_alert_min_risk, ai_anomaly_min_score):
    with connect_db() as connection:
        connection.executemany(
            "INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [("endpoint_alert_min_risk", str(int(endpoint_alert_min_risk))), ("ai_anomaly_min_score", str(int(ai_anomaly_min_score)))],
        )


def load_ioc_watchlist(enabled_only=False):
    query = "SELECT id, indicator_type, indicator_value, label, created_at, enabled, source, expires_at FROM ioc_watchlist"
    if enabled_only:
        query += " WHERE enabled = 1 AND (expires_at IS NULL OR expires_at = '' OR expires_at >= date('now'))"
    query += " ORDER BY id DESC"
    with connect_db() as connection:
        return pd.read_sql_query(query, connection)


def validate_watchlist_indicator(indicator_type, value):
    clean = str(value).strip().lower()
    kind = str(indicator_type).lower()
    if kind == "ip address":
        return str(ipaddress.ip_address(clean))
    if kind == "file hash":
        if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})", clean):
            raise ValueError("Enter a valid MD5, SHA-1, SHA-256, or SHA-512 hexadecimal hash.")
        return clean
    if kind == "domain":
        if len(clean) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", clean):
            raise ValueError("Enter a valid domain name, such as suspicious.example.")
        return clean
    raise ValueError("Choose an IP address, domain, or file hash.")


def extract_alert_iocs(alert):
    """Extract format-valid IPs, domains, and hashes from alert metadata only."""
    text = "\n".join((str(alert.get("title") or ""), str(alert.get("details") or "")))
    found = {}
    for value in re.findall(r"(?<![a-f0-9])(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])", text, flags=re.I):
        found[("File hash", value.lower())] = True
    for value in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            found[("IP address", str(ipaddress.ip_address(value)))] = True
        except ValueError:
            continue
    skipped_extensions = {
        "apk", "asp", "aspx", "bat", "bin", "cmd", "conf", "csv", "dat", "db",
        "dll", "doc", "docx", "dylib", "exe", "gif", "gz", "htm", "html", "ico", "ini",
        "jar", "jpeg", "jpg", "js", "json", "log", "md", "md5", "mds", "mkv", "mp3",
        "mp4", "msi", "pdf", "php", "png", "ps1", "py", "rar", "reg", "sh", "sha1",
        "sha256", "sha512", "so", "sql", "sqlite", "svg", "sys", "tar", "tmp", "ts",
        "txt", "war", "webp", "xls", "xlsx", "xml", "yaml", "yml", "zip", "7z",
    }
    domain_pattern = r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])"
    for value in re.findall(domain_pattern, text):
        try:
            normalized = validate_watchlist_indicator("Domain", value)
        except ValueError:
            continue
        if normalized.rsplit(".", 1)[-1] in skipped_extensions:
            continue
        found[("Domain", normalized)] = True
    return pd.DataFrame(
        [{"Type": kind, "Indicator": value} for kind, value in sorted(found)],
        columns=["Type", "Indicator"],
    )


def render_alert_ioc_extractor(alert):
    alert_id = int(alert.get("id", 0) or 0)
    with st.expander("Extract indicators from this alert"):
        st.caption("Scans only this alert's title and saved metadata. Nothing is sent to an external provider; review each value before adding it to the local IOC Watchlist.")
        indicators = extract_alert_iocs(alert)
        if indicators.empty:
            st.info("No format-valid IP address, domain, or file hash was found in this alert.")
            return
        st.dataframe(indicators, hide_index=True, width="stretch")
        if not is_admin():
            st.info("An Admin can select an indicator below and add it to the IOC Watchlist.")
            return
        choices = {
            f"{row.Type} · {row.Indicator}": (str(row.Type), str(row.Indicator))
            for row in indicators.itertuples(index=False)
        }
        with st.form(f"alert_ioc_extractor_form_{alert_id}"):
            selected_label = st.selectbox("Indicator to watch", list(choices), key=f"alert_ioc_choice_{alert_id}")
            indicator_type, indicator_value = choices[selected_label]
            label = st.text_input("Watchlist label (optional)", value=f"From alert #{alert_id}", max_chars=120, key=f"alert_ioc_label_{alert_id}")
            expires = st.checkbox("Expire this watch entry after 30 days", value=True, key=f"alert_ioc_expiry_{alert_id}")
            submitted = st.form_submit_button("Add selected indicator to watchlist")
        if submitted:
            try:
                normalized = validate_watchlist_indicator(indicator_type, indicator_value)
                expires_at = (datetime.now(timezone.utc).date() + timedelta(days=30)).isoformat() if expires else None
                with connect_db() as connection:
                    connection.execute(
                        "INSERT INTO ioc_watchlist (indicator_type,indicator_value,label,created_at,enabled,source,expires_at) VALUES (?,?,?,?,1,?,?)",
                        (indicator_type.lower(), normalized, label.strip()[:120], datetime.now(timezone.utc).isoformat(timespec="seconds"), f"Alert #{alert_id}", expires_at),
                    )
                audit_event("alert_ioc_added_to_watchlist", f"alert_id={alert_id}; type={indicator_type}; indicator={normalized}")
                st.success("Indicator added to the IOC Watchlist.")
                st.rerun()
            except sqlite3.IntegrityError:
                st.info("This indicator is already on the IOC Watchlist.")
            except ValueError as error:
                st.error(str(error))


def sync_watchlist_alerts(events):
    if events is None or events.empty:
        return 0
    watchlist = load_ioc_watchlist(enabled_only=True)
    if watchlist.empty:
        return 0
    rules = load_suppression_rules(active_only=True)
    created = 0
    for event in events.to_dict("records"):
        event_id = str(event.get("event_id") or event.get("event_uid") or event.get("id") or "").strip()
        if not event_id:
            continue
        rule = matching_suppression_rule(event, rules)
        if rule:
            record_suppression_match(event_id, rule)
            continue
        fields = {
            "ip address": [event.get("remote_ip", "")],
            "domain": [],
            "file hash": [event.get("file_sha256", "")],
        }
        text = " ".join(str(event.get(key) or "") for key in ("summary", "details", "file_name", "process_name"))
        for row in watchlist.itertuples(index=False):
            value = str(row.indicator_value).strip().lower()
            kind = str(row.indicator_type).lower()
            matched = False
            if kind == "ip address":
                matched = any(str(item or "").strip().lower() == value for item in fields[kind]) or bool(re.search(r"(?<![\w.])" + re.escape(value) + r"(?![\w.])", text, re.I))
            elif kind == "file hash":
                matched = any(str(item or "").strip().lower() == value for item in fields[kind]) or bool(re.search(r"(?<![a-f0-9])" + re.escape(value) + r"(?![a-f0-9])", text, re.I))
            elif kind == "domain":
                matched = bool(re.search(r"(?<![a-z0-9.-])" + re.escape(value) + r"(?![a-z0-9.-])", text, re.I))
            if not matched:
                continue
            label = str(row.label or "").strip()
            details = "\n".join([
                "Indicator matched an analyst-maintained local watchlist.",
                f"Type: {row.indicator_type}",
                f"Indicator: {value}",
                f"Label: {label or 'Not provided'}",
                f"Event: {event.get('summary') or event.get('event_type') or 'Endpoint activity'}",
                "A watchlist match is a review signal and requires verification.",
            ])
            severity = "High"
            source_key = f"watchlist:{int(row.id)}:{event_id}"
            if add_alert(f"Watchlist match: {label or value}", severity, details, source_event_id=source_key):
                created += 1
    return created


def render_ioc_watchlist():
    render_page_heading("IOC Watchlist")
    if not require_admin():
        return
    st.write("Keep IP addresses, domains, and file hashes you want the sensor events checked against.")
    st.caption("Matches create deduplicated alerts when endpoint metadata or an authorized local log contains the indicator. The sensor currently records IPs and file hashes; domain matches are available in text/log evidence where the domain is present.")
    with st.form("ioc_watchlist_add_form", clear_on_submit=True):
        kind = st.selectbox("Indicator type", ["IP address", "Domain", "File hash"])
        value = st.text_input("Indicator value", max_chars=253)
        label = st.text_input("Friendly label (optional)", max_chars=120)
        source_name = st.selectbox("Indicator source", ["Analyst supplied", "Threat feed", "VirusTotal", "AbuseIPDB", "Other"])
        has_expiry = st.checkbox("Set an expiry date", value=False)
        expires_on = st.date_input("Expires after (UTC)", value=datetime.now(timezone.utc).date() + timedelta(days=30), disabled=not has_expiry)
        submitted = st.form_submit_button("Add to watchlist")
    if submitted:
        try:
            normalized = validate_watchlist_indicator(kind, value)
            with connect_db() as connection:
                connection.execute(
                    "INSERT INTO ioc_watchlist (indicator_type, indicator_value, label, created_at, enabled, source, expires_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
                    (kind.lower(), normalized, label.strip()[:120], datetime.now(timezone.utc).isoformat(timespec="seconds"), source_name, expires_on.isoformat() if has_expiry else None),
                )
            audit_event("ioc_watchlist_added", f"type={kind}; indicator={normalized}")
            st.success("Indicator added to the watchlist.")
            st.rerun()
        except ValueError as error:
            st.error(str(error))
        except sqlite3.IntegrityError:
            st.info("This indicator is already on the watchlist.")
    items = load_ioc_watchlist()
    st.subheader("Saved indicators")
    if items.empty:
        st.info("Watchlist is empty. Add an indicator above to start monitoring for matches.")
        return
    display = items.rename(columns={"indicator_type":"Type", "indicator_value":"Indicator", "label":"Label", "created_at":"Added (UTC)", "enabled":"Enabled", "source":"Source", "expires_at":"Expires (UTC)"})
    today_utc = datetime.now(timezone.utc).date().isoformat()
    display["Status"] = display.apply(lambda row: "Expired" if row["Expires (UTC)"] and str(row["Expires (UTC)"]) < today_utc else "Active" if row["Enabled"] else "Disabled", axis=1)
    st.dataframe(display[["id", "Type", "Indicator", "Label", "Source", "Added (UTC)", "Expires (UTC)", "Status"]], hide_index=True, width="stretch")
    options = {f"#{row.id} · {row.indicator_type} · {row.indicator_value}": int(row.id) for row in items.itertuples(index=False)}
    selected = st.selectbox("Indicator to update", list(options), key="watchlist_selected_item")
    left, right = st.columns(2)
    selected_id = options[selected]
    current_enabled = bool(items.loc[items["id"] == selected_id, "enabled"].iloc[0])
    with left:
        if st.button("Disable indicator" if current_enabled else "Enable indicator", key="watchlist_toggle"):
            with connect_db() as connection:
                connection.execute("UPDATE ioc_watchlist SET enabled = ? WHERE id = ?", (0 if current_enabled else 1, selected_id))
            audit_event("ioc_watchlist_toggled", f"id={selected_id}; enabled={not current_enabled}")
            st.rerun()
    with right:
        if st.button("Remove indicator", key="watchlist_remove", type="secondary"):
            with connect_db() as connection:
                connection.execute("DELETE FROM ioc_watchlist WHERE id = ?", (selected_id,))
            audit_event("ioc_watchlist_removed", f"id={selected_id}")
            st.rerun()


def render_detection_tuning():
    render_page_heading("Detection Tuning")
    st.write("Adjust when endpoint and AI signals are promoted into investigation alerts.")
    st.caption("Lower values create more review alerts; higher values focus on stronger signals. These settings do not change the sensor's file/network collection behavior.")
    values = get_detection_settings()
    with st.form("detection_tuning_form"):
        endpoint_threshold = st.slider("Minimum endpoint risk to create an alert", 0, 100, values["endpoint_alert_min_risk"], 5, help="Sensor event risk score required before a Review event is promoted. High and Critical sensor severities still create alerts.")
        anomaly_threshold = st.slider("Minimum anomaly score for an AI alert", 20, 95, max(20, values["ai_anomaly_min_score"]), 5, help="Sets the cutoff for metadata fallback scoring and filters weaker AI anomaly alerts.")
        saved = st.form_submit_button("Save detection settings")
    if saved:
        save_detection_settings(endpoint_threshold, anomaly_threshold)
        audit_event("detection_settings_updated", f"endpoint_min_risk={endpoint_threshold}; ai_min_score={anomaly_threshold}")
        st.success("Detection settings saved. New events will use these thresholds.")
        st.rerun()
    st.markdown("#### Current effect")
    st.write(f"Endpoint review alerts: risk score {values['endpoint_alert_min_risk']} or higher. High/Critical sensor alerts are always kept.")
    st.write(f"AI anomaly alert minimum: score {values['ai_anomaly_min_score']} or higher.")


def notify_security_alert(severity, title):
    """Show an in-app notification and email qualifying new alerts."""
    ranks = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    threshold = st.session_state.get("alert_notification_threshold", setting("ALERT_NOTIFY_MINIMUM", "High"))
    if ranks.get(str(severity), 0) < ranks.get(str(threshold), 3):
        return
    if st.session_state.get("in_app_notifications_enabled", True):
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


def send_security_email(subject, body, recipient_override=None):
    """Send email through a provider API or SMTP, using private settings."""
    recipient = str(recipient_override or setting("ALERT_EMAIL_TO")).strip()
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


def add_alert(title, severity, details, mitre_id="", source_event_id=None):
    alert_id = None
    grouped_alert = None
    dedupe_key = alert_fingerprint(title, severity)
    with connect_db() as connection:
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if source_event_id:
            if connection.execute("SELECT 1 FROM alerts WHERE source_event_id = ?", (source_event_id,)).fetchone():
                return False
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=alert_group_window_minutes())).isoformat(timespec="seconds")
        grouped_alert = connection.execute(
            "SELECT id, occurrence_count FROM alerts WHERE dedupe_key = ? AND status IN ('Open', 'Acknowledged') AND last_seen_at >= ? ORDER BY id DESC LIMIT 1",
            (dedupe_key, cutoff),
        ).fetchone()
        if grouped_alert:
            alert_id = int(grouped_alert[0])
            occurrence_count = int(grouped_alert[1] or 1) + 1
            connection.execute(
                "UPDATE alerts SET occurrence_count = ?, last_seen_at = ? WHERE id = ?",
                (occurrence_count, created_at, alert_id),
            )
        elif source_event_id:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO alerts
                   (created_at, title, severity, details, mitre_id, source_event_id, status, occurrence_count, last_seen_at, dedupe_key)
                   VALUES (?, ?, ?, ?, ?, ?, 'Open', 1, ?, ?)""",
                (created_at, title, severity, details, mitre_id, source_event_id, created_at, dedupe_key),
            )
            if cursor.rowcount == 0:
                return False
            alert_id = int(cursor.lastrowid)
        else:
            cursor = connection.execute(
                """INSERT INTO alerts
                   (created_at, title, severity, details, mitre_id, status, occurrence_count, last_seen_at, dedupe_key)
                   VALUES (?, ?, ?, ?, ?, 'Open', 1, ?, ?)""",
                (created_at, title, severity, details, mitre_id, created_at, dedupe_key),
            )
            alert_id = int(cursor.lastrowid)
    if grouped_alert:
        record_alert_timeline(alert_id, "Repeated alert grouped", f"Another matching signal was grouped into this alert. Occurrence count: {occurrence_count}.")
        audit_event("alert_occurrence_grouped", f"alert_id={alert_id}; occurrence_count={occurrence_count}")
        return False
    record_alert_timeline(alert_id, "Alert created", f"{severity}: {title}\n{details}")
    audit_event("alert_created", f"severity={severity}; title={title[:150]}")
    notify_security_alert(severity, title)
    return True


def load_alert_checklist(alert_id):
    """Create and load the standard investigation checklist for one alert."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with connect_db() as connection:
        connection.executemany(
            """INSERT OR IGNORE INTO alert_checklist
               (alert_id, item_key, label, completed, updated_at)
               VALUES (?, ?, ?, 0, ?)""",
            [(int(alert_id), key, label, now) for key, label in ALERT_CHECKLIST_ITEMS],
        )
        return pd.read_sql_query(
            "SELECT item_key, label, completed FROM alert_checklist "
            "WHERE alert_id = ? ORDER BY rowid",
            connection,
            params=(int(alert_id),),
        )


def save_alert_checklist(alert_id, checked_items):
    """Persist analyst checklist progress for one alert."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with connect_db() as connection:
        connection.executemany(
            """UPDATE alert_checklist SET completed = ?, updated_at = ?
               WHERE alert_id = ? AND item_key = ?""",
            [
                (int(bool(checked)), now, int(alert_id), item_key)
                for item_key, checked in checked_items.items()
            ],
        )
    completed = sum(bool(value) for value in checked_items.values())
    record_alert_timeline(
        alert_id,
        "Checklist updated",
        f"Investigation checklist saved: {completed}/{len(checked_items)} steps complete.",
    )


def load_custom_detection_rules(enabled_only=False):
    with connect_db() as connection:
        query = "SELECT * FROM custom_detection_rules"
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY id DESC"
        return pd.read_sql_query(query, connection)


def sync_custom_detection_rules(events):
    """Apply saved analyst rules to endpoint event metadata and create deduplicated alerts."""
    if events is None or events.empty:
        return 0
    rules = load_custom_detection_rules(enabled_only=True)
    if rules.empty:
        return 0
    suppressions = load_suppression_rules(active_only=True)
    inserted = 0
    for event in events.to_dict("records"):
        event_id = str(event.get("event_id") or event.get("event_uid") or event.get("id") or "").strip()
        if not event_id:
            continue
        event_type = str(event.get("event_type") or "").strip().casefold()
        process = str(event.get("process_name") or "").strip().casefold()
        remote_ip = str(event.get("remote_ip") or "").strip()
        file_name = str(event.get("file_name") or event.get("file_path") or "").strip()
        extension = Path(file_name).suffix.casefold()
        try:
            risk = int(float(event.get("risk_score") or 0))
        except (TypeError, ValueError):
            risk = 0
        try:
            if matching_suppression_rule(event, suppressions):
                continue
        except Exception:
            pass
        for rule in rules.to_dict("records"):
            conditions = [
                (not rule["event_type"] or event_type == str(rule["event_type"]).casefold()),
                (not rule["process_contains"] or str(rule["process_contains"]).casefold() in process),
                (not rule["remote_ip"] or remote_ip == str(rule["remote_ip"])),
                (not rule["file_extension"] or extension == str(rule["file_extension"]).casefold()),
                risk >= int(rule["min_risk"] or 0),
            ]
            if not all(conditions):
                continue
            configured_severity = str(rule["output_severity"] or "High").title()
            if configured_severity not in {"Medium", "High", "Critical"}:
                configured_severity = "High"
            details = [
                "Source: analyst-defined detection rule",
                f"Rule: {rule['name']}",
                f"Matched event: {event_type or 'unknown'}",
                f"Risk score: {risk}/100",
            ]
            for key, label in (("process_name", "Process"), ("remote_ip", "Remote IP"), ("file_name", "File"), ("summary", "Event")):
                value = str(event.get(key) or "").strip()
                if value:
                    details.append(f"{label}: {value[:300]}")
            source_key = f"custom-rule:{int(rule['id'])}:{event_id}"
            inserted += int(add_alert(
                f"Custom rule: {rule['name']}", configured_severity,
                "\n".join(details), source_event_id=source_key,
            ))
    if inserted:
        audit_event("custom_detection_alerts_created", f"count={inserted}")
    return inserted


def render_detection_rule_builder():
    render_page_heading("Custom Detection Rule Builder")
    st.write("Create metadata-based rules. Every condition you fill in must match; blank conditions are ignored.")
    if not require_admin():
        st.caption("Analysts can review saved rules; Admin access is required to create, toggle, or delete them.")
    else:
        with st.form("custom_detection_rule_form", clear_on_submit=True):
            name = st.text_input("Rule name", max_chars=100)
            col1, col2 = st.columns(2)
            with col1:
                event_type = st.text_input("Event type (exact, optional)", max_chars=50, placeholder="network_connection")
                process_contains = st.text_input("Process contains (optional)", max_chars=120, placeholder="powershell")
            with col2:
                remote_ip = st.text_input("Remote IP (exact, optional)", max_chars=64)
                file_extension = st.text_input("File extension (optional)", max_chars=16, placeholder=".exe")
            min_risk = st.slider("Minimum risk score", 0, 100, 0, 5)
            output_severity = st.selectbox("Alert severity", ["Medium", "High", "Critical"], index=1)
            submitted = st.form_submit_button("Save detection rule", type="primary")
        if submitted:
            clean_name = name.strip()
            event_type = event_type.strip()
            process_contains = process_contains.strip()
            remote_ip = remote_ip.strip()
            file_extension = file_extension.strip().casefold()
            try:
                if not clean_name or not any((event_type, process_contains, remote_ip, file_extension, min_risk > 0)):
                    raise ValueError("Add a rule name and at least one matching condition.")
                if remote_ip:
                    remote_ip = str(ipaddress.ip_address(remote_ip))
                if file_extension:
                    file_extension = file_extension if file_extension.startswith(".") else f".{file_extension}"
                    if not re.fullmatch(r"\.[a-z0-9]{1,12}", file_extension):
                        raise ValueError("Enter a file extension such as .exe or .ps1.")
                with connect_db() as connection:
                    connection.execute(
                        """INSERT INTO custom_detection_rules
                           (name, event_type, process_contains, remote_ip, file_extension, min_risk, output_severity, enabled, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                           ON CONFLICT(name) DO UPDATE SET event_type=excluded.event_type,
                           process_contains=excluded.process_contains, remote_ip=excluded.remote_ip,
                           file_extension=excluded.file_extension, min_risk=excluded.min_risk,
                           output_severity=excluded.output_severity, enabled=1""",
                        (clean_name, event_type, process_contains, remote_ip, file_extension, min_risk,
                         output_severity, datetime.now(timezone.utc).isoformat(timespec="seconds")),
                    )
                audit_event("custom_detection_rule_saved", f"name={clean_name[:100]}; severity={output_severity}")
                st.success("Rule saved. New matching endpoint events will create deduplicated alerts during alert refresh.")
                st.rerun()
            except (ValueError, sqlite3.IntegrityError) as error:
                st.error(str(error) or "Could not save this rule.")

    rules = load_custom_detection_rules()
    if rules.empty:
        st.info("No custom rules saved yet.")
        return
    display = rules.rename(columns={
        "name": "Rule", "event_type": "Event type", "process_contains": "Process contains",
        "remote_ip": "Remote IP", "file_extension": "Extension", "min_risk": "Min risk",
        "output_severity": "Alert severity", "enabled": "Enabled", "created_at": "Created (UTC)",
        "source": "Source",
    })
    display["Enabled"] = display["Enabled"].map({1: "Yes", 0: "No"})
    st.dataframe(display[["id", "Rule", "Event type", "Process contains", "Remote IP", "Extension", "Min risk", "Alert severity", "Source", "Enabled", "Created (UTC)"]], hide_index=True, width="stretch")
    if is_admin():
        selected = st.selectbox("Manage rule", rules["id"].astype(int).tolist(), format_func=lambda value: rules.loc[rules["id"].eq(value), "name"].iloc[0])
        first, second = st.columns(2)
        selected_rule = rules.loc[rules["id"].eq(selected)].iloc[0]
        if first.button("Disable rule" if int(selected_rule["enabled"]) else "Enable rule", key="toggle_custom_rule"):
            with connect_db() as connection:
                connection.execute("UPDATE custom_detection_rules SET enabled = ? WHERE id = ?", (0 if int(selected_rule["enabled"]) else 1, selected))
            audit_event("custom_detection_rule_toggled", f"id={selected}; enabled={not bool(selected_rule['enabled'])}")
            st.rerun()
        if second.button("Delete rule", key="delete_custom_rule"):
            with connect_db() as connection:
                connection.execute("DELETE FROM custom_detection_rules WHERE id = ?", (selected,))
            audit_event("custom_detection_rule_deleted", f"id={selected}")
            st.rerun()


def sync_endpoint_alerts(events):
    """Turn endpoint events into deduplicated alerts unless an active rule suppresses them."""
    if events is None or events.empty:
        return 0

    severity_map = {"Review": "Medium", "High": "High", "Critical": "Critical"}
    min_risk = get_detection_settings()["endpoint_alert_min_risk"]

    def value(event, key, default=""):
        result = event.get(key, default)
        if result is None or pd.isna(result):
            return default
        return str(result).strip()

    inserted = 0
    suppressed_count = 0
    rules = load_suppression_rules(active_only=True)
    for event in events.to_dict("records"):
        event_severity = value(event, "severity").title()
        if event_severity not in severity_map:
            continue
        try:
            event_risk = int(float(value(event, "risk_score", "0")))
        except (TypeError, ValueError):
            event_risk = 0
        if event_severity not in {"High", "Critical"} and event_risk < min_risk:
            continue
        event_id = value(event, "event_id") or value(event, "event_uid") or value(event, "id")
        if not event_id:
            continue
        rule = matching_suppression_rule(event, rules)
        if rule:
            suppressed_count += int(record_suppression_match(event_id, rule))
            continue
        summary = value(event, "summary", "Endpoint event needs review")
        event_type = value(event, "event_type", "endpoint_event")
        details = [
            "Source: Windows endpoint sensor",
            f"Event type: {event_type}",
            f"Risk score: {event_risk}/100",
            f"Signal: {summary}",
        ]
        for key, label in (("file_name", "File"), ("folder", "Folder"), ("process_name", "Process"), ("remote_ip", "Remote IP"), ("remote_port", "Remote port"), ("details", "Assessment")):
            item = value(event, key)
            if item:
                details.append(f"{label}: {item}")
        candidates = map_signal_to_mitre(" ".join([event_type, summary, *details]))
        mitre_id = candidates[0]["Technique ID"] if candidates else ""
        inserted += int(add_alert(
            f"Endpoint signal: {summary}", severity_map[event_severity], "\n".join(details),
            mitre_id=mitre_id, source_event_id=f"endpoint:{event_id}",
        ))
    if suppressed_count:
        audit_event("endpoint_events_suppressed", f"new_unique_events={suppressed_count}")
    return inserted + sync_custom_detection_rules(events)


def add_incident(title, severity, notes):
    with connect_db() as connection:
        cursor = connection.execute(
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
        incident_id = int(cursor.lastrowid)
    record_incident_timeline(incident_id, "Incident created", f"{severity}: {title}\n{notes}")
    return incident_id


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


@st.cache_data(ttl=3, show_spinner=False)
def load_cloud_sensor_heartbeats():
    """Read authenticated sensor heartbeats from the endpoint API."""
    api_url = setting("API_BASE_URL").rstrip("/")
    api_token = setting("API_TOKEN")
    if not api_url or not api_token:
        return [], "not_configured"
    response = requests.get(
        f"{api_url}/v1/sensors/status?limit=100",
        headers={"Authorization": f"Bearer {api_token}"},
        timeout=8,
    )
    response.raise_for_status()
    return response.json().get("sensors", []), "cloud"


def local_sensor_snapshot():
    """Read local event, upload-queue, and sensor-process timestamps when available."""
    snapshot = {"last_event_at": None, "event_count": 0, "pending_events": 0, "state": {}}
    if not DATABASE_PATH.exists():
        return snapshot
    try:
        with connect_db() as connection:
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if "endpoint_events" in tables:
                columns = {
                    row[1] for row in connection.execute(
                        "PRAGMA table_info(endpoint_events)"
                    ).fetchall()
                }
                pending_expression = (
                    "COALESCE(SUM(CASE WHEN synced = 0 THEN 1 ELSE 0 END), 0)"
                    if "synced" in columns
                    else "0"
                )
                row = connection.execute(
                    f"SELECT MAX(created_at), COUNT(*), {pending_expression} "
                    "FROM endpoint_events"
                ).fetchone()
                snapshot.update(
                    last_event_at=row[0],
                    event_count=int(row[1] or 0),
                    pending_events=int(row[2] or 0),
                )
            if "endpoint_sensor_state" in tables:
                snapshot["state"] = dict(connection.execute(
                    "SELECT key, value FROM endpoint_sensor_state"
                ).fetchall())
    except sqlite3.Error:
        pass
    return snapshot


def sensor_age_label(timestamp):
    if timestamp is None:
        return "Never"
    parsed = pd.to_datetime(timestamp, utc=True, errors="coerce")
    if pd.isna(parsed):
        return "Unknown"
    seconds = max(0, int((datetime.now(timezone.utc) - parsed.to_pydatetime()).total_seconds()))
    if seconds < 10:
        return "Just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def sensor_health_report(events, source):
    """Combine sensor liveness, last activity, and event-upload backlog."""
    if source == "cloud":
        try:
            sensors, status_source = load_cloud_sensor_heartbeats()
        except requests.RequestException as error:
            return {
                "status": "Heartbeat unavailable",
                "last_heartbeat": "Unknown",
                "last_event": "Unknown",
                "cloud_sync": "Unknown",
                "pending": "Unknown",
                "explanation": (
                    "The endpoint API could not provide sensor heartbeat status. "
                    "Check API availability and deploy the updated endpoint API. "
                    f"Details: {type(error).__name__}"
                ),
            }
        if status_source == "not_configured":
            return {
                "status": "API not configured",
                "last_heartbeat": "Unknown",
                "last_event": "Unknown",
                "cloud_sync": "Not configured",
                "pending": "Unknown",
                "explanation": "Set API_BASE_URL and API_TOKEN in the dashboard's private settings.",
            }
        if not sensors:
            last_event = None
            if events is not None and not events.empty:
                time_column = next((name for name in ("occurred_at", "created_at") if name in events), None)
                if time_column:
                    last_event = events[time_column].dropna().max()
            return {
                "status": "Waiting for heartbeat",
                "last_heartbeat": "Never",
                "last_event": sensor_age_label(last_event),
                "cloud_sync": "No sensor check-in",
                "pending": "Unknown",
                "explanation": "The API has no sensor heartbeat yet. Start the local sensor and update the deployed API if needed.",
            }

        latest = sensors[0]
        seen_at = latest.get("last_seen_at")
        parsed_seen = pd.to_datetime(seen_at, utc=True, errors="coerce")
        age_seconds = (
            max(0, (datetime.now(timezone.utc) - parsed_seen.to_pydatetime()).total_seconds())
            if not pd.isna(parsed_seen)
            else float("inf")
        )
        online = age_seconds <= 45
        pending_count = int(latest.get("pending_events", 0) or 0)
        last_event = latest.get("last_event_at")
        return {
            "status": "Online" if online else "Offline · stale heartbeat",
            "last_heartbeat": sensor_age_label(seen_at),
            "last_event": sensor_age_label(last_event),
            "cloud_sync": f"{pending_count} pending" if pending_count else ("Connected" if online else "Not confirmed"),
            "pending": str(pending_count),
            "explanation": (
                f"Sensor {latest.get('sensor_id', '')[:12]}… last checked in {sensor_age_label(seen_at)}. "
                "A quiet event stream alone does not mean the sensor stopped."
            ),
        }

    snapshot = local_sensor_snapshot()
    if os.name != "nt" and os.environ.get("CTI_DESKTOP_MODE") != "1":
        process_running = False
        status = "Laptop status unavailable"
        explanation = "A hosted dashboard cannot inspect the laptop process directly; it uses the sensor's cloud heartbeat."
    else:
        try:
            import psutil
            expected_script = os.path.normcase(os.path.abspath(BASE_DIR / "endpoint_monitor.py"))
            process_running = False
            for process in psutil.process_iter(["cmdline"]):
                try:
                    if any(
                        os.path.normcase(os.path.abspath(str(argument))) == expected_script
                        for argument in (process.info.get("cmdline") or [])
                    ):
                        process_running = True
                        break
                except (psutil.Error, OSError, TypeError, ValueError):
                    continue
            status = "Running" if process_running else "Stopped"
            explanation = (
                "The local sensor process is active."
                if process_running
                else "The local sensor process is not active. Start the desktop app to launch it."
            )
        except (ImportError, OSError):
            process_running = False
            status = "Status unavailable"
            explanation = "Process monitoring is unavailable on this computer."

    state = snapshot["state"]
    api_configured = state.get("cloud_sync_configured") == "1" or bool(
        setting("API_BASE_URL") and setting("API_TOKEN")
    )
    if not api_configured:
        cloud_sync = "Local only"
    elif snapshot["pending_events"]:
        cloud_sync = f"{snapshot['pending_events']} pending"
    elif state.get("last_cloud_checkin_at") and sensor_age_label(state["last_cloud_checkin_at"]) not in ("Never", "Unknown"):
        last_checkin = pd.to_datetime(state["last_cloud_checkin_at"], utc=True, errors="coerce")
        cloud_sync = "Connected" if not pd.isna(last_checkin) and (datetime.now(timezone.utc) - last_checkin.to_pydatetime()).total_seconds() <= 45 else "Stale"
    else:
        cloud_sync = "Awaiting first check-in"
    return {
        "status": status,
        "last_heartbeat": sensor_age_label(state.get("last_sensor_heartbeat_at")),
        "last_event": sensor_age_label(snapshot["last_event_at"]),
        "cloud_sync": cloud_sync,
        "pending": str(snapshot["pending_events"]),
        "explanation": explanation,
    }


def sync_sensor_health_alert(report, source):
    """Create one alert per sensor outage and resolve it after heartbeat recovery."""
    mode = "cloud" if source == "cloud" else "local"
    state_key = f"sensor_health_episode_{mode}"
    is_down = str(report.get("status", "")).lower().startswith(("offline", "stopped"))
    last_heartbeat = str(report.get("last_heartbeat", "Unknown"))
    has_seen_sensor = last_heartbeat not in {"Never", "Unknown", ""}
    with connect_db() as connection:
        state_row = connection.execute("SELECT value FROM app_state WHERE key = ?", (state_key,)).fetchone()
        episode = state_row[0] if state_row else ""
    if is_down and has_seen_sensor and episode != "open":
        details = (
            f"Sensor source: {mode}; current status: {report.get('status')}; "
            f"last heartbeat: {last_heartbeat}; last event: {report.get('last_event', 'Unknown')}; "
            f"cloud sync: {report.get('cloud_sync', 'Unknown')}. "
            "Check the sensor process, network connection, and pending upload queue."
        )
        episode_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        add_alert(
            f"Endpoint sensor is offline ({mode})", "High", details,
            source_event_id=f"sensor-health:{mode}:{episode_id}",
        )
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO app_state (key, value) VALUES (?, 'open') ON CONFLICT(key) DO UPDATE SET value='open'",
                (state_key,),
            )
        audit_event("sensor_health_outage_detected", f"source={mode}; last_heartbeat={last_heartbeat}")
    elif not is_down and episode == "open":
        prefix = f"sensor-health:{mode}:%"
        with connect_db() as connection:
            rows = connection.execute(
                "SELECT id, status FROM alerts WHERE source_event_id LIKE ? AND status IN ('Open', 'Acknowledged')",
                (prefix,),
            ).fetchall()
            connection.execute(
                "INSERT INTO app_state (key, value) VALUES (?, 'recovered') ON CONFLICT(key) DO UPDATE SET value='recovered'",
                (state_key,),
            )
            connection.executemany(
                "UPDATE alerts SET status = 'Resolved' WHERE id = ?",
                [(int(row[0]),) for row in rows],
            )
        for alert_id, _ in rows:
            record_alert_timeline(int(alert_id), "Sensor recovered", f"{mode.title()} sensor heartbeat is healthy again; alert resolved.")
        if rows:
            audit_event("sensor_health_recovered", f"source={mode}; resolved_alerts={len(rows)}")


@st.fragment(run_every="10s")
def render_sensor_health_cards(events, source):
    report = sensor_health_report(events, source)
    sync_sensor_health_alert(report, source)
    st.markdown("#### Sensor health and cloud sync")
    status_col, heartbeat_col, event_col, sync_col = st.columns(4)
    status_col.metric("Sensor", report["status"], help=report["explanation"])
    heartbeat_col.metric("Last heartbeat", report["last_heartbeat"])
    event_col.metric("Last event", report["last_event"])
    sync_col.metric("Cloud sync", report["cloud_sync"])
    st.caption(f"Sensor-reported upload queue: {report['pending']} event(s). {report['explanation']}")


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
            update_alert_status(selected_id, "Acknowledged")
            st.rerun()


@st.cache_data(ttl=900, show_spinner=False)
def load_feodo_feed():
    attempted_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        response = requests.get(
            FEODO_FEED_URL,
            timeout=15,
            headers={"User-Agent": "Local-CTI/1.0"},
        )
        response.raise_for_status()
    except requests.RequestException as error:
        save_app_state("threat_feed_last_attempt_at", attempted_at)
        save_app_state("threat_feed_last_error", f"{type(error).__name__}: {error}"[:500])
        raise
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
    save_app_state("threat_feed_last_success_at", attempted_at)
    save_app_state("threat_feed_last_attempt_at", attempted_at)
    save_app_state("threat_feed_indicator_count", len(feed))
    save_app_state("threat_feed_last_error", "")
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


def make_incident_evidence_zip(incident, alerts, timeline):
    """Package incident metadata, linked evidence records and their timelines."""
    incident_id = int(incident.get("id"))
    alert_ids = [int(value) for value in alerts.get("id", pd.Series(dtype=int)).dropna().tolist()] if alerts is not None and not alerts.empty else []
    timeline_parts = []
    if alert_ids:
        with connect_db() as connection:
            for alert_id in alert_ids:
                rows = pd.read_sql_query(
                    "SELECT alert_id, occurred_at, event_type, actor, note FROM alert_timeline WHERE alert_id = ? ORDER BY occurred_at, id",
                    connection, params=(alert_id,),
                )
                if not rows.empty:
                    timeline_parts.append(rows)
    alert_timeline = pd.concat(timeline_parts, ignore_index=True) if timeline_parts else pd.DataFrame(columns=["alert_id", "occurred_at", "event_type", "actor", "note"])
    ioc_matches = alerts[alerts.get("title", pd.Series(index=alerts.index, dtype=str)).astype(str).str.startswith("Watchlist match:")].copy() if alerts is not None and not alerts.empty else pd.DataFrame()
    log_findings = alerts[alerts.get("title", pd.Series(index=alerts.index, dtype=str)).astype(str).str.startswith("Log finding:")].copy() if alerts is not None and not alerts.empty else pd.DataFrame()
    manifest = (
        "AI Cyber Threat Intelligence — Incident Evidence Bundle\n"
        f"Incident ID: {incident_id}\n"
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
        "Contents: incident.json, linked_alerts.csv, incident_timeline.csv, alert_timelines.csv, ioc_matches.csv, log_findings.csv.\n"
        "Original uploaded log files are not retained by the application and are not included. Log finding alert records contain the saved reason and limited excerpt.\n"
        "Indicators and automated correlations are investigation leads, not confirmed malware verdicts."
    )
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("manifest.txt", manifest)
        bundle.writestr("incident.json", json.dumps(incident.to_dict(), ensure_ascii=False, indent=2, default=str))
        bundle.writestr("linked_alerts.csv", alerts.to_csv(index=False).encode("utf-8-sig") if alerts is not None and not alerts.empty else b"id,title,severity,status\n")
        bundle.writestr("incident_timeline.csv", timeline.to_csv(index=False).encode("utf-8-sig") if timeline is not None and not timeline.empty else b"occurred_at,event_type,actor,note\n")
        bundle.writestr("alert_timelines.csv", alert_timeline.to_csv(index=False).encode("utf-8-sig"))
        bundle.writestr("ioc_matches.csv", ioc_matches.to_csv(index=False).encode("utf-8-sig"))
        bundle.writestr("log_findings.csv", log_findings.to_csv(index=False).encode("utf-8-sig"))
    return buffer.getvalue()


def make_incident_pdf(incident, alerts, timeline):
    from reportlab.lib import colors as pdf_colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.55*inch, leftMargin=0.55*inch, topMargin=0.55*inch, bottomMargin=0.55*inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="IncidentBody", parent=styles["BodyText"], fontSize=8, leading=11, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="IncidentTitle", parent=styles["Title"], fontSize=17, leading=21, textColor=pdf_colors.HexColor("#14213D")))
    safe = lambda value: escape(str(value or "").encode("latin-1", "replace").decode("latin-1")).replace("\n", "<br/>")
    story = [Paragraph("Incident Investigation Report", styles["IncidentTitle"]), Spacer(1, 10)]
    summary = [["Incident ID", "Title", "Severity", "Status", "Created (UTC)"], [str(incident.get("id", "")), safe(incident.get("title", "")), safe(incident.get("severity", "")), safe(incident.get("status", "")), safe(incident.get("created_at", ""))]]
    table = Table(summary, colWidths=[0.8*inch, 2.8*inch, 0.8*inch, 0.8*inch, 1.4*inch], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),pdf_colors.HexColor("#22577A")),("TEXTCOLOR",(0,0),(-1,0),pdf_colors.white),("GRID",(0,0),(-1,-1),0.4,pdf_colors.HexColor("#CCD6E0")),("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),5)]))
    story += [table, Spacer(1, 8), Paragraph("Incident notes", styles["Heading2"]), Paragraph(safe(incident.get("notes", "")) or "No notes recorded.", styles["IncidentBody"]), Spacer(1, 8), Paragraph("Linked alerts", styles["Heading2"])]
    alert_rows = [["ID", "Time", "Severity", "Status", "Title"]]
    for row in alerts.to_dict("records") if alerts is not None and not alerts.empty else []:
        alert_rows.append([str(row.get("id", "")), safe(row.get("created_at", "")), safe(row.get("severity", "")), safe(row.get("status", "")), safe(row.get("title", ""))])
    if len(alert_rows) == 1:
        alert_rows.append(["-", "-", "-", "-", "No linked alerts"])
    table = Table(alert_rows, colWidths=[0.4*inch, 1.3*inch, 0.7*inch, 0.8*inch, 3.4*inch], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),pdf_colors.HexColor("#22577A")),("TEXTCOLOR",(0,0),(-1,0),pdf_colors.white),("GRID",(0,0),(-1,-1),0.4,pdf_colors.HexColor("#CCD6E0")),("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),4)]))
    story += [table, Spacer(1, 8), Paragraph("Investigation timeline", styles["Heading2"])]
    timeline_rows = [["Time (UTC)", "Activity", "User", "Details"]]
    for row in timeline.to_dict("records") if timeline is not None and not timeline.empty else []:
        timeline_rows.append([safe(row.get("occurred_at", "")), safe(row.get("event_type", "")), safe(row.get("actor", "")), safe(row.get("note", ""))])
    if len(timeline_rows) == 1:
        timeline_rows.append(["-", "-", "-", "No investigation timeline recorded"])
    table = Table(timeline_rows, colWidths=[1.2*inch, 1.1*inch, 0.8*inch, 3.5*inch], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),pdf_colors.HexColor("#22577A")),("TEXTCOLOR",(0,0),(-1,0),pdf_colors.white),("GRID",(0,0),(-1,-1),0.4,pdf_colors.HexColor("#CCD6E0")),("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),4)]))
    story.append(table)
    document.build(story)
    return buffer.getvalue()


def build_shift_handover_brief(events, alerts, incidents, event_source):
    """Build a factual, exportable shift summary and bounded AI-review payload."""
    now = datetime.now(timezone.utc)
    active = alerts[alerts["status"].isin(["Open", "Acknowledged"])].copy() if not alerts.empty else alerts
    open_incidents = incidents[incidents.get("status", pd.Series(dtype=str)).astype(str).str.casefold().eq("open")] if not incidents.empty else incidents
    severity_counts = {
        severity: int(active["severity"].astype(str).str.casefold().eq(severity.casefold()).sum())
        if not active.empty and "severity" in active else 0
        for severity in ("Critical", "High", "Medium", "Low")
    }
    if not active.empty and "assigned_to" in active:
        unassigned_count = int(active["assigned_to"].fillna("").astype(str).str.strip().eq("").sum())
    else:
        unassigned_count = len(active)
    overdue_count = 0
    if not active.empty and "due_at" in active:
        due = pd.to_datetime(active["due_at"], errors="coerce", utc=True)
        overdue_count = int((due.notna() & due.lt(pd.Timestamp(now))).sum())

    risk_column = "AI risk score" if "AI risk score" in events else "risk_score"
    risk_values = pd.to_numeric(events.get(risk_column, pd.Series(0, index=events.index)), errors="coerce").fillna(0)
    high_risk_count = int(risk_values.ge(70).sum()) if not events.empty else 0
    event_type_counts = (
        events.get("event_type", pd.Series(dtype=str)).fillna("Unknown").astype(str).value_counts().head(8)
        if not events.empty else pd.Series(dtype=int)
    )
    sensor_report = sensor_health_report(events, event_source)

    priorities = []
    follow_ups = []
    if severity_counts["Critical"]:
        follow_ups.append(f"Review {severity_counts['Critical']} Critical active alert(s) first.")
    if overdue_count:
        follow_ups.append(f"Reassess {overdue_count} overdue alert(s) and update their investigation timelines.")
    if unassigned_count:
        follow_ups.append(f"Assign an owner to {unassigned_count} active alert(s) without an analyst.")
    if str(sensor_report.get("status", "")).casefold() not in {"online", "healthy"}:
        follow_ups.append(f"Check endpoint sensor status: {sensor_report.get('status', 'Unknown')}.")
    if high_risk_count:
        follow_ups.append(f"Validate {high_risk_count} high-risk event(s) in the current telemetry sample against their evidence.")
    if not follow_ups:
        follow_ups.append("No urgent follow-up was identified from the current snapshot; continue normal monitoring.")

    if not active.empty:
        priorities_frame = active.copy()
        priorities_frame["_priority"] = priorities_frame.get("severity", pd.Series("Low", index=priorities_frame.index)).astype(str).str.title().map(
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        ).fillna(4)
        sort_columns = ["_priority"] + (["created_at"] if "created_at" in priorities_frame else [])
        priorities_frame = priorities_frame.sort_values(sort_columns, ascending=[True, False][:len(sort_columns)]).head(5)
        for row in priorities_frame.to_dict("records"):
            priorities.append({
                "severity": str(row.get("severity") or "Unknown"),
                "status": str(row.get("status") or "Open"),
                "title": str(row.get("title") or "Untitled alert"),
                "assigned_to": str(row.get("assigned_to") or ""),
            })

    summary = {
        "generated_at_utc": now.isoformat(timespec="seconds"),
        "event_source": event_source,
        "sensor_status": sensor_report.get("status", "Unknown"),
        "recent_event_count": len(events),
        "high_risk_event_count": high_risk_count,
        "event_type_counts": [
            {"event_type": str(name), "count": int(count)}
            for name, count in event_type_counts.items()
        ],
        "active_alert_count": len(active),
        "active_alert_counts": severity_counts,
        "unassigned_alert_count": unassigned_count,
        "overdue_alert_count": overdue_count,
        "open_incident_count": len(open_incidents),
        "priority_alerts": priorities,
        "follow_up_items": follow_ups,
    }

    lines = [
        "### Shift snapshot",
        f"- Generated (UTC): {now.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Event source: {event_source}",
        f"- Sensor: {sensor_report.get('status', 'Unknown')} · last heartbeat {sensor_report.get('last_heartbeat', 'Unknown')} · cloud sync {sensor_report.get('cloud_sync', 'Unknown')}",
        f"- Events in the current {len(events)}-event sample: {high_risk_count} at AI/sensor risk 70 or higher",
        f"- Active alerts: {len(active)} (Critical {severity_counts['Critical']} · High {severity_counts['High']} · Medium {severity_counts['Medium']} · Low {severity_counts['Low']})",
        f"- Open incidents: {len(open_incidents)} · Unassigned alerts: {unassigned_count} · Overdue alerts: {overdue_count}",
        "",
        "### Priority alerts",
    ]
    if priorities:
        lines.extend(
            f"- **{item['severity']} / {item['status']}** — {item['title']} · {('Assigned' if item['assigned_to'] else 'Unassigned')}"
            for item in priorities
        )
    else:
        lines.append("- No active alerts in the current snapshot.")
    lines.extend(["", "### Recommended follow-ups"])
    lines.extend(f"- {item}" for item in follow_ups)
    lines.extend(["", "_This is a snapshot-based triage aid. Verify evidence and sensor coverage before handing over._"])
    return "\n".join(lines), summary


def render_shift_handover_brief(events, alerts, incidents, event_source):
    brief, raw_context = build_shift_handover_brief(events, alerts, incidents, event_source)
    payload = build_handover_context(raw_context)
    with st.expander("Shift handover brief", expanded=False):
        st.caption("A snapshot of live telemetry, active alerts, sensor health, incidents, and pending analyst follow-ups.")
        st.markdown(brief)
        st.download_button(
            "Download shift handover (.md)",
            data=brief.encode("utf-8"),
            file_name=f"soc_shift_handover_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            key="download_soc_shift_handover",
        )
    context_id = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    render_optional_ai_review(
        payload=payload,
        review_type="handover",
        key_suffix=context_id,
        disclosure=(
            "Only aggregate event/alert counts, sensor status, event types, and up to five short alert titles/statuses are sent after consent and a button click. "
            "File contents, full paths, file hashes, and analyst names are excluded. Alert titles can contain process or indicator labels. API usage may be billed."
        ),
    )


def explain_alert_priority(alert, now=None):
    """Explain a relative alert-triage score from recorded evidence only."""
    now = now or datetime.now(timezone.utc)
    severity = str(alert.get("severity") or "Low").title()
    baseline = {"Critical": 80, "High": 65, "Medium": 42, "Low": 22}.get(severity, 22)
    score = baseline
    reasons = [f"{severity} severity sets a {baseline}-point starting priority."]
    details = str(alert.get("details") or "")
    title = str(alert.get("title") or "")
    evidence = f"{title}\n{details}"
    risk_match = re.search(
        r"(?:combined\s+ai\s+risk\s+score|ai\s+risk\s+score|risk\s+score|sensor\s+risk)\D{0,16}(\d{1,3})(?:\s*/\s*100)?",
        evidence,
        flags=re.IGNORECASE,
    )
    if risk_match:
        risk_score = min(100, int(risk_match.group(1)))
        score = max(score, risk_score)
        reasons.append(f"Recorded risk score is {risk_score}/100.")

    lower_evidence = evidence.casefold()
    ioc_match = any(token in lower_evidence for token in (
        "threat-intel ioc", "threat-feed ioc", "threat-feed match", "ioc match: yes", "watchlist match",
    ))
    if ioc_match:
        score += 12
        reasons.append("Threat-intelligence or watchlist evidence is recorded (+12).")
    if alert.get("mitre_id"):
        score += 4
        reasons.append(f"A candidate ATT&CK technique is attached ({str(alert.get('mitre_id'))[:24]}).")

    try:
        occurrence_count = max(1, int(alert.get("occurrence_count", 1) or 1))
    except (TypeError, ValueError, OverflowError):
        occurrence_count = 1
    if occurrence_count > 1:
        repeat_points = min(12, (occurrence_count - 1) * 3)
        score += repeat_points
        reasons.append(f"The alert groups {occurrence_count} observations (+{repeat_points}).")

    due_at = pd.to_datetime(alert.get("due_at"), errors="coerce", utc=True)
    if pd.notna(due_at) and due_at.to_pydatetime() < now:
        score += 12
        reasons.append("The saved review deadline has passed (+12).")
    assigned_to = str(alert.get("assigned_to") or "").strip()
    if not assigned_to and severity in {"Critical", "High"}:
        score += 5
        reasons.append("No analyst is assigned to this high-severity alert (+5).")
    score = min(100, max(0, int(score)))

    if any(token in lower_evidence for token in ("sensor heartbeat", "sensor offline", "sensor health")):
        next_step = "Check the endpoint sensor heartbeat, process status, and pending upload queue before interpreting missing telemetry."
    elif any(token in lower_evidence for token in ("file_sha256", "sha-256", "file_created", "file_modified", "file hash")):
        next_step = "Verify the file origin and signer locally, then check its hash with an approved reputation source. Do not upload file contents."
    elif any(token in lower_evidence for token in ("remote ip", "remote_ip", "network_connection", "connection", "threat-feed")):
        next_step = "Validate the destination IP/port and owning process, check the indicator in IOC Analysis, and compare nearby events from the same sensor."
    elif any(token in lower_evidence for token in ("process_started", "process name", "process_name", "application_installed")):
        next_step = "Verify the process publisher, parent process, and expected install location; review nearby file and network events."
    else:
        next_step = "Review the saved evidence and nearby same-sensor events, then record the analyst's finding in the investigation timeline."
    return {"score": score, "reasons": reasons, "next_step": next_step, "risk_score": int(risk_match.group(1)) if risk_match else None}


def render_alert_priority_explainer(active_alerts):
    if active_alerts.empty:
        return
    st.markdown("#### Explainable alert priority")
    st.caption("Select an active alert to see why it ranks highly and the next safe verification step.")
    options = {
        f"#{int(row['id'])} · {str(row.get('severity', 'Unknown'))} · {str(row.get('title', 'Untitled alert'))[:90]}": index
        for index, row in active_alerts.iterrows()
    }
    selected_label = st.selectbox(
        "Alert to explain",
        list(options),
        key="dashboard_priority_explainer_alert",
        label_visibility="collapsed",
    )
    selected_alert = active_alerts.loc[options[selected_label]].to_dict()
    explanation = explain_alert_priority(selected_alert)
    score_col, reasons_col = st.columns([0.35, 0.65])
    with score_col:
        st.metric("Triage index", f"{explanation['score']}/100", str(selected_alert.get("severity", "Unknown")))
    with reasons_col:
        st.markdown("**Why it ranks here**")
        for reason in explanation["reasons"]:
            st.markdown(f"- {reason}")
    st.info("**Suggested verification:** " + explanation["next_step"])
    st.caption("The triage index is a transparent prioritization aid, not a probability of compromise or an automated verdict.")


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
    active_alerts = alerts[alerts["status"].isin(["Open", "Acknowledged"])].copy() if not alerts.empty else alerts
    open_alerts = int((active_alerts["status"] == "Open").sum()) if not active_alerts.empty else 0
    critical = int((active_alerts["severity"].astype(str).str.casefold() == "critical").sum()) if not active_alerts.empty and "severity" in active_alerts else 0
    open_incidents = int((incidents["status"] == "Open").sum()) if not incidents.empty else 0

    st.markdown(
        """
        <div class="cti-page-heading">
          <div>
            <div class="cti-eyebrow">SOC / analyst workstation</div>
            <h1>Security operations desk</h1>
            <p>Monitor sensor health, triage the active alert queue, and move investigations forward.</p>
          </div>
          <div class="cti-status"><span class="cti-dot"></span> SHIFT ACTIVE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="cti-workbench-rail">
          <span><b class="cti-rail-live"></b>{str(event_source).upper()} EVENT STREAM</span>
          <span>OPERATOR: {str(st.session_state.get('user_role', 'Analyst')).upper()}</span>
          <span>CONSOLE TIME: {datetime.now().astimezone().strftime('%H:%M:%S')}</span>
          <span>ACTIVE QUEUE: {len(active_alerts)}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="cti-hero">
          <div>
            <div class="cti-eyebrow">Current shift / operational picture</div>
            <h2>Investigate the strongest signals first</h2>
            <p>Use correlated telemetry and alert evidence to validate activity, assign ownership, and document each decision.</p>
          </div>
          <div class="cti-hero-mark">⌖</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Endpoint events", len(endpoint_events), help="Recent events available to this dashboard.")
    col2.metric("Open alerts", open_alerts)
    col3.metric("Critical queue", critical)
    col4.metric("Open incidents", open_incidents)

    @st.fragment(run_every="5s")
    def sensor_health_tile():
        try:
            latest_events, latest_source = load_sensor_events(limit=500)
            render_sensor_health_cards(latest_events, latest_source)
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
                st.bar_chart(counts, color="#56D9CF")
        with right:
            with st.container(border=True):
                st.subheader("Attack categories")
                if "predicted_category" in report.columns:
                    st.bar_chart(report["predicted_category"].value_counts().head(8), color="#3D83B6")
                else:
                    st.info("Attack-category predictions are not available in this report.")

    left, right = st.columns([1.15, 0.85], gap="large")
    with left:
        with st.container(border=True):
            st.subheader("Priority alert queue")
            st.caption("Open and acknowledged alerts, ordered by severity for analyst triage.")
            if active_alerts.empty:
                st.success("Queue clear. No open or acknowledged alerts.")
            else:
                priority = active_alerts.copy()
                priority["_priority"] = priority["severity"].astype(str).str.title().map(
                    {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
                ).fillna(4)
                sort_columns = ["_priority"] + (["created_at"] if "created_at" in priority else [])
                priority = priority.sort_values(sort_columns, ascending=[True, False][:len(sort_columns)]).head(8)
                queue_columns = [name for name in ("created_at", "title", "severity", "status", "assigned_to") if name in priority]
                st.dataframe(priority[queue_columns], hide_index=True, width="stretch")
                render_alert_priority_explainer(priority)
    with right:
        with st.container(border=True):
            st.subheader("Network sensor console")
            if live:
                a, b = st.columns(2)
                a.metric("Packets captured", live["packets"])
                b.metric("Packets / second", live["packets_per_second"])
                st.caption(f"Unique destination ports: {len(live['destination_ports'])}")
            else:
                st.info("No capture summary yet. Start a capture from Live Monitor.")

            render_dashboard_alert_inbox()

    with st.container(border=True):
        st.subheader("Latest endpoint telemetry")
        st.caption("Source: deployed API" if event_source == "cloud" else "Source: this computer")
        if endpoint_events.empty:
            st.info("No endpoint events yet. Start the local sensor to begin collecting events.")
        else:
            recent = endpoint_events.head(10).copy()
            if "created_at" in recent.columns and "occurred_at" not in recent.columns:
                recent = recent.rename(columns={"created_at": "occurred_at"})
            columns = [name for name in ("occurred_at", "sensor_id", "event_type", "severity", "summary", "risk_score") if name in recent]
            st.dataframe(recent[columns], hide_index=True, width="stretch")

    render_shift_handover_brief(endpoint_events, alerts, incidents, event_source)


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
            load_cloud_sensor_heartbeats.clear()
            st.rerun()

        st.caption("Event source: " + ("deployed API" if source == "cloud" else "this computer") + " · Auto-refresh: 5 sec")
        render_sensor_health_cards(events, source)
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
    ioc_type = st.selectbox(
        "Indicator type",
        ["IP address", "Domain", "File hash (MD5 / SHA-1 / SHA-256)"],
    )
    placeholder = {
        "IP address": "203.0.113.10",
        "Domain": "example.org",
        "File hash (MD5 / SHA-1 / SHA-256)": "Paste a file hash; do not upload the file",
    }[ioc_type]
    ioc_text = st.text_input("Indicator", placeholder=placeholder)
    vt_key = setting("VT_API_KEY")
    abuseipdb_key = setting("ABUSEIPDB_API_KEY")
    available_sources = []
    if vt_key:
        available_sources.append("VirusTotal")
    if ioc_type == "IP address":
        if abuseipdb_key:
            available_sources.append("AbuseIPDB")
        available_sources.append("Feodo Tracker")
    st.caption(
        "Add VT_API_KEY and/or ABUSEIPDB_API_KEY to the app's private Secrets to enable those lookups. "
        "Only sources selected below receive the indicator when you press Check IOC; file contents are never uploaded."
    )
    if "VirusTotal" in available_sources:
        st.warning(
            "VirusTotal may add queried indicators to its shared dataset. Do not check confidential, "
            "sensitive, or personally identifying indicators there."
        )
    if ioc_type != "IP address" and not vt_key:
        st.info("VirusTotal is the supported reputation source for domains and hashes. Add VT_API_KEY to private Secrets to enable it.")
    selected_sources = st.multiselect(
        "Reputation sources",
        available_sources,
        default=available_sources,
        key=f"ioc_sources_{ioc_type}",
        help="Choose which providers receive this indicator. Feodo Tracker compares IPs against its public feed.",
    )
    if st.button("Check IOC", type="primary"):
        try:
            value = ioc_text.strip()
            if not value:
                st.error("Enter an indicator first.")
                return
            if not selected_sources:
                st.error("Select at least one available reputation source.")
                return
            if ioc_type == "IP address":
                address = ipaddress.ip_address(value)
                normalized = str(address)
                endpoint = "ip_addresses"
            else:
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
            for source in selected_sources:
                try:
                    if (
                        ioc_type == "IP address"
                        and source in {"VirusTotal", "AbuseIPDB"}
                        and not address.is_global
                    ):
                        st.warning(f"This IP is not globally routable, so it was not sent to {source}.")
                        continue
                    if source == "VirusTotal":
                        result = query_virustotal(endpoint, normalized, vt_key)
                        show_virustotal_result(result, normalized)
                    elif source == "AbuseIPDB":
                        result = query_abuseipdb(normalized, abuseipdb_key)
                        show_abuseipdb_result(result, normalized)
                    elif source == "Feodo Tracker":
                        if address.version != 4:
                            st.info("Feodo Tracker supports IPv4 only; no lookup was made for this IPv6 address.")
                            continue
                        feed = load_feodo_feed()
                        matches = feed[feed["dst_ip"] == normalized] if not feed.empty else pd.DataFrame()
                        if matches.empty:
                            st.success("No match for this IP was found in the current Feodo Tracker feed.")
                        else:
                            st.error("Feodo Tracker match found. Review this indicator before taking action.")
                            st.dataframe(matches, hide_index=True, width="stretch")
                            add_alert(
                                "IOC match from manual analysis",
                                "High",
                                f"IPv4 {normalized} matched {len(matches)} Feodo Tracker record(s).",
                                source_event_id=f"ioc:feodo:{normalized}",
                            )
                except requests.HTTPError as error:
                    status_code = error.response.status_code if error.response is not None else "unknown"
                    if status_code == 401 or status_code == 403:
                        st.error(f"{source} rejected its API key or account access (HTTP {status_code}). Check its private secret.")
                    elif status_code == 429:
                        st.warning(f"{source} rate limit reached. Try again later.")
                    else:
                        st.error(f"{source} lookup failed (HTTP {status_code}).")
                except requests.RequestException as error:
                    st.error(f"{source} could not be reached: {error}")
                except (KeyError, TypeError, ValueError) as error:
                    st.error(f"{source} returned an unreadable result: {error}")
            audit_event("ioc_lookup", f"type={ioc_type}; indicator={normalized}")
        except ValueError:
            if ioc_type == "IP address":
                st.error("Enter a valid IP address.")
            else:
                st.error("The indicator format is invalid.")
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


def query_abuseipdb(indicator, api_key):
    response = requests.get(
        ABUSEIPDB_CHECK_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": indicator, "maxAgeInDays": 90},
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("data", {})


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
        add_alert(
            "Threat-intelligence IOC reputation match",
            severity,
            f"Indicator: {indicator}\nMalicious detections: {malicious}\nSuspicious detections: {suspicious}\nSource: VirusTotal reputation API",
            source_event_id=f"ioc:virustotal:{indicator}",
        )
    else:
        st.success("No malicious or suspicious detections were returned. This does not prove the indicator is safe.")


def show_abuseipdb_result(result, indicator):
    confidence = int(result.get("abuseConfidenceScore", 0) or 0)
    reports = int(result.get("totalReports", 0) or 0)
    reporters = int(result.get("numDistinctUsers", 0) or 0)
    columns = st.columns(4)
    columns[0].metric("Abuse confidence", f"{confidence}%")
    columns[1].metric("Reports", reports)
    columns[2].metric("Distinct reporters", reporters)
    columns[3].metric("Country", result.get("countryCode") or "Unknown")
    st.caption(
        f"AbuseIPDB checked {indicator}. Usage: {result.get('usageType') or 'Unknown'} · "
        f"ISP: {result.get('isp') or 'Unknown'} · Last reported: {result.get('lastReportedAt') or 'Unknown'}. "
        "A reputation score is a lead for review, not proof of compromise."
    )
    if confidence >= 50:
        severity = "Critical" if confidence >= 90 else "High" if confidence >= 75 else "Medium"
        st.warning("AbuseIPDB reports a meaningful abuse confidence score. Validate recency and context before responding.")
        add_alert(
            "AbuseIPDB IOC reputation match",
            severity,
            f"Indicator: {indicator}\nAbuse confidence: {confidence}%\nTotal reports: {reports}\nDistinct reporters: {reporters}\nLast reported: {result.get('lastReportedAt') or 'Unknown'}\nSource: AbuseIPDB",
            source_event_id=f"ioc:abuseipdb:{indicator}",
        )
    else:
        st.success("AbuseIPDB returned a low confidence score. This does not prove the indicator is safe.")


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


def ai_event_identity(event):
    for key in ("event_id", "event_uid", "id"):
        value = event.get(key)
        if value is not None and not pd.isna(value) and str(value).strip():
            return str(value).strip()
    return ""


def ai_event_fingerprint(sensor_id, event_type, process_name):
    raw = "|".join((str(sensor_id).casefold(), str(event_type).casefold(), str(process_name).casefold()))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def apply_device_baselines(events):
    """Score novel activity against each sensor's unique-event history, with analyst feedback."""
    frame = events.copy()
    if frame.empty:
        frame["Device baseline score"] = pd.Series(dtype=int)
        frame["Device baseline reason"] = pd.Series(dtype=str)
        frame["Baseline sample count"] = pd.Series(dtype=int)
        return frame
    time_column = next((column for column in ("occurred_at", "created_at") if column in frame), None)
    parsed_times = pd.to_datetime(frame[time_column], errors="coerce", utc=True) if time_column else pd.Series(pd.NaT, index=frame.index)
    order = parsed_times.sort_values(kind="stable", na_position="last").index
    output = {}
    prepared = {}
    for index in order:
        row = frame.loc[index].to_dict()
        def text_value(value, default=""):
            return default if value is None or pd.isna(value) else str(value).strip()
        sensor_id = text_value(row.get("sensor_id"), "Local sensor") or "Local sensor"
        event_type = text_value(row.get("event_type"), "unknown").casefold() or "unknown"
        process_name = text_value(row.get("process_name")).casefold()
        event_id = ai_event_identity(row)
        timestamp = parsed_times.loc[index]
        occurred_at = timestamp.isoformat() if not pd.isna(timestamp) else datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not event_id:
            event_id = hashlib.sha256(f"{sensor_id}|{event_type}|{process_name}|{occurred_at}|{index}".encode("utf-8")).hexdigest()
        try:
            risk = max(0, min(100, int(float(row.get("risk_score") or 0))))
        except (TypeError, ValueError):
            risk = 0
        prepared[index] = (sensor_id, event_id, event_type, process_name, risk, occurred_at)
    with connect_db() as connection:
        identities = list({(value[0], value[1]) for value in prepared.values()})
        existing_rows = {}
        for start in range(0, len(identities), 400):
            chunk = identities[start:start + 400]
            if not chunk:
                continue
            placeholders = ",".join("(?, ?)" for _ in chunk)
            parameters = [item for pair in chunk for item in pair]
            rows = connection.execute(
                f"SELECT sensor_id, event_id, baseline_score, baseline_reason, sample_count FROM ai_baseline_events WHERE (sensor_id, event_id) IN ({placeholders})",
                parameters,
            ).fetchall()
            existing_rows.update({(row[0], row[1]): (row[2], row[3], row[4]) for row in rows})
        for index in order:
            sensor_id, event_id, event_type, process_name, risk, occurred_at = prepared[index]
            existing = existing_rows.get((sensor_id, event_id))
            if existing:
                output[index] = (int(existing[0]), str(existing[1]), int(existing[2]))
                continue

            prior = connection.execute(
                """SELECT COUNT(*),
                          SUM(CASE WHEN event_type = ? THEN 1 ELSE 0 END),
                          SUM(CASE WHEN process_name = ? AND process_name <> '' THEN 1 ELSE 0 END),
                          AVG(risk_score), AVG(risk_score * risk_score)
                   FROM ai_baseline_events WHERE sensor_id = ? AND occurred_at < ?""",
                (event_type, process_name, sensor_id, occurred_at),
            ).fetchone()
            sample_count = int(prior[0] or 0)
            event_type_count = int(prior[1] or 0)
            process_count = int(prior[2] or 0)
            mean_risk = float(prior[3] or 0)
            variance = max(0.0, float(prior[4] or 0) - mean_risk * mean_risk)
            score = 0
            reasons = []
            if sample_count >= 20:
                if event_type_count == 0:
                    score += 30
                    reasons.append("New event type for this device")
                if process_name and process_count == 0:
                    score += 35
                    reasons.append("New process for this device")
                if risk >= mean_risk + max(25, 2 * variance ** 0.5):
                    score += 35
                    reasons.append(f"Risk {risk} is above this device's usual level ({mean_risk:.0f})")
            fingerprint = ai_event_fingerprint(sensor_id, event_type, process_name)
            feedback = connection.execute(
                "SELECT verdict FROM ai_analyst_feedback WHERE fingerprint = ? ORDER BY updated_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if feedback and feedback[0] == "Confirmed threat":
                score = min(100, score + 25)
                reasons.append("Analyst previously confirmed this device/process pattern")
            elif feedback and feedback[0] == "Benign":
                score = round(score * 0.25)
                reasons.append("Analyst previously marked this device/process pattern benign")
            reason = "; ".join(reasons) if reasons else (
                f"Building this device's baseline ({sample_count}/20 events)" if sample_count < 20
                else "No meaningful deviation from this device's baseline"
            )
            connection.execute(
                """INSERT OR IGNORE INTO ai_baseline_events
                   (sensor_id, event_id, event_type, process_name, risk_score, occurred_at, baseline_score, baseline_reason, sample_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (sensor_id, event_id, event_type, process_name, risk, occurred_at, score, reason, sample_count),
            )
            output[index] = (score, reason, sample_count)
        connection.execute(
            "DELETE FROM ai_baseline_events WHERE rowid NOT IN (SELECT rowid FROM ai_baseline_events ORDER BY occurred_at DESC LIMIT 20000)"
        )
    frame["Device baseline score"] = pd.Series({index: value[0] for index, value in output.items()}).reindex(frame.index).fillna(0).astype(int)
    frame["Device baseline reason"] = pd.Series({index: value[1] for index, value in output.items()}).reindex(frame.index).fillna("No device baseline available")
    frame["Baseline sample count"] = pd.Series({index: value[2] for index, value in output.items()}).reindex(frame.index).fillna(0).astype(int)
    return frame


def live_event_features(events):
    """Build numeric, metadata-only features for the rolling endpoint model."""
    frame = pd.DataFrame(index=events.index)
    risk = pd.to_numeric(events.get("risk_score", pd.Series(0, index=events.index)), errors="coerce")
    frame["sensor_risk"] = risk.fillna(0).clip(0, 100)
    frame["device_baseline_score"] = pd.to_numeric(events.get("Device baseline score", pd.Series(0, index=events.index)), errors="coerce").fillna(0).clip(0, 100)

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
    events = apply_device_baselines(events)
    features = live_event_features(events)
    anomaly_cutoff = get_detection_settings()["ai_anomaly_min_score"]
    device_scores = pd.to_numeric(events.get("Device baseline score", pd.Series(0, index=events.index)), errors="coerce").fillna(0).clip(0, 100).astype(int)
    if len(events) >= model_minimum:
        if SKLEARN_AVAILABLE:
            model = IsolationForest(n_estimators=40, contamination="auto", random_state=42, n_jobs=1)
            predictions = model.fit_predict(features)
            decision = model.decision_function(features)
            global_scores = (pd.Series(-decision, index=events.index).rank(pct=True) * 100).round().astype(int)
            events["AI anomaly score"] = pd.concat([global_scores.rename("rolling"), device_scores.rename("device")], axis=1).max(axis=1).astype(int)
            events["AI anomaly"] = ((predictions == -1) & global_scores.ge(anomaly_cutoff)) | device_scores.ge(anomaly_cutoff)
            model_label = "Isolation Forest + per-device behavioral baseline"
        else:
            severity_points = features["severity_level"].map({0.0: 0, 1.0: 8, 2.0: 22, 3.0: 35}).fillna(0)
            rare_process = features["process_frequency"].le(1) & features["process_frequency"].gt(0)
            raw_score = (
                features["sensor_risk"] * 0.25
                + features["uncommon_remote_port"] * 30
                + rare_process.astype(int) * 20
                + features["ioc_match"] * 60
                + severity_points
                + features["device_baseline_score"] * 0.5
            ).clip(0, 100)
            events["AI anomaly score"] = pd.concat([raw_score.round().astype(int).rename("metadata"), device_scores.rename("device")], axis=1).max(axis=1).astype(int)
            events["AI anomaly"] = events["AI anomaly score"].ge(anomaly_cutoff)
            model_label = "Metadata anomaly rules + per-device behavioral baseline"
    else:
        events["AI anomaly"] = device_scores.ge(anomaly_cutoff)
        events["AI anomaly score"] = device_scores
        model_label = f"Per-device baseline active · global model collecting {len(events)}/{model_minimum} events"

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
            if int(device_scores.at[index]) >= anomaly_cutoff:
                signals.append(str(events.at[index, "Device baseline reason"]))
            if len(events) >= model_minimum:
                signals.append("Rolling anomaly model flagged this event")
        reasons.append("; ".join(signals) if signals else "No elevated signal in current metadata")
    events["AI indicators"] = reasons
    return events, model_label


def render_live_ai_toggle():
    api_key_configured = bool(setting("OPENAI_API_KEY"))
    default_enabled = api_key_configured
    enabled = st.checkbox(
        "Enable live OpenAI reviews",
        value=default_enabled,
        key="live_openai_reviews_enabled",
        disabled=not api_key_configured,
        help="Reviews only new High/Critical anomalies or threat-feed matches. Limited to one request per minute and 10 requests per hour.",
    )
    if api_key_configured:
        st.caption(
            "OpenAI receives allow-listed event metadata only (event type, scores, indicators, process name, and remote IP/port). "
            "File contents, full paths, and file hashes are excluded. API usage may be billed."
        )
    else:
        st.info("Configure OPENAI_API_KEY in this app's private settings to enable live OpenAI reviews.")
    return enabled


def render_live_ai_panel(show_assistant=False, live_openai_enabled=False):
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
    chains = detect_ai_attack_chains(events)
    chain_alerts = promote_ai_attack_chain_alerts(chains)
    drift = model_drift_summary(events)
    drift_alert_created = save_drift_alert(drift)
    live_ai_state = _queue_live_ai_review(events, live_openai_enabled)

    occurred_col = "occurred_at" if "occurred_at" in events else "created_at"
    latest = "Unavailable"
    if occurred_col in events and events[occurred_col].notna().any():
        latest = str(events[occurred_col].dropna().astype(str).max())
    st.caption(f"Source: {source} endpoint sensor · Updated {datetime.now().astimezone().strftime('%H:%M:%S')} · Latest event: {latest}")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Events in rolling window", len(events))
    c2.metric("AI anomalies", int(events["AI anomaly"].sum()))
    c3.metric("Threat-feed IOC matches", int(events["Threat-intel IOC"].sum()))
    c4.metric("Highest AI risk", f"{events['AI risk score'].max():.0f}/100")
    c5.metric("Attack chains", len(chains))
    st.caption(f"Live model: {model_label}. The anomaly score is a relative ranking within this window, not a malware probability or verdict.")
    if drift["status"] == "Review drift":
        st.warning("Model input drift needs review. " + drift["detail"])
        if drift_alert_created:
            st.caption("A model-drift review alert was added to Alert System.")
    elif drift["status"] == "Stable":
        st.caption(f"Model input health: {drift['status']} · drift score {drift['score']}/100 · {drift['detail']}")
    else:
        st.caption(f"Model input health: {drift['status']} · {drift['detail']}")
    _render_live_ai_review(live_openai_enabled, live_ai_state)

    display_columns = [column for column in [occurred_col, "event_type", "AI severity", "AI risk score", "AI anomaly", "AI anomaly score", "Device baseline score", "Device baseline reason", "AI indicators", "process_name", "remote_ip", "summary"] if column in events]
    st.dataframe(events[display_columns].head(50), hide_index=True, width="stretch")
    feedback = analyst_feedback_summary()
    feedback_counts = {str(row["verdict"]): int(row["count"]) for row in feedback.to_dict("records")}
    with st.expander("Analyst feedback learning"):
        st.caption("Saved labels adjust future device/process baseline scores. They are not used to retrain the UNSW model automatically.")
        feedback_metrics = st.columns(3)
        feedback_metrics[0].metric("Confirmed threats", feedback_counts.get("Confirmed threat", 0))
        feedback_metrics[1].metric("Benign", feedback_counts.get("Benign", 0))
        feedback_metrics[2].metric("Needs investigation", feedback_counts.get("Needs investigation", 0))
    if not chains.empty:
        st.subheader("Possible attack chains")
        st.caption("Same-device process, file, and network events grouped into a recent sequence. This is a review lead, not a confirmed attack.")
        chain_columns = ["Sensor", "Stages", "Events", "Risk score", "IOC match", "Processes", "Remote IPs", "Latest event (UTC)"]
        st.dataframe(chains[chain_columns], hide_index=True, width="stretch")
        if chain_alerts:
            st.success(f"Created {chain_alerts} new attack-chain review alert(s).")
    cross_sensor = detect_cross_sensor_correlations(events)
    st.subheader("Cross-sensor threat correlation")
    st.caption("Finds the same public IP or SHA-256 on multiple sensors. Shared public IPs are shown only when IOC-matched or risk is elevated. Matches are leads for review, not proof of compromise.")
    if cross_sensor.empty:
        st.info("No qualifying indicators are currently shared across multiple sensors. Connect another sensor or collect more endpoint events to use cross-sensor correlation.")
    else:
        display_correlations = cross_sensor.copy()
        display_correlations["Indicator"] = display_correlations.apply(
            lambda row: row["Indicator"] if row["Indicator type"] == "Public IP" else str(row["Indicator"])[:16] + "…",
            axis=1,
        )
        st.dataframe(display_correlations, hide_index=True, width="stretch")
        correlation_options = {
            f"{row['Indicator type']} · {row['Indicator'] if row['Indicator type'] == 'Public IP' else str(row['Indicator'])[:16] + '…'} · {row['Sensor count']} sensors": index
            for index, row in cross_sensor.iterrows()
        }
        selected_correlation = st.selectbox(
            "Select a correlation to investigate",
            list(correlation_options),
            key="ai_cross_sensor_candidate",
        )
        if st.button("Create investigation alert", key="ai_cross_sensor_create_alert"):
            created = create_cross_sensor_correlation_alert(
                cross_sensor.iloc[correlation_options[selected_correlation]].to_dict()
            )
            if created:
                st.success("Cross-sensor investigation alert created and added to the notification center.")
            else:
                st.info("A matching alert is already open or was previously recorded.")
    render_ai_rule_suggestions(events)
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
        st.subheader("Analyst feedback")
        render_analyst_feedback(selected.to_dict())
        event_context = build_event_context(selected.to_dict())
        mitre_signal = " ".join([event_context["event_type"], *event_context["rule_indicators"]])
        event_context["candidate_mitre_techniques"] = [
            {
                "technique_id": item["Technique ID"],
                "technique": item["Technique"],
                "mapping_rationale": item["Mapping rationale"],
            }
            for item in map_signal_to_mitre(mitre_signal)
        ][:8]
        event_context_id = hashlib.sha256(
            json.dumps(event_context, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()[:12]
        render_optional_ai_review(
            payload=event_context,
            review_type="event",
            key_suffix=event_context_id,
            disclosure=(
                "Only this event's type and timestamp, severity and risk scores, anomaly/IOC flags, "
                "rule-generated reasons, possible ATT&CK technique IDs/rationales, process name, and remote IP/port are sent after you check "
                "consent and click Generate. File contents, full paths, file hashes, and arbitrary "
                "event text are excluded. The request uses OpenAI's Responses API with storage disabled."
            ),
        )
    if len(events) < model_minimum:
        st.info("The live ML model starts after 20 endpoint events. Until then, the table shows sensor detections and IOC matches without inventing AI results.")


def create_ai_anomaly_alerts(events):
    """Promote model outliers into deduplicated analyst-review alerts."""
    if events is None or events.empty:
        return 0
    inserted = 0
    settings = get_detection_settings()
    rules = load_suppression_rules(active_only=True)
    for event in events.to_dict("records"):
        event_id = str(event.get("event_id") or event.get("event_uid") or event.get("id") or "").strip()
        if not event_id:
            continue
        rule = matching_suppression_rule(event, rules)
        if rule:
            record_suppression_match(event_id, rule)
            continue
        score = int(event.get("AI risk score", event.get("AI anomaly score", 0)) or 0)
        sensor_severity = str(event.get("severity") or "").title()
        if score < settings["endpoint_alert_min_risk"] or int(event.get("AI anomaly score", 0) or 0) < settings["ai_anomaly_min_score"]:
            continue
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
        inserted += int(add_alert(
            f"AI anomaly: {summary[:120]}", severity, details, mitre_id=mitre_id,
            source_event_id=f"ai-endpoint:{event_id}",
        ))
    return inserted


def detect_ai_attack_chains(events):
    """Find short, same-sensor process/file/network sequences for analyst review."""
    if events is None or events.empty or "event_type" not in events:
        return pd.DataFrame()
    data = events.copy()
    time_column = next((name for name in ("occurred_at", "created_at") if name in data), None)
    if not time_column:
        return pd.DataFrame()
    data["_chain_time"] = pd.to_datetime(data[time_column], errors="coerce", utc=True)
    data = data[data["_chain_time"].notna()].copy()
    if data.empty:
        return pd.DataFrame()
    data["_sensor"] = data.get("sensor_id", pd.Series("Local sensor", index=data.index)).fillna("Local sensor").astype(str)
    data["_kind"] = data["event_type"].fillna("").astype(str).map(
        lambda value: "process" if value.startswith("process_") else "file" if value.startswith("file_") else "network" if "network" in value or "connection" in value else "other"
    )
    data["_risk"] = pd.to_numeric(data.get("risk_score", pd.Series(0, index=data.index)), errors="coerce").fillna(0).clip(0, 100)
    now = pd.Timestamp.now(tz="UTC")
    rows = []
    for sensor_id, group in data.groupby("_sensor"):
        group = group[group["_chain_time"].ge(now - pd.Timedelta(minutes=15))].sort_values("_chain_time")
        stages = set(group["_kind"]) & {"process", "file", "network"}
        if len(stages) < 2 or group.empty:
            continue
        ioc = group.get("Threat-intel IOC", pd.Series(False, index=group.index)).fillna(False).astype(bool).any()
        max_risk = int(group["_risk"].max())
        if not (len(stages) == 3 or (max_risk >= 80 or ioc)):
            continue
        score = min(100, len(stages) * 20 + int(max_risk * 0.35) + (25 if ioc else 0))
        event_ids = [ai_event_identity(item) for item in group.to_dict("records")]
        event_ids = [value for value in event_ids if value]
        latest = group["_chain_time"].max()
        bucket = latest.floor("15min").isoformat()
        processes = sorted(set(group.get("process_name", pd.Series(dtype=str)).dropna().astype(str)) - {""})
        addresses = sorted(set(group.get("remote_ip", pd.Series(dtype=str)).dropna().astype(str)) - {""})
        summaries = group.get("summary", pd.Series("", index=group.index)).fillna("").astype(str).tolist()
        rows.append({
            "Sensor": sensor_id,
            "Stages": ", ".join(sorted(stages)),
            "Events": len(group),
            "Risk score": score,
            "Highest event risk": max_risk,
            "IOC match": bool(ioc),
            "Processes": ", ".join(processes[:6]),
            "Remote IPs": ", ".join(addresses[:6]),
            "Latest event (UTC)": latest.isoformat(),
            "Event IDs": event_ids,
            "Bucket": bucket,
            "Evidence": "; ".join(item for item in summaries if item)[:1200],
        })
    return pd.DataFrame(rows).sort_values("Risk score", ascending=False) if rows else pd.DataFrame()


def detect_cross_sensor_correlations(events):
    """Find high-signal public IP or SHA-256 indicators shared across sensors."""
    if events is None or events.empty or "sensor_id" not in events:
        return pd.DataFrame()
    data = events.copy()
    data["_sensor"] = data["sensor_id"].fillna("").astype(str).str.strip()
    data = data[data["_sensor"].ne("")].copy()
    if data.empty:
        return pd.DataFrame()
    risk_column = "AI risk score" if "AI risk score" in data else "risk_score"
    data["_risk"] = pd.to_numeric(data.get(risk_column, pd.Series(0, index=data.index)), errors="coerce").fillna(0).clip(0, 100)
    if "Threat-intel IOC" in data:
        data["_ioc"] = data["Threat-intel IOC"].map(
            lambda value: str(value).strip().lower() in {"1", "true", "yes"} if isinstance(value, str) else bool(value) if pd.notna(value) else False
        )
    else:
        data["_ioc"] = False
    time_column = next((name for name in ("occurred_at", "created_at") if name in data), None)
    data["_seen"] = pd.to_datetime(data[time_column], errors="coerce", utc=True) if time_column else pd.NaT
    candidates = []
    for column, indicator_type in (("remote_ip", "Public IP"), ("file_sha256", "SHA-256")):
        if column not in data:
            continue
        indicators = data[column].fillna("").astype(str).str.strip().str.lower()
        valid = []
        for value in indicators:
            try:
                if indicator_type == "Public IP":
                    valid.append(value if value and ipaddress.ip_address(value).is_global else "")
                else:
                    valid.append(value if re.fullmatch(r"[a-f0-9]{64}", value) else "")
            except ValueError:
                valid.append("")
        data["_indicator"] = valid
        grouped = data[data["_indicator"].ne("")].groupby("_indicator", sort=False)
        for indicator, group in grouped:
            sensor_ids = sorted(group["_sensor"].unique().tolist())
            if len(sensor_ids) < 2:
                continue
            ioc_match = bool(group["_ioc"].any())
            highest_risk = int(group["_risk"].max())
            # Avoid noisy shared infrastructure IPs; a multi-device IP must also
            # have an IOC match or elevated event risk. Exact file hashes are rarer.
            if indicator_type == "Public IP" and not ioc_match and highest_risk < 70:
                continue
            times = group["_seen"].dropna()
            event_types = sorted(group.get("event_type", pd.Series(dtype=str)).dropna().astype(str).unique().tolist())
            candidates.append({
                "Indicator type": indicator_type,
                "Indicator": indicator,
                "Sensor count": len(sensor_ids),
                "Sensors": ", ".join(sensor_ids[:8]),
                "Event count": len(group),
                "Highest AI risk": highest_risk,
                "IOC match": ioc_match,
                "Event types": ", ".join(event_types[:8]),
                "First seen (UTC)": times.min().isoformat() if not times.empty else "Unknown",
                "Last seen (UTC)": times.max().isoformat() if not times.empty else "Unknown",
            })
    if not candidates:
        return pd.DataFrame()
    return pd.DataFrame(candidates).sort_values(
        ["IOC match", "Highest AI risk", "Sensor count", "Event count"],
        ascending=[False, False, False, False],
    ).reset_index(drop=True)


def create_cross_sensor_correlation_alert(correlation):
    """Save one analyst-approved cross-sensor correlation as a review alert."""
    indicator_type = str(correlation.get("Indicator type", "indicator"))
    indicator = str(correlation.get("Indicator", ""))
    sensors = [item for item in str(correlation.get("Sensors", "")).split(", ") if item]
    if len(sensors) < 2 or not indicator:
        return False
    ioc_match = bool(correlation.get("IOC match", False))
    highest_risk = int(correlation.get("Highest AI risk", 0) or 0)
    severity = "High" if ioc_match or indicator_type == "SHA-256" or highest_risk >= 80 else "Medium"
    title_indicator = indicator if indicator_type == "Public IP" else indicator[:16] + "…"
    title = f"Cross-sensor {indicator_type} correlation: {title_indicator}"
    details = "\n".join([
        "Source: analyst-reviewed cross-sensor indicator correlation",
        f"Indicator type: {indicator_type}",
        f"Indicator: {indicator}",
        f"Sensors: {', '.join(sensors)}",
        f"Matching events: {int(correlation.get('Event count', 0) or 0)}",
        f"Highest AI risk: {highest_risk}/100",
        f"Threat-intelligence IOC match: {'yes' if ioc_match else 'no'}",
        f"Event types: {correlation.get('Event types', 'Unknown')}",
        f"First seen (UTC): {correlation.get('First seen (UTC)', 'Unknown')}",
        f"Last seen (UTC): {correlation.get('Last seen (UTC)', 'Unknown')}",
        "Correlation is an investigation lead; shared infrastructure or a repeated hash is not, by itself, proof of compromise.",
    ])
    latest = pd.to_datetime(correlation.get("Last seen (UTC)"), errors="coerce", utc=True)
    bucket = latest.floor("h").isoformat() if pd.notna(latest) else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
    digest = hashlib.sha256(f"{indicator_type}|{indicator}|{'|'.join(sensors)}|{bucket}".encode("utf-8")).hexdigest()[:32]
    return add_alert(title, severity, details, source_event_id=f"ai-cross-sensor:{digest}")


def promote_ai_attack_chain_alerts(chains):
    if chains is None or chains.empty:
        return 0
    inserted = 0
    for chain in chains.to_dict("records"):
        source_digest = hashlib.sha256(f"{chain['Sensor']}|{chain['Bucket']}".encode("utf-8")).hexdigest()[:32]
        details = "\n".join([
            "Source: explainable same-device event-sequence correlation",
            f"Sensor: {chain['Sensor']}",
            f"Observed stages: {chain['Stages']}",
            f"Event count: {chain['Events']}",
            f"Highest sensor risk: {chain['Highest event risk']}/100",
            f"IOC match: {'yes' if chain['IOC match'] else 'no'}",
            f"Processes: {chain['Processes'] or 'None recorded'}",
            f"Remote IPs: {chain['Remote IPs'] or 'None recorded'}",
            f"Event evidence: {chain['Evidence'] or 'No summary text recorded'}",
            "This sequence is an investigation lead, not a confirmed attack verdict.",
        ])
        severity = "Critical" if int(chain["Risk score"]) >= 90 else "High"
        mapped = map_signal_to_mitre(f"{chain['Stages']} {chain['Evidence']}")
        inserted += int(add_alert(
            f"Possible multi-stage activity: {chain['Sensor'][:40]}", severity, details,
            mitre_id=mapped[0]["Technique ID"] if mapped else "",
            source_event_id=f"ai-chain:{source_digest}",
        ))
    return inserted


def model_drift_summary(events):
    """Compare current event-type and risk distributions with earlier stored telemetry."""
    if events is None or events.empty or len(events) < 20:
        return {"status": "Collecting data", "score": None, "detail": "Need at least 20 current events and 50 earlier baseline events."}
    current = events.copy()
    time_column = next((name for name in ("occurred_at", "created_at") if name in current), None)
    if not time_column:
        return {"status": "Unavailable", "score": None, "detail": "Event timestamps are missing."}
    current["_time"] = pd.to_datetime(current[time_column], errors="coerce", utc=True)
    current = current[current["_time"].notna()].sort_values("_time").tail(100)
    if len(current) < 20:
        return {"status": "Collecting data", "score": None, "detail": "Need at least 20 timestamped current events."}
    current_ids = [ai_event_identity(row) for row in current.to_dict("records")]
    cutoff = current["_time"].min().isoformat()
    with connect_db() as connection:
        reference = pd.read_sql_query(
            "SELECT event_type, risk_score FROM ai_baseline_events WHERE occurred_at < ? ORDER BY occurred_at DESC LIMIT 1000",
            connection, params=(cutoff,),
        )
    if len(reference) < 50:
        return {"status": "Collecting data", "score": None, "detail": f"Earlier baseline: {len(reference)}/50 events. More unique telemetry is needed."}
    current_types = current.get("event_type", pd.Series("unknown", index=current.index)).fillna("unknown").astype(str).value_counts(normalize=True)
    reference_types = reference["event_type"].fillna("unknown").astype(str).value_counts(normalize=True)
    categories = set(current_types.index) | set(reference_types.index)
    epsilon = 0.0001
    type_psi = sum((current_types.get(category, 0.0) - reference_types.get(category, 0.0)) * math.log((current_types.get(category, 0.0) + epsilon) / (reference_types.get(category, 0.0) + epsilon)) for category in categories)
    current_risk = pd.to_numeric(current.get("risk_score", pd.Series(0, index=current.index)), errors="coerce").fillna(0)
    reference_risk = pd.to_numeric(reference["risk_score"], errors="coerce").fillna(0)
    reference_std = float(reference_risk.std(ddof=0))
    mean_shift = abs(float(current_risk.mean()) - float(reference_risk.mean()))
    risk_z = mean_shift / max(reference_std, 10.0)
    drift_score = round(max(min(type_psi / 0.5, 1.0), min(risk_z / 3, 1.0)) * 100)
    drifted = type_psi >= 0.25 or risk_z >= 2.0
    detail = f"Event-type PSI {type_psi:.3f}; sensor-risk mean shift {risk_z:.2f} baseline standard deviations; compared {len(current)} recent with {len(reference)} earlier events."
    return {"status": "Review drift" if drifted else "Stable", "score": drift_score, "detail": detail, "psi": type_psi, "risk_z": risk_z}


def save_drift_alert(summary):
    if summary.get("status") != "Review drift":
        return False
    today = datetime.now(timezone.utc).date().isoformat()
    return add_alert(
        "AI model input drift detected", "Medium",
        "The endpoint event distribution has changed compared with earlier observed telemetry. This may reflect a normal workload change or a sensor/configuration change. Review before changing model thresholds.\n" + str(summary.get("detail", "")),
        source_event_id=f"model-drift:{today}",
    )


def ai_rule_suggestions(events):
    """Mine repeated higher-risk patterns for disabled custom-rule drafts."""
    if events is None or events.empty or "event_type" not in events:
        return pd.DataFrame()
    frame = events.copy()
    frame["_risk"] = pd.to_numeric(frame.get("risk_score", pd.Series(0, index=frame.index)), errors="coerce").fillna(0)
    frame = frame[frame["_risk"].ge(60)].copy()
    if frame.empty:
        return pd.DataFrame()
    frame["event_type"] = frame["event_type"].fillna("").astype(str)
    frame["process_name"] = frame.get("process_name", pd.Series("", index=frame.index)).fillna("").astype(str)
    frame["remote_ip"] = frame.get("remote_ip", pd.Series("", index=frame.index)).fillna("").astype(str)
    suggestions = []
    for (event_type, process, remote_ip), group in frame.groupby(["event_type", "process_name", "remote_ip"], dropna=False):
        if len(group) < 3 or not (process or remote_ip):
            continue
        median_risk = int(group["_risk"].median())
        target = f"process {process}" if process else f"destination {remote_ip}"
        suggestions.append({
            "Rule name": f"AI suggestion: {event_type} / {target}"[:100],
            "Event type": event_type,
            "Process contains": process,
            "Remote IP": "" if process else remote_ip,
            "Minimum risk": max(40, min(median_risk, 95)),
            "Repeated events": len(group),
            "Highest risk": int(group["_risk"].max()),
            "Reason": f"{len(group)} events share this pattern and have risk scores of at least 60.",
        })
    return pd.DataFrame(suggestions).sort_values(["Repeated events", "Highest risk"], ascending=False).head(20) if suggestions else pd.DataFrame()


def render_ai_rule_suggestions(events):
    suggestions = ai_rule_suggestions(events)
    st.subheader("AI detection rule suggestions")
    st.caption("Local pattern mining highlights repeated higher-risk metadata. Suggestions are saved disabled; Admin review is required to enable a rule.")
    if suggestions.empty:
        st.info("No repeated high-risk pattern is strong enough to suggest a rule in this event window.")
        return
    st.dataframe(suggestions, hide_index=True, width="stretch")
    if not is_admin():
        st.caption("Ask an Admin to save a suggestion as a disabled draft.")
        return
    selected = st.selectbox("Suggestion to save", suggestions["Rule name"].tolist(), key="ai_rule_suggestion_selected")
    if st.button("Save as disabled rule draft", key="save_ai_rule_suggestion"):
        rule = suggestions[suggestions["Rule name"].eq(selected)].iloc[0]
        with connect_db() as connection:
            connection.execute(
                """INSERT INTO custom_detection_rules
                   (name, event_type, process_contains, remote_ip, file_extension, min_risk, output_severity, enabled, created_at, source)
                   VALUES (?, ?, ?, ?, '', ?, 'High', 0, ?, 'AI suggested')
                   ON CONFLICT(name) DO UPDATE SET event_type=excluded.event_type,
                   process_contains=excluded.process_contains, remote_ip=excluded.remote_ip,
                   min_risk=excluded.min_risk, enabled=0, source='AI suggested'""",
                (rule["Rule name"], rule["Event type"], rule["Process contains"], rule["Remote IP"],
                 int(rule["Minimum risk"]), datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
        audit_event("ai_detection_rule_draft_saved", f"name={selected[:100]}")
        st.success("Saved as a disabled draft. Review it in Custom Detection Rule Builder before enabling.")


def analyst_feedback_summary():
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT verdict, COUNT(*) AS count FROM ai_analyst_feedback GROUP BY verdict ORDER BY verdict",
            connection,
        )


def render_analyst_feedback(event):
    event_id = ai_event_identity(event)
    if not event_id:
        st.info("This event has no stable ID, so analyst feedback cannot be saved for it.")
        return
    sensor_id = str(event.get("sensor_id") or "Local sensor")
    event_type = str(event.get("event_type") or "unknown")
    process_name = str(event.get("process_name") or "")
    fingerprint = ai_event_fingerprint(sensor_id, event_type, process_name)
    with connect_db() as connection:
        saved = connection.execute("SELECT verdict, note FROM ai_analyst_feedback WHERE event_id = ?", (event_id,)).fetchone()
    verdicts = ["Needs investigation", "Confirmed threat", "Benign"]
    default_verdict = verdicts.index(saved[0]) if saved and saved[0] in verdicts else 0
    key = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:12]
    with st.form(f"ai_feedback_form_{key}"):
        verdict = st.selectbox("Analyst verdict", verdicts, index=default_verdict, key=f"ai_feedback_verdict_{key}")
        note = st.text_input("Short evidence note (optional)", value=saved[1] if saved else "", max_chars=500, key=f"ai_feedback_note_{key}")
        submitted = st.form_submit_button("Save AI feedback")
    if submitted:
        with connect_db() as connection:
            connection.execute(
                """INSERT INTO ai_analyst_feedback
                   (event_id, sensor_id, event_type, process_name, fingerprint, verdict, note, updated_by, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(event_id) DO UPDATE SET sensor_id=excluded.sensor_id, event_type=excluded.event_type,
                   process_name=excluded.process_name, fingerprint=excluded.fingerprint, verdict=excluded.verdict,
                   note=excluded.note, updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
                (event_id, sensor_id, event_type, process_name, fingerprint, verdict, note.strip(),
                 str(st.session_state.get("username", "analyst")), datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
        audit_event("ai_analyst_feedback_saved", f"event_id={event_id[:100]}; verdict={verdict}")
        st.success("Feedback saved. Confirmed/benign labels adjust future scores for the same device/process/event pattern.")
        st.rerun()


def render_ai_engine(report):
    render_page_heading("AI Engine")
    st.write("Live endpoint anomaly detection with bounded OpenAI analyst reviews for new high-risk events.")
    live_openai_enabled = render_live_ai_toggle()

    @st.fragment(run_every="5s")
    def live_panel():
        render_live_ai_panel(live_openai_enabled=live_openai_enabled)

    live_panel()
    render_ai_feedback_threshold_lab()
    with st.expander("Historical UNSW-NB15 model output"):
        st.write("This is a separate offline dataset report. It is not used to label live files or endpoint activity.")
        if report.empty:
            st.info("No historical threat_report.csv is available.")
        else:
            st.write(f"Historical report rows: {len(report)}")
            st.dataframe(report.head(10), hide_index=True, width="stretch")


def feedback_threshold_metrics(labeled_events):
    """Estimate alert-threshold precision/recall from analyst-labeled live events."""
    if labeled_events.empty:
        return pd.DataFrame()
    scores = pd.to_numeric(labeled_events["AI risk score"], errors="coerce").fillna(0)
    actual = labeled_events["verdict"].eq("Confirmed threat")
    rows = []
    for threshold in range(20, 96, 5):
        predicted = scores.ge(threshold)
        tp = int((predicted & actual).sum())
        fp = int((predicted & ~actual).sum())
        fn = int((~predicted & actual).sum())
        tn = int((~predicted & ~actual).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        rows.append({
            "Risk threshold": threshold,
            "Precision": precision,
            "Recall": recall,
            "F1": f1,
            "Alerts on labeled events": tp + fp,
            "Missed confirmed threats": fn,
            "True negatives": tn,
        })
    return pd.DataFrame(rows)


def render_ai_feedback_threshold_lab():
    st.subheader("AI Feedback Calibration Lab")
    st.caption(
        "Compare alert-risk cutoffs against endpoint events analysts marked Confirmed threat or Benign. "
        "This is a recent-window estimate, not a held-out accuracy claim or malware probability."
    )
    try:
        events, source = load_sensor_events(limit=2000)
        if events.empty:
            st.info("No endpoint events are available for calibration yet.")
            return
        scored, model_label = analyze_live_events(events)
        identity_column = next((name for name in ("event_id", "event_uid", "id") if name in scored), None)
        if not identity_column:
            st.info("These events do not include stable IDs, so they cannot be matched to analyst feedback.")
            return
        scored["_feedback_event_id"] = scored[identity_column].fillna("").astype(str)
        with connect_db() as connection:
            feedback = pd.read_sql_query(
                "SELECT event_id, verdict FROM ai_analyst_feedback WHERE verdict IN ('Confirmed threat', 'Benign')",
                connection,
            )
        labeled = scored.merge(feedback, left_on="_feedback_event_id", right_on="event_id", how="inner")
    except Exception as error:
        st.warning(f"Could not build the feedback calibration view: {error}")
        return

    if labeled.empty:
        st.info("Label events in Explainable AI Assistant to start collecting calibration data.")
        return

    counts = labeled["verdict"].value_counts()
    confirmed = int(counts.get("Confirmed threat", 0))
    benign = int(counts.get("Benign", 0))
    summary = st.columns(3)
    summary[0].metric("Labeled endpoint events", len(labeled))
    summary[1].metric("Confirmed threats", confirmed)
    summary[2].metric("Marked benign", benign)
    metrics = feedback_threshold_metrics(labeled)
    minimum_per_class = 2
    enough_labels = confirmed >= minimum_per_class and benign >= minimum_per_class
    if enough_labels:
        best = metrics.sort_values(["F1", "Precision", "Risk threshold"], ascending=[False, False, False]).iloc[0]
        st.success(
            f"Best observed F1 in this labeled window: threshold {int(best['Risk threshold'])} "
            f"(precision {best['Precision']:.0%}, recall {best['Recall']:.0%})."
        )
    else:
        st.warning(
            f"Need at least {minimum_per_class} Confirmed threat and {minimum_per_class} Benign labels "
            "before suggesting a cutoff. Current counts are too small for a useful comparison."
        )

    settings = get_detection_settings()
    current_threshold = settings["endpoint_alert_min_risk"]
    selected_threshold = st.slider(
        "Endpoint alert risk threshold",
        min_value=20,
        max_value=95,
        value=max(20, min(95, current_threshold)),
        step=5,
        key="ai_feedback_calibration_threshold",
        help="A higher threshold reduces the number of alerts and may miss more labeled threats.",
    )
    selected_row = metrics.iloc[(metrics["Risk threshold"] - selected_threshold).abs().argsort()[:1]]
    if not selected_row.empty:
        row = selected_row.iloc[0]
        metric_cols = st.columns(4)
        metric_cols[0].metric("Estimated precision", f"{row['Precision']:.0%}")
        metric_cols[1].metric("Estimated recall", f"{row['Recall']:.0%}")
        metric_cols[2].metric("F1", f"{row['F1']:.2f}")
        metric_cols[3].metric("Labeled events alerted", int(row["Alerts on labeled events"]))
    st.dataframe(metrics.style.format({"Precision": "{:.0%}", "Recall": "{:.0%}", "F1": "{:.2f}"}), hide_index=True, width="stretch")
    st.caption(f"Scoring source: {source} · {model_label}. Only saved analyst labels in this app are used; unlabeled events do not count as benign.")
    if is_admin():
        if st.button(
            "Apply selected risk threshold",
            key="apply_ai_feedback_threshold",
            disabled=not enough_labels or selected_threshold == current_threshold,
        ):
            save_detection_settings(selected_threshold, settings["ai_anomaly_min_score"])
            audit_event("ai_feedback_threshold_applied", f"threshold={selected_threshold}; labels={len(labeled)}")
            st.success(f"Endpoint alert risk threshold updated to {selected_threshold}.")
            st.rerun()
    else:
        st.caption("An Admin can apply the selected threshold after enough analyst labels are available.")


def render_explainable_ai_assistant():
    render_page_heading("Explainable AI Assistant")
    st.write("Select a live endpoint event to see the exact signals behind its risk score and suggested analyst checks.")
    st.caption("This assistant explains the sensor and model evidence available in the event; it does not invent conclusions or label the score as a probability.")
    live_openai_enabled = render_live_ai_toggle()

    @st.fragment(run_every="10s")
    def assistant_panel():
        render_live_ai_panel(show_assistant=True, live_openai_enabled=live_openai_enabled)

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
    if not SKLEARN_AVAILABLE:
        st.warning(
            "Model evaluation is unavailable because this computer blocked a scientific-library component. "
            "The live dashboard and metadata-based anomaly scoring are still available."
        )
        return
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
    evaluation_context = build_evaluation_context(result, target, source)
    evaluation_context_id = hashlib.sha256(
        json.dumps(evaluation_context, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()[:12]
    render_optional_ai_review(
        payload=evaluation_context,
        review_type="evaluation",
        key_suffix=evaluation_context_id,
        disclosure=(
            "Only aggregate accuracy/F1 metrics, class names and per-class scores, row counts, "
            "dataset/target labels, and the top feature names/importances are sent after you check "
            "consent and click Generate. No CSV rows, raw samples, or file contents are sent. "
            "Avoid sensitive class or feature names in uploaded datasets."
        ),
    )
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


def render_alert_system():
    render_page_heading("Alert System")
    severity_levels = ["Critical", "High", "Medium", "Low"]
    configured_threshold = setting("ALERT_NOTIFY_MINIMUM", "High").title()
    default_index = severity_levels.index(configured_threshold) if configured_threshold in severity_levels else 1
    st.session_state.setdefault("in_app_notifications_enabled", True)
    in_app_notifications_enabled = st.toggle(
        "In-app notifications",
        key="in_app_notifications_enabled",
        help="Show an in-app toast when a new alert at or above the selected severity is created. This starts ON each session.",
    )
    st.caption("In-app notification toasts are " + ("ON" if in_app_notifications_enabled else "OFF") + ". Email has its own separate switch.")
    notification_minimum = st.selectbox("Notification threshold (in-app and email)", severity_levels, index=default_index, key="alert_notification_threshold")
    if is_admin():
        render_local_email_settings()
    else:
        st.caption("Email delivery settings can be changed by an Admin.")
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
        disabled=not configured_for_email or not is_admin(),
        help="This switch resets to OFF whenever you restart the app or sign in again. Admin access is required.",
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
    st.caption("Auto-refresh is off. Notifications stay on this page until you check for new alerts or another module records one.")
    if st.button("Check for new notifications", type="primary", key="alert_system_check_new"):
        try:
            load_sensor_events.clear()
            load_cloud_sensor_heartbeats.clear()
            endpoint_events, _ = load_sensor_events(limit=1000)
            new_alerts = sync_endpoint_alerts(endpoint_events)
            new_alerts += sync_watchlist_alerts(endpoint_events)
            if len(endpoint_events) >= 20:
                analyzed_events, _ = analyze_live_events(endpoint_events)
                ai_anomalies = analyzed_events[analyzed_events["AI anomaly"]]
                new_alerts += create_ai_anomaly_alerts(ai_anomalies)
                new_alerts += promote_ai_attack_chain_alerts(detect_ai_attack_chains(analyzed_events))
                save_drift_alert(model_drift_summary(analyzed_events))
            st.success(f"Checked current activity. {new_alerts} new notification(s) added.")
        except Exception as error:
            st.warning(f"Could not check live endpoint events: {error}")

    alerts = hide_cleared_notifications(load_alerts())
    if not alerts.empty and {"due_at", "status"}.issubset(alerts.columns):
        due_values = pd.to_datetime(alerts["due_at"], utc=True, errors="coerce")
        overdue = due_values.lt(pd.Timestamp.now(tz="UTC")) & alerts["status"].isin(["Open", "Acknowledged"])
        alerts["SLA status"] = "No deadline"
        alerts.loc[due_values.notna(), "SLA status"] = "On time"
        alerts.loc[overdue, "SLA status"] = "OVERDUE"
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
    if "occurrence_count" in alerts.columns:
        grouped_observations = int(pd.to_numeric(alerts["occurrence_count"], errors="coerce").fillna(1).sum())
        st.caption(f"{len(alerts)} alert group(s) represent {grouped_observations} observed signal(s). Matching open alerts are grouped for {alert_group_window_minutes()} minute(s).")
    if is_admin() and st.button("Clear all notifications", disabled=active_count == 0, type="secondary"):
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
        changed = update_alert_status(selected_id, new_status)
        if changed:
            st.success("Alert status updated and added to its investigation timeline.")
        else:
            st.info("The alert already has that status.")
        st.rerun()

    selected_alert = visible.loc[visible["id"].astype(int) == int(selected_id)].iloc[0]
    st.caption(f"Grouped observations: {int(selected_alert.get('occurrence_count', 1) or 1)} · Last observed: {selected_alert.get('last_seen_at') or selected_alert.get('created_at')}")
    if str(selected_alert.get("SLA status", "")) == "OVERDUE":
        st.error("This alert has passed its review deadline.")
    with st.form(f"alert_assignment_sla_form_{selected_id}"):
        assigned_to = st.text_input("Assigned analyst", value=str(selected_alert.get("assigned_to") or ""), max_chars=120, key=f"alert_assignee_{selected_id}")
        has_deadline = st.checkbox("Set review deadline", value=bool(selected_alert.get("due_at")), key=f"alert_deadline_enabled_{selected_id}")
        deadline_hours = st.number_input("Deadline in hours from now", min_value=1, max_value=720, value=24, step=1, key=f"alert_deadline_hours_{selected_id}", disabled=not has_deadline)
        assignment_saved = st.form_submit_button("Save assignment and SLA")
    if assignment_saved:
        due_at = (datetime.now(timezone.utc) + timedelta(hours=int(deadline_hours))).isoformat(timespec="seconds") if has_deadline else None
        with connect_db() as connection:
            connection.execute("UPDATE alerts SET assigned_to = ?, due_at = ? WHERE id = ?", (assigned_to.strip(), due_at, int(selected_id)))
        record_alert_timeline(int(selected_id), "Assignment/SLA updated", f"Assigned to: {assigned_to.strip() or 'Unassigned'}; deadline: {due_at or 'None'}")
        audit_event("alert_assignment_sla_updated", f"alert_id={selected_id}; assigned={assigned_to.strip()[:100]}; deadline={due_at or 'none'}")
        st.success("Assignment and review deadline saved.")
        st.rerun()

    with st.expander("Alert evidence and context"):
        st.caption(f"Created: {selected_alert.get('created_at', 'Unknown')}")
        st.caption(f"MITRE ATT&CK: {selected_alert.get('mitre_id') or 'Not mapped'}")
        st.text(str(selected_alert.get("details") or "No additional evidence was recorded."))

    render_alert_ioc_extractor(selected_alert.to_dict())

    st.markdown("#### Investigation and response checklist")
    checklist = load_alert_checklist(selected_id)
    completed_count = int(checklist["completed"].astype(bool).sum())
    st.progress(
        completed_count / max(len(checklist), 1),
        text=f"{completed_count} of {len(checklist)} steps complete",
    )
    checked_items = {}
    with st.form(f"alert_checklist_form_{selected_id}"):
        for item in checklist.itertuples(index=False):
            widget_key = f"alert_checklist_{selected_id}_{item.item_key}"
            if widget_key not in st.session_state:
                st.session_state[widget_key] = bool(item.completed)
            checked_items[item.item_key] = st.checkbox(item.label, key=widget_key)
        checklist_submitted = st.form_submit_button("Save checklist progress")
    if checklist_submitted:
        save_alert_checklist(selected_id, checked_items)
        audit_event(
            "alert_checklist_saved",
            f"alert_id={selected_id}; completed={sum(bool(value) for value in checked_items.values())}/{len(checked_items)}",
        )
        st.success("Investigation checklist progress saved for this alert.")
        st.rerun()

    render_response_playbook(selected_alert)

    st.markdown("#### Investigation timeline")
    note_key = f"alert_investigation_note_{selected_id}"
    with st.form(f"alert_note_form_{selected_id}", clear_on_submit=True):
        investigation_note = st.text_area(
            "Add an investigation note",
            key=note_key,
            placeholder="Record what you checked, evidence observed, and the decision made.",
            max_chars=4000,
        )
        note_submitted = st.form_submit_button("Add note to timeline")
    if note_submitted:
        if not investigation_note.strip():
            st.warning("Enter a note before saving it to the timeline.")
        else:
            record_alert_timeline(selected_id, "Investigation note", investigation_note.strip())
            audit_event("alert_investigation_note_added", f"alert_id={selected_id}")
            st.success("Investigation note saved.")
            st.rerun()

    timeline = load_alert_timeline(selected_id)
    if timeline.empty:
        st.caption("No investigation activity has been recorded for this alert yet.")
    else:
        st.dataframe(
            timeline.rename(columns={
                "occurred_at": "Time (UTC)",
                "event_type": "Activity",
                "actor": "User",
                "note": "Details",
            }),
            hide_index=True,
            width="stretch",
        )


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
                incident_id = add_incident(f"Grouped investigation ({len(selected_rows)} alerts)", severity, notes)
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                with connect_db() as connection:
                    connection.executemany(
                        "INSERT OR IGNORE INTO incident_alert_links (incident_id, alert_id, created_at) VALUES (?, ?, ?)",
                        [(incident_id, int(row.id), now) for row in selected_rows],
                    )
                for row in selected_rows:
                    record_incident_timeline(incident_id, "Alert linked", f"Alert #{row.id}: {row.title}")
                    record_alert_timeline(int(row.id), "Linked to incident", f"Incident #{incident_id}")
                audit_event("incident_created_from_alerts", f"incident_id={incident_id}; alert_ids={','.join(str(row.id) for row in selected_rows)}")
                st.success("Incident created with alert links and investigation timeline.")
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
        record_incident_timeline(int(selected_id), "Status changed", f"Incident status set to {status}")
        audit_event("incident_status_changed", f"incident_id={selected_id}; status={status}")
        st.success("Incident status updated and timeline saved.")
        st.rerun()

    selected_incident = incidents.loc[incidents["id"].astype(int) == int(selected_id)].iloc[0]
    with connect_db() as connection:
        linked_ids = [int(row[0]) for row in connection.execute(
            "SELECT alert_id FROM incident_alert_links WHERE incident_id = ? ORDER BY alert_id", (int(selected_id),)
        ).fetchall()]
        if not linked_ids:
            legacy = re.search(r"Related alert IDs:\s*([0-9, ]+)", str(selected_incident.get("notes", "")))
            if legacy:
                linked_ids = [int(value) for value in re.findall(r"\d+", legacy.group(1))]
        timeline = load_incident_timeline(int(selected_id))
        if linked_ids:
            marks = ",".join("?" for _ in linked_ids)
            linked_alerts = pd.read_sql_query(f"SELECT * FROM alerts WHERE id IN ({marks}) ORDER BY id", connection, params=linked_ids)
        else:
            linked_alerts = pd.DataFrame()
    st.markdown("#### Linked alerts")
    if linked_alerts.empty:
        st.info("No linked alerts. Group alerts in the section above to include them in the incident export.")
    else:
        st.dataframe(linked_alerts, hide_index=True, width="stretch")
    st.markdown("#### Incident investigation timeline")
    if timeline.empty:
        st.caption("No incident timeline activity has been recorded yet.")
    else:
        st.dataframe(timeline.rename(columns={"occurred_at":"Time (UTC)","event_type":"Activity","actor":"User","note":"Details"}), hide_index=True, width="stretch")
    csv_parts = []
    summary_row = selected_incident.to_frame().T
    summary_row.insert(0, "record_type", "incident")
    csv_parts.append(summary_row)
    if not linked_alerts.empty:
        linked_export = linked_alerts.copy()
        linked_export.insert(0, "record_type", "linked_alert")
        csv_parts.append(linked_export)
    if not timeline.empty:
        timeline_export = timeline.copy()
        timeline_export.insert(0, "record_type", "incident_timeline")
        csv_parts.append(timeline_export)
    export_frame = pd.concat(csv_parts, ignore_index=True, sort=False)
    stem = f"incident_{int(selected_id)}_report"
    csv_bytes = export_frame.to_csv(index=False).encode("utf-8-sig")
    pdf_bytes = make_incident_pdf(selected_incident, linked_alerts, timeline)
    left, right = st.columns(2)
    with left:
        if st.download_button("Download incident report (CSV)", csv_bytes, f"{stem}.csv", "text/csv", key=f"incident_csv_{selected_id}"):
            audit_event("incident_report_exported", f"incident_id={selected_id}; format=csv")
    with right:
        if st.download_button("Download incident report (PDF)", pdf_bytes, f"{stem}.pdf", "application/pdf", key=f"incident_pdf_{selected_id}"):
            audit_event("incident_report_exported", f"incident_id={selected_id}; format=pdf")
    evidence_zip = make_incident_evidence_zip(selected_incident, linked_alerts, timeline)
    if st.download_button("Download incident evidence bundle (ZIP)", evidence_zip, f"incident_{int(selected_id)}_evidence.zip", "application/zip", key=f"incident_bundle_{selected_id}"):
        audit_event("incident_evidence_bundle_exported", f"incident_id={selected_id}; linked_alerts={len(linked_alerts)}")


def analyze_log_text(contents, watchlist=None):
    """Extract security-relevant log lines and optional watchlist matches locally."""
    ip_pattern = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    failed_pattern = re.compile(r"failed password|failed login|authentication failure|invalid user|logon failure|event\s*id\s*[:=]?\s*4625", re.I)
    suspicious_pattern = re.compile(r"encodedcommand|(?:^|\s)-enc(?:odedcommand)?\b|downloadstring|invoke-webrequest|frombase64string|mimikatz|lsass|credential dump", re.I)
    malware_pattern = re.compile(r"malware|trojan|ransomware|quarantin|virus detected", re.I)
    detections = []
    failed_counts = {}
    active_watchlist = watchlist if watchlist is not None else pd.DataFrame()
    for line_number, line in enumerate(contents.splitlines(), start=1):
        failed = bool(failed_pattern.search(line))
        suspicious_match = suspicious_pattern.search(line)
        watchlist_matches = []
        if not active_watchlist.empty:
            for indicator in active_watchlist.itertuples(index=False):
                token = str(indicator.indicator_value).strip()
                kind = str(indicator.indicator_type).lower()
                if kind == "ip address":
                    found = bool(re.search(r"(?<![\w.])" + re.escape(token) + r"(?![\w.])", line, re.I))
                elif kind == "file hash":
                    found = bool(re.search(r"(?<![a-f0-9])" + re.escape(token) + r"(?![a-f0-9])", line, re.I))
                else:
                    found = bool(re.search(r"(?<![a-z0-9.-])" + re.escape(token) + r"(?![a-z0-9.-])", line, re.I))
                if found:
                    watchlist_matches.append((kind, token, str(indicator.label or "").strip()))
        if failed:
            ips = ip_pattern.findall(line)
            key = ips[0] if ips else "unknown source"
            failed_counts[key] = failed_counts.get(key, 0) + 1
        if failed or suspicious_match or malware_pattern.search(line) or watchlist_matches:
            reasons = []
            severity = "Medium"
            for kind, token, label in watchlist_matches:
                reasons.append(f"IOC watchlist match ({kind}): {token}" + (f" · {label}" if label else ""))
                severity = "High"
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
    findings = analyze_log_text(text, load_ioc_watchlist(enabled_only=True))
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
        timeline_rows = []
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
                    timeline_rows.append((
                        int(cursor.lastrowid),
                        row["severity"],
                        title[:250],
                        f"Source file: {Path(upload.name).name}\nLine: {row['line_number']}\nSource IP: {row['source_ip'] or 'not found'}\nReason: {row['reason']}",
                    ))
                    notifications.append((row["severity"], title[:120]))
        for alert_id, severity, title, details in timeline_rows:
            record_alert_timeline(alert_id, "Alert created", f"{severity}: {title}\n{details}")
        for severity, title in notifications:
            notify_security_alert(severity, title)
        audit_event("log_findings_promoted", f"filename={Path(upload.name).name}; findings={len(findings)}; new_alerts={inserted}")
        st.success(f"Created {inserted} new alert(s); repeated imports were deduplicated.")


@st.fragment(run_every="10s")
def render_threat_hunting():
    render_page_heading("Threat Hunting")
    st.write("Search recent endpoint events and group related activity by process for analyst review.")
    try:
        events, source = load_sensor_events(limit=5000)
    except Exception as error:
        st.error(f"Could not load endpoint events: {error}")
        return
    if events.empty:
        st.info("No endpoint events are available yet. Start the local sensor and check its sync status.")
        return
    st.caption(f"Source: {source} · {len(events)} recent event(s) · auto-refresh every 10 seconds")
    if st.button("Refresh now", key="threat_hunt_refresh"):
        load_sensor_events.clear()
        st.rerun()

    data = events.copy()
    if "risk_score" not in data:
        data["risk_score"] = 0
    data["risk_score"] = pd.to_numeric(data["risk_score"], errors="coerce").fillna(0).clip(0, 100)
    time_column = next((column for column in ("occurred_at", "created_at") if column in data.columns), None)
    saved_queries = load_saved_hunt_queries()
    saved_query_names = saved_queries["name"].astype(str).tolist() if not saved_queries.empty else []
    selected_saved_query = st.selectbox("Saved search", ["Current filters", *saved_query_names], key="hunt_saved_selection")
    if selected_saved_query != "Current filters":
        saved_row = saved_queries.loc[saved_queries["name"].eq(selected_saved_query)].iloc[0]
        if st.session_state.get("_loaded_hunt_query") != int(saved_row["id"]):
            try:
                saved_filters = json.loads(str(saved_row["filters_json"] or "{}"))
            except (TypeError, ValueError):
                saved_filters = {}
            st.session_state["hunt_query"] = str(saved_row["query_text"] or "")
            st.session_state["hunt_lookback"] = int(saved_filters.get("lookback_hours", 24))
            st.session_state["hunt_min_risk"] = int(saved_filters.get("min_risk", 0))
            st.session_state["hunt_types"] = list(saved_filters.get("event_types", []))
            st.session_state["hunt_severity"] = list(saved_filters.get("severities", []))
            st.session_state["_loaded_hunt_query"] = int(saved_row["id"])
            st.rerun()
    lookback_hours = st.select_slider("Look back", options=[1, 6, 12, 24, 48, 72, 168], value=24, format_func=lambda value: f"{value} hour(s)", key="hunt_lookback")
    if time_column:
        parsed = pd.to_datetime(data[time_column], errors="coerce", utc=True)
        cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=lookback_hours)
        data = data[parsed.isna() | parsed.ge(cutoff)].copy()
        data["_parsed_time"] = parsed.loc[data.index]
    columns = st.columns(3)
    types = sorted(data.get("event_type", pd.Series(dtype=str)).dropna().astype(str).unique().tolist())
    severities = sorted(data.get("severity", pd.Series(dtype=str)).dropna().astype(str).unique().tolist())
    if selected_saved_query != "Current filters":
        st.session_state["hunt_types"] = [value for value in st.session_state.get("hunt_types", []) if value in types]
        st.session_state["hunt_severity"] = [value for value in st.session_state.get("hunt_severity", []) if value in severities]
    with columns[0]:
        chosen_types = st.multiselect("Event type", types, default=types, key="hunt_types")
    with columns[1]:
        chosen_severity = st.multiselect("Sensor severity", severities, default=severities, key="hunt_severity")
    with columns[2]:
        min_risk = st.slider("Minimum risk score", 0, 100, 0, 5, key="hunt_min_risk")
    query = st.text_input("Search event text, process, IP, or file name", key="hunt_query").strip().casefold()
    with st.expander("Save current hunting filters"):
        with st.form("save_threat_hunt_query_form"):
            query_name = st.text_input("Search name", max_chars=100, placeholder="e.g. High-risk PowerShell activity")
            save_query_clicked = st.form_submit_button("Save search")
        if save_query_clicked:
            try:
                save_hunt_query(query_name, query, {
                    "event_types": chosen_types,
                    "severities": chosen_severity,
                    "min_risk": int(min_risk),
                    "lookback_hours": int(lookback_hours),
                })
                st.success("Saved search is available from the Saved search selector.")
                st.rerun()
            except ValueError as error:
                st.error(str(error))
    if "event_type" in data:
        data = data[data["event_type"].astype(str).isin(chosen_types)]
    if "severity" in data:
        data = data[data["severity"].astype(str).isin(chosen_severity)]
    data = data[data["risk_score"].ge(min_risk)]
    if query:
        search_columns = [column for column in ("summary", "details", "process_name", "remote_ip", "file_name", "file_sha256") if column in data]
        combined = data[search_columns].fillna("").astype(str).agg(" ".join, axis=1).str.casefold()
        data = data[combined.str.contains(re.escape(query), regex=True, na=False)]
    high_count = int(data.get("severity", pd.Series(index=data.index, dtype=str)).astype(str).str.lower().isin(["high", "critical"]).sum())
    left, middle, right = st.columns(3)
    left.metric("Matching events", len(data))
    middle.metric("High / Critical", high_count)
    right.metric("Median risk", round(float(data["risk_score"].median()), 1) if not data.empty else 0)
    if data.empty:
        st.info("No events match these filters.")
        return
    st.dataframe(data.drop(columns=["_parsed_time"], errors="ignore").head(1000), hide_index=True, width="stretch")
    st.download_button("Download hunt results (CSV)", data.drop(columns=["_parsed_time"], errors="ignore").to_csv(index=False).encode("utf-8-sig"), "threat_hunt_events.csv", "text/csv", key="hunt_download")

    process_col = "process_name" if "process_name" in data else None
    if not process_col:
        st.info("Process names are not present in this event set, so process correlation is unavailable.")
        return
    st.markdown("#### Related activity by process")
    correlated = data[data[process_col].notna() & data[process_col].astype(str).str.strip().ne("")].copy()
    if correlated.empty:
        st.info("No process names are available in the filtered events.")
        return
    correlated["_event_type"] = correlated.get("event_type", pd.Series("unknown", index=correlated.index)).fillna("unknown").astype(str)
    groups = correlated.groupby(process_col, dropna=True).agg(
        event_count=(process_col, "size"),
        distinct_event_types=("_event_type", "nunique"),
        max_risk=("risk_score", "max"),
        event_types=("_event_type", lambda values: ", ".join(sorted(set(values))[:8])),
    ).reset_index()
    groups = groups[(groups["event_count"] >= 3) | ((groups["event_count"] >= 2) & (groups["distinct_event_types"] >= 2)) | groups["max_risk"].ge(70)]
    groups = groups.sort_values(["max_risk", "event_count"], ascending=False)
    if groups.empty:
        st.info("No process group met the correlation threshold in this time window.")
        return
    st.dataframe(groups, hide_index=True, width="stretch")
    process_names = groups[process_col].astype(str).tolist()
    chosen_process = st.selectbox("Process group to promote for investigation", process_names, key="hunt_correlated_process")
    if st.button("Create deduplicated correlation alert", key="hunt_create_correlation_alert"):
        related = correlated[correlated[process_col].astype(str).eq(chosen_process)].sort_values("_parsed_time" if "_parsed_time" in correlated else process_col, ascending=False).head(50)
        row = groups[groups[process_col].astype(str).eq(chosen_process)].iloc[0]
        digest = hashlib.sha256((chosen_process + "|" + "|".join(sorted(str(item) for item in related.get("event_id", related.get("event_uid", related.get("id", pd.Series(dtype=str))).tolist())))).encode("utf-8")).hexdigest()[:24]
        addresses = sorted(set(related.get("remote_ip", pd.Series(dtype=str)).dropna().astype(str)))
        details = "\n".join([
            "Source: analyst-triggered process event correlation",
            f"Process: {chosen_process}",
            f"Related event count: {int(row['event_count'])}",
            f"Event types: {row['event_types']}",
            f"Highest sensor risk: {int(row['max_risk'])}/100",
            f"Observed remote IPs: {', '.join(addresses[:20]) or 'None recorded'}",
            "This correlation is a review lead, not a confirmed compromise.",
        ])
        created = add_alert(f"Correlated process activity: {chosen_process}", "High" if int(row["max_risk"]) < 90 else "Critical", details, source_event_id=f"threat-hunt:{digest}")
        audit_event("threat_hunt_correlation_alert", f"process={chosen_process[:120]}; events={int(row['event_count'])}; created={created}")
        st.success("Correlation alert created." if created else "This exact correlation was already promoted; duplicate alert was skipped.")


def render_event_correlation_graph():
    render_page_heading("Event Correlation Graph")
    st.write("Explore event links that share a sensor, process, destination IP, or file hash.")
    st.caption("Links are based on matching endpoint metadata within the selected time window. A relationship is an investigation lead, not proof of an attack.")
    try:
        events, source = load_sensor_events(limit=3000)
    except Exception as error:
        st.error(f"Could not load endpoint events: {type(error).__name__}")
        return
    if events is None or events.empty:
        st.info("No endpoint events are available to correlate yet.")
        return
    data = events.copy()
    if "sensor_id" not in data:
        data["sensor_id"] = "Local sensor"
    time_column = next((column for column in ("occurred_at", "created_at") if column in data), None)
    lookback_hours = st.select_slider("Correlation window", options=[1, 6, 12, 24, 48, 72, 168], value=24, format_func=lambda value: f"Last {value} hour(s)")
    if time_column:
        times = pd.to_datetime(data[time_column], errors="coerce", utc=True)
        data = data[times.isna() | times.ge(pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=lookback_hours))].copy()
    if data.empty:
        st.info("No events are in this time window.")
        return

    entity_columns = {
        "Process": "process_name", "Destination IP": "remote_ip",
        "File hash": "file_sha256", "Sensor": "sensor_id",
    }
    options = []
    for label, column in entity_columns.items():
        if column in data:
            values = data[column].dropna().astype(str).str.strip()
            options.extend((label, value) for value in sorted(set(values) - {""}))
    if not options:
        st.info("No shared process, IP, hash, or sensor fields were found in these events.")
        return
    labels = [f"{kind}: {value[:90]}" for kind, value in options]
    selected_index = st.selectbox("Start from an entity", range(len(options)), format_func=lambda index: labels[index])
    selected_kind, selected_value = options[selected_index]
    selected_column = entity_columns[selected_kind]
    related = data[data[selected_column].fillna("").astype(str).eq(selected_value)].copy()
    if time_column:
        related = related.sort_values(time_column, ascending=False)
    related = related.head(20)
    st.caption(f"Source: {source} · {len(related)} related event(s) in the graph · max 20 for readability")
    st.metric("Related events", len(related))

    def dot_quote(value):
        return json.dumps(str(value)[:120], ensure_ascii=True)

    def node_id(kind, value):
        return f"n_{hashlib.sha256((kind + ':' + str(value)).encode('utf-8')).hexdigest()[:14]}"

    center_id = node_id(selected_kind, selected_value)
    graph_lines = ["graph CTI {", "  graph [bgcolor=\"transparent\", overlap=false, splines=true];", "  node [style=filled, fontname=Arial, fontsize=10, color=\"#394447\", fontcolor=\"#f2f4ef\"];", "  edge [color=\"#778477\", penwidth=1.2];"]
    graph_lines.append(f"  {center_id} [label={dot_quote(selected_kind + ': ' + selected_value[:38])}, shape=hexagon, fillcolor=\"#536B42\"];")
    for index, row in enumerate(related.to_dict("records")):
        event_key = str(row.get("event_id") or row.get("event_uid") or row.get("id") or index)
        event_node = node_id("event", event_key)
        event_type = str(row.get("event_type") or "event")
        event_time = str(row.get(time_column) or "")[:19] if time_column else ""
        label = f"{event_type}\n{event_time}\nRisk {row.get('risk_score', 0)}"
        graph_lines.append(f"  {event_node} [label={dot_quote(label)}, shape=box, fillcolor=\"#26353A\"];")
        graph_lines.append(f"  {center_id} -- {event_node};")
        other_entities = (
            ("Sensor", "sensor_id", "#334b57"),
            ("Process", "process_name", "#665738"),
            ("IP", "remote_ip", "#574768"),
            ("SHA256", "file_sha256", "#6a4444"),
        )
        for kind, column, color in other_entities:
            raw_value = row.get(column)
            value = "" if raw_value is None or pd.isna(raw_value) else str(raw_value).strip()
            if not value or (column == selected_column and value == selected_value):
                continue
            entity_node = node_id(kind, value)
            graph_lines.append(f"  {entity_node} [label={dot_quote(kind + ': ' + value[:34])}, shape=ellipse, fillcolor={dot_quote(color)}];")
            graph_lines.append(f"  {event_node} -- {entity_node};")
    graph_lines.append("}")
    try:
        st.graphviz_chart("\n".join(graph_lines), width="stretch")
    except Exception:
        st.info("The graph renderer is unavailable in this installation. Use the related-event table below; install the project requirements to enable the visual graph.")
    visible_columns = [column for column in ("occurred_at", "created_at", "sensor_id", "event_type", "severity", "risk_score", "summary", "process_name", "remote_ip", "file_name", "file_sha256") if column in related]
    st.dataframe(related[visible_columns], hide_index=True, width="stretch")
    st.download_button("Download related events (CSV)", related.to_csv(index=False).encode("utf-8-sig"), "event_correlation.csv", "text/csv")


def render_alert_noise_control():
    st.subheader("Alert Noise Control")
    st.write("Group repeat alerts over a configurable time window and review where duplicate signals are coming from.")
    alerts = load_alerts()
    active = alerts[alerts["status"].isin(["Open", "Acknowledged"])] if not alerts.empty else alerts
    grouped = pd.to_numeric(active.get("occurrence_count", pd.Series(dtype=int)), errors="coerce").fillna(1)
    repeat_count = int((grouped - 1).clip(lower=0).sum())
    metric_columns = st.columns(3)
    metric_columns[0].metric("Active alert groups", len(active))
    metric_columns[1].metric("Repeated signals grouped", repeat_count)
    metric_columns[2].metric("Active suppression rules", len(load_suppression_rules(active_only=True)))
    current_window = alert_group_window_minutes()
    new_window = st.slider("Group matching open alerts for", 1, 1440, current_window, 1, format="%d min", key="alert_group_window_control")
    st.caption("Matching title and severity alerts are grouped during this window. Suppression rules remain exact-match and keep collecting events.")
    if is_admin() and st.button("Save alert grouping window", key="save_alert_group_window"):
        save_app_state("alert_group_window_minutes", str(int(new_window)))
        audit_event("alert_group_window_updated", f"minutes={int(new_window)}")
        st.success("Alert grouping window saved.")
        st.rerun()
    if not active.empty:
        repeated = active.copy()
        repeated["occurrence_count"] = pd.to_numeric(repeated["occurrence_count"], errors="coerce").fillna(1)
        st.markdown("#### Most repeated active signals")
        st.dataframe(
            repeated.sort_values(["occurrence_count", "last_seen_at"], ascending=[False, False])
            [[column for column in ("title", "severity", "status", "occurrence_count", "created_at", "last_seen_at") if column in repeated.columns]]
            .head(20), hide_index=True, width="stretch",
        )
    else:
        st.info("No active alerts are available to summarize yet.")


def render_saved_hunt_queries_panel():
    st.subheader("Saved Threat Hunting Queries")
    st.write("Save searches in Threat Hunting and reuse the same text, time window, event types, severity, and risk threshold.")
    saved = load_saved_hunt_queries()
    if saved.empty:
        st.info("No saved searches yet. Open Threat Hunting, set filters, then use **Save current hunting filters**.")
        return
    display = saved[["name", "query_text", "filters_json", "created_by", "updated_at"]].copy()
    display = display.rename(columns={"name":"Search", "query_text":"Text filter", "filters_json":"Saved filters", "created_by":"Saved by", "updated_at":"Updated (UTC)"})
    st.dataframe(display, hide_index=True, width="stretch")
    if is_admin():
        selected_name = st.selectbox("Saved search to remove", saved["name"].astype(str).tolist(), key="saved_query_delete_choice")
        confirm = st.checkbox("I understand this removes only the saved search, not event data.", key="confirm_saved_query_delete")
        if st.button("Delete saved search", disabled=not confirm, key="delete_saved_hunt_query"):
            with connect_db() as connection:
                connection.execute("DELETE FROM saved_hunt_queries WHERE name = ?", (selected_name,))
            audit_event("threat_hunt_query_deleted", f"name={selected_name[:100]}")
            st.success("Saved search deleted.")
            st.rerun()


def render_sensor_diagnostics():
    st.subheader("Sensor Diagnostics")
    st.write("Check the endpoint sensor, local event store, watched folders, and cloud API connection.")
    try:
        events, source = load_sensor_events(limit=500)
        report = sensor_health_report(events, source)
    except Exception as error:
        events, source, report = pd.DataFrame(), "unavailable", {"status":"Error", "last_heartbeat":"Unknown", "last_event":"Unknown", "cloud_sync":"Unknown", "pending":"Unknown", "explanation":str(error)[:300]}
    columns = st.columns(4)
    columns[0].metric("Sensor", report.get("status", "Unknown"))
    columns[1].metric("Last heartbeat", report.get("last_heartbeat", "Unknown"))
    columns[2].metric("Last event", report.get("last_event", "Unknown"))
    columns[3].metric("Cloud sync queue", report.get("pending", "Unknown"))
    st.caption(report.get("explanation", "No diagnostic details."))

    checks = []
    try:
        with connect_db() as connection:
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            connection.execute("SAVEPOINT cti_diagnostics_write")
            probe_key = "diagnostic_probe_" + uuid.uuid4().hex
            connection.execute("INSERT INTO app_state (key,value) VALUES (?, 'ok')", (probe_key,))
            connection.execute("ROLLBACK TO cti_diagnostics_write")
            connection.execute("RELEASE cti_diagnostics_write")
        checks.append({"Check":"Application database", "Result":"Healthy" if integrity == "ok" else "Needs review", "Details":str(integrity)})
    except sqlite3.Error as error:
        checks.append({"Check":"Application database", "Result":"Error", "Details":str(error)[:240]})

    if source == "local" and os.name == "nt":
        watched_roots = [Path.home() / name for name in ("Downloads", "Desktop", "Documents")]
        checks.extend({"Check":f"Watch folder · {folder.name}", "Result":"Available" if folder.is_dir() else "Not found", "Details":str(folder)} for folder in watched_roots)
    else:
        checks.append({"Check":"Laptop folder access", "Result":"Not available here", "Details":"A hosted dashboard cannot inspect folders on the laptop."})

    api_url = setting("API_BASE_URL").strip().rstrip("/")
    if api_url:
        try:
            response = requests.get(f"{api_url}/health", timeout=8)
            response.raise_for_status()
            checks.append({"Check":"Endpoint API", "Result":"Connected", "Details":str(response.json().get("service", "API is healthy"))})
        except (requests.RequestException, ValueError) as error:
            checks.append({"Check":"Endpoint API", "Result":"Unavailable", "Details":f"{type(error).__name__}: {str(error)[:200]}"})
    else:
        checks.append({"Check":"Endpoint API", "Result":"Not configured", "Details":"Events are local-only until API settings are configured."})
    st.dataframe(pd.DataFrame(checks), hide_index=True, width="stretch")
    if st.button("Refresh diagnostics", key="refresh_sensor_diagnostics"):
        load_sensor_events.clear()
        load_cloud_sensor_heartbeats.clear()
        st.rerun()


def render_case_notes():
    st.subheader("Investigation Case Notes")
    st.write("Create a case, link related alerts, assign an owner, and keep analyst notes in a timestamped timeline.")
    alerts = load_alerts()
    alert_choices = {}
    if not alerts.empty:
        alert_choices = {f"#{int(row.id)} · {row.severity} · {str(row.title)[:90]}": int(row.id) for row in alerts.itertuples()}
    with st.form("investigation_case_create_form"):
        title = st.text_input("Case title", max_chars=180)
        left, right = st.columns(2)
        with left:
            severity = st.selectbox("Case severity", ["Low", "Medium", "High", "Critical"], index=1)
        with right:
            owner = st.text_input("Assigned analyst", max_chars=120)
        summary = st.text_area("Initial case summary", max_chars=3000)
        linked_alerts = st.multiselect("Link alerts", list(alert_choices))
        create_case = st.form_submit_button("Create investigation case", type="primary")
    if create_case:
        if not title.strip():
            st.error("Enter a case title.")
        else:
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with connect_db() as connection:
                cursor = connection.execute(
                    "INSERT INTO investigation_cases (title,severity,owner,summary,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                    (title.strip(), severity, owner.strip(), summary.strip(), str(st.session_state.get("username", "Analyst"))[:120], now, now),
                )
                case_id = int(cursor.lastrowid)
                connection.executemany(
                    "INSERT OR IGNORE INTO investigation_case_alerts (case_id,alert_id,linked_at) VALUES (?,?,?)",
                    [(case_id, alert_choices[label], now) for label in linked_alerts],
                )
            audit_event("investigation_case_created", f"case_id={case_id}; title={title.strip()[:120]}")
            st.success(f"Case #{case_id} created.")
            st.rerun()

    with connect_db() as connection:
        cases = pd.read_sql_query("SELECT * FROM investigation_cases ORDER BY updated_at DESC, id DESC", connection)
    if cases.empty:
        st.info("No investigation cases have been created yet.")
        return
    st.dataframe(cases[["id","title","severity","status","owner","created_at","updated_at"]], hide_index=True, width="stretch")
    labels = {f"#{int(row.id)} · {row.status} · {str(row.title)[:100]}":int(row.id) for row in cases.itertuples()}
    selected_label = st.selectbox("Case to review", list(labels), key="case_notes_selection")
    case_id = labels[selected_label]
    current_case = cases.loc[cases["id"].eq(case_id)].iloc[0]
    with st.form(f"case_update_form_{case_id}"):
        status = st.selectbox("Case status", ["Open", "Investigating", "Contained", "Resolved", "Closed"], index=["Open", "Investigating", "Contained", "Resolved", "Closed"].index(current_case["status"]) if current_case["status"] in ["Open", "Investigating", "Contained", "Resolved", "Closed"] else 0)
        new_owner = st.text_input("Case owner", value=str(current_case["owner"] or ""), max_chars=120)
        note = st.text_area("Add case note", max_chars=4000, placeholder="Evidence checked, decisions, and next steps")
        save_case_update = st.form_submit_button("Save case update")
    if save_case_update:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with connect_db() as connection:
            connection.execute("UPDATE investigation_cases SET status=?,owner=?,updated_at=? WHERE id=?", (status,new_owner.strip(),now,case_id))
            if note.strip():
                connection.execute("INSERT INTO investigation_case_notes (case_id,created_at,created_by,note) VALUES (?,?,?,?)", (case_id,now,str(st.session_state.get("username","Analyst"))[:120],note.strip()))
        audit_event("investigation_case_updated", f"case_id={case_id}; status={status}; note_added={bool(note.strip())}")
        st.success("Case update saved.")
        st.rerun()
    with connect_db() as connection:
        linked = pd.read_sql_query(
            "SELECT a.id,a.severity,a.status,a.title,a.created_at FROM alerts a JOIN investigation_case_alerts l ON l.alert_id=a.id WHERE l.case_id=? ORDER BY a.id DESC",
            connection, params=(case_id,),
        )
        notes = pd.read_sql_query("SELECT created_at,created_by,note FROM investigation_case_notes WHERE case_id=? ORDER BY id DESC", connection, params=(case_id,))
    st.markdown("#### Linked alerts")
    st.dataframe(linked, hide_index=True, width="stretch") if not linked.empty else st.caption("No alerts are linked to this case.")
    st.markdown("#### Case timeline")
    st.dataframe(notes.rename(columns={"created_at":"Time (UTC)","created_by":"Analyst","note":"Note"}), hide_index=True, width="stretch") if not notes.empty else st.caption("No case notes have been added yet.")


def render_safe_test_generator():
    st.subheader("Safe Test-Event Generator")
    st.write("Create clearly marked synthetic alerts to verify the alert inbox and investigation flow. Nothing is uploaded, emailed, or run on the endpoint.")
    scenarios = {
        "Repeated suspicious process": ("High", 82, "Synthetic process metadata suggests repeated execution from a user-writable path."),
        "Unusual outbound connection": ("Medium", 68, "Synthetic outbound connection metadata is included for alert workflow validation."),
        "After-hours sign-in pattern": ("High", 76, "Synthetic repeated sign-in metadata is included for alert workflow validation."),
    }
    scenario = st.selectbox("Test scenario", list(scenarios), key="safe_test_scenario")
    if is_admin() and st.button("Generate safe test alert", type="primary", key="generate_safe_test_event"):
        severity, score, reason = scenarios[scenario]
        event_id = "test-" + uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        title = f"[TEST] {scenario}"
        details = f"SAFE SYNTHETIC TEST EVENT — not real endpoint activity.\nScenario: {scenario}\nRisk score: {score}/100\nReason: {reason}\nNo endpoint files, processes, or network connections were accessed. No email or cloud event upload was performed."
        with connect_db() as connection:
            cursor = connection.execute(
                "INSERT INTO alerts (created_at,title,severity,details,source_event_id,status,occurrence_count,last_seen_at,dedupe_key) VALUES (?,?,?,?,?,'Open',1,?,?)",
                (now,title,severity,details,f"safe-test:{event_id}",now,alert_fingerprint(title,severity)),
            )
            alert_id = int(cursor.lastrowid)
            connection.execute("INSERT INTO safe_test_events (event_id,created_at,scenario,severity,risk_score,alert_id,status) VALUES (?,?,?,?,?,?,'Active')", (event_id,now,scenario,severity,score,alert_id))
        record_alert_timeline(alert_id,"Safe test alert created",details)
        audit_event("safe_test_event_generated", f"event_id={event_id}; scenario={scenario}; alert_id={alert_id}")
        st.success(f"Synthetic alert #{alert_id} created. Find it in Alert System; it is labeled [TEST].")
    elif not is_admin():
        st.info("Admin access is required to generate synthetic alerts.")
    with connect_db() as connection:
        generated = pd.read_sql_query("SELECT event_id,created_at,scenario,severity,risk_score,alert_id,status FROM safe_test_events ORDER BY created_at DESC", connection)
    if not generated.empty:
        st.dataframe(generated, hide_index=True, width="stretch")
        if is_admin():
            if st.button("Close all active test alerts", key="close_safe_test_alerts"):
                active_ids = generated.loc[generated["status"].eq("Active"), "alert_id"].dropna().astype(int).tolist()
                with connect_db() as connection:
                    connection.execute("UPDATE safe_test_events SET status='Closed' WHERE status='Active'")
                    if active_ids:
                        marks = ",".join("?" for _ in active_ids)
                        connection.execute(f"UPDATE alerts SET status='Closed' WHERE id IN ({marks})", active_ids)
                for alert_id in active_ids:
                    record_alert_timeline(alert_id,"Safe test closed","Synthetic test alert closed by the test-event generator.")
                audit_event("safe_test_alerts_closed", f"count={len(active_ids)}")
                st.success(f"Closed {len(active_ids)} synthetic test alert(s).")
                st.rerun()


def render_data_retention_controls():
    st.subheader("Data Retention Controls")
    st.write("Preview and remove records older than the selected period. Open alerts, active incidents, saved searches, case notes, and configuration are preserved.")
    if not is_admin():
        st.info("Admin access is required to change retention or purge old records.")
        return
    days = st.selectbox("Retain records for", [7, 14, 30, 60, 90, 180, 365], index=2, format_func=lambda value:f"{value} days", key="retention_days")
    cutoff, local_counts = load_retention_counts(days)
    st.caption(f"Cutoff: before {cutoff} (UTC). Local application database preview:")
    st.dataframe(pd.DataFrame([{"Record type":name,"Older records":count} for name,count in local_counts.items()]), hide_index=True, width="stretch")
    api_url = setting("API_BASE_URL").strip().rstrip("/")
    api_preview = None
    if api_url and setting("API_TOKEN"):
        if st.button("Preview cloud sensor-event retention", key="preview_cloud_retention"):
            try:
                api_preview = call_api_retention(days)
                st.session_state["cloud_retention_preview"] = api_preview
            except requests.RequestException as error:
                st.error(f"Cloud retention preview could not reach the API: {type(error).__name__}.")
        api_preview = st.session_state.get("cloud_retention_preview")
        if api_preview:
            if int(api_preview.get("days", -1)) == int(days):
                st.metric("Older cloud sensor events", int(api_preview.get("eligible_events", 0)))
            else:
                st.warning("The retention period changed. Preview cloud events again before applying this period.")
    else:
        st.info("Cloud event retention is unavailable until the authenticated endpoint API is configured.")
    st.warning("Purging is permanent. Review the preview first; only closed/resolved alerts and old telemetry/history are eligible.")
    confirmed = st.checkbox("I reviewed the counts and want to permanently purge records older than this period.", key="confirm_data_retention_purge")
    cloud_preview_ready = not (api_url and setting("API_TOKEN")) or (
        bool(st.session_state.get("cloud_retention_preview"))
        and int(st.session_state["cloud_retention_preview"].get("days", -1)) == int(days)
    )
    if st.button("Apply retention now", disabled=not confirmed or not cloud_preview_ready, type="secondary", key="apply_data_retention"):
        try:
            cloud_removed = None
            if api_url and setting("API_TOKEN"):
                cloud_removed = call_api_retention(days, apply=True)
            local_removed = purge_local_retention_records(days)
            audit_event("data_retention_applied", f"days={days}; local={json.dumps(local_removed,sort_keys=True)}; cloud={json.dumps(cloud_removed,sort_keys=True) if cloud_removed else 'not configured'}")
            st.success(f"Retention complete. Local records removed: {sum(local_removed.values())}. Cloud sensor events removed: {int((cloud_removed or {}).get('deleted_events',0))}.")
            st.session_state.pop("cloud_retention_preview", None)
            st.rerun()
        except requests.RequestException as error:
            st.error(f"Cloud retention failed before local cleanup. API response: {type(error).__name__}.")
        except (sqlite3.Error, ValueError) as error:
            st.error(f"Retention could not complete: {str(error)[:300]}")


def render_security_operations_toolkit():
    render_page_heading("Security Operations Toolkit")
    st.write("Six practical tools for reducing alert noise, reusing hunts, diagnosing the sensor, tracking cases, validating workflows, and managing data retention.")
    tabs = st.tabs(["Alert Noise Control", "Saved Hunt Queries", "Sensor Diagnostics", "Case Notes", "Safe Test Events", "Data Retention"])
    with tabs[0]:
        render_alert_noise_control()
    with tabs[1]:
        render_saved_hunt_queries_panel()
    with tabs[2]:
        render_sensor_diagnostics()
    with tabs[3]:
        render_case_notes()
    with tabs[4]:
        render_safe_test_generator()
    with tabs[5]:
        render_data_retention_controls()


def render_network_connection_map():
    render_page_heading("Network Connection Map")
    st.write("View which processes contacted which public IP addresses, along with observed ports and risk signals.")
    st.caption("This is a process-to-IP relationship view built from sensor metadata. It does not geolocate devices or send IPs to a map provider.")
    try:
        events, source = load_sensor_events(limit=5000)
    except Exception as error:
        st.error(f"Could not load network events: {error}")
        return
    if events.empty or "remote_ip" not in events:
        st.info("No network connection records are available yet.")
        return
    if "event_type" in events:
        network = events[events["event_type"].astype(str).eq("network_connection")].copy()
    else:
        network = events.copy()
    network = network[network["remote_ip"].notna()].copy()
    if network.empty:
        st.info("No outbound connection events were found in the current event window.")
        return
    def is_public(value):
        try:
            return ipaddress.ip_address(str(value).strip()).is_global
        except ValueError:
            return False
    network = network[network["remote_ip"].map(is_public)]
    if network.empty:
        st.info("No public destination IPs are present in the available records.")
        return
    if "process_name" not in network:
        network["process_name"] = "Unknown process"
    network["process_name"] = network["process_name"].fillna("Unknown process").astype(str)
    if "remote_port" not in network:
        network["remote_port"] = ""
    if "risk_score" not in network:
        network["risk_score"] = 0
    network["risk_score"] = pd.to_numeric(network["risk_score"], errors="coerce").fillna(0).clip(0,100)
    groups = network.groupby(["process_name", "remote_ip", "remote_port"], dropna=False).agg(
        observations=("remote_ip", "size"), max_risk=("risk_score", "max"),
    ).reset_index().sort_values(["max_risk", "observations"], ascending=False)
    st.caption(f"Source: {source} · {len(network)} connection observations · {network['remote_ip'].nunique()} public destination(s)")
    st.dataframe(groups.head(500), hide_index=True, width="stretch")
    edges = groups.head(80)
    dot = ["digraph Connections {", "rankdir=LR;", 'graph [bgcolor="transparent", pad="0.25"];', 'node [style="filled", fontname="Arial", fontsize="10"];', 'edge [fontname="Arial", fontsize="8", color="#58718a"];']
    process_nodes, ip_nodes = set(), set()
    for row in edges.itertuples(index=False):
        process = str(row.process_name)
        remote = str(row.remote_ip)
        process_id = "proc_" + hashlib.sha1(process.encode("utf-8", errors="replace")).hexdigest()[:12]
        ip_id = "ip_" + hashlib.sha1(remote.encode("utf-8", errors="replace")).hexdigest()[:12]
        if process_id not in process_nodes:
            label = json.dumps(process.replace("\n", " ")[:70], ensure_ascii=False)
            dot.append(f'{process_id} [label={label}, shape=box, fillcolor="#e9f2ff"];')
            process_nodes.add(process_id)
        if ip_id not in ip_nodes:
            dot.append(f'{ip_id} [label="{remote}", shape=ellipse, fillcolor="#e3f6ef"];')
            ip_nodes.add(ip_id)
        port = str(row.remote_port or "")
        risk = int(row.max_risk)
        label = json.dumps(f"port {port or '?'} · risk {risk}", ensure_ascii=False)
        dot.append(f'{process_id} -> {ip_id} [label={label}];')
    dot.append("}")
    st.graphviz_chart("\n".join(dot), width="stretch")
    csv = groups.to_csv(index=False).encode("utf-8-sig")
    st.download_button("Download connection map data (CSV)", csv, "network_connection_map.csv", "text/csv", key="network_map_csv")


def build_daily_summary(report_date):
    try:
        events, source = load_sensor_events(limit=10000)
    except Exception as error:
        events, source = pd.DataFrame(), f"unavailable ({type(error).__name__})"
    alerts = load_alerts()
    if not events.empty:
        time_col = next((col for col in ("occurred_at", "created_at") if col in events), None)
        if time_col:
            event_times = pd.to_datetime(events[time_col], errors="coerce", utc=True)
            events = events[event_times.dt.date.eq(report_date)].copy()
    if not alerts.empty and "created_at" in alerts:
        alert_times = pd.to_datetime(alerts["created_at"], errors="coerce", utc=True)
        todays_alerts = alerts[alert_times.dt.date.eq(report_date)].copy()
    else:
        todays_alerts = pd.DataFrame()
    if events.empty:
        high_risk_events = 0
        destination_count = 0
        event_type_counts = pd.Series(dtype=int)
        top_destinations = []
    else:
        risk = pd.to_numeric(events.get("risk_score", pd.Series(0, index=events.index)), errors="coerce").fillna(0)
        severity = events.get("severity", pd.Series("", index=events.index)).fillna("").astype(str).str.lower()
        high_risk_events = int((risk.ge(70) | severity.isin(["high", "critical"])).sum())
        destination_count = int(events.get("remote_ip", pd.Series(dtype=str)).dropna().nunique())
        event_type_counts = events.get("event_type", pd.Series("Unknown", index=events.index)).fillna("Unknown").astype(str).value_counts()
        top_destinations = events.get("remote_ip", pd.Series(dtype=str)).dropna().astype(str).value_counts().head(5).to_dict()
    open_alerts = int(alerts.get("status", pd.Series(dtype=str)).isin(["Open", "Acknowledged"]).sum()) if not alerts.empty else 0
    open_incidents_df = load_incidents()
    open_incidents = int(open_incidents_df.get("status", pd.Series(dtype=str)).isin(["Open", "Investigating", "Contained"]).sum()) if not open_incidents_df.empty else 0
    watchlist_alerts = int(todays_alerts.get("title", pd.Series(dtype=str)).astype(str).str.startswith("Watchlist match:").sum()) if not todays_alerts.empty else 0
    records = [
        {"Metric": "Report date (UTC)", "Value": report_date.isoformat()},
        {"Metric": "Event source", "Value": source},
        {"Metric": "Endpoint events", "Value": len(events)},
        {"Metric": "High-risk events (risk ≥ 70 or High/Critical)", "Value": high_risk_events},
        {"Metric": "Distinct public destination IPs", "Value": destination_count},
        {"Metric": "New alerts today", "Value": len(todays_alerts)},
        {"Metric": "Watchlist match alerts today", "Value": watchlist_alerts},
        {"Metric": "Currently open/acknowledged alerts", "Value": open_alerts},
        {"Metric": "Open/investigating incidents", "Value": open_incidents},
        {"Metric": "Top destination IPs", "Value": json.dumps(top_destinations, ensure_ascii=False)},
        {"Metric": "Event type counts", "Value": json.dumps(event_type_counts.to_dict(), ensure_ascii=False)},
    ]
    return pd.DataFrame(records), events, todays_alerts


def render_daily_security_summary():
    render_page_heading("Daily Security Summary")
    st.write("Create a UTC daily snapshot of endpoint events, alerts, destinations, and open incidents.")
    report_date = st.date_input("Summary date (UTC)", value=datetime.now(timezone.utc).date(), key="daily_summary_date")
    summary, events, alerts = build_daily_summary(report_date)
    st.dataframe(summary, hide_index=True, width="stretch")
    c1, c2, c3 = st.columns(3)
    c1.metric("Events", len(events))
    c2.metric("New alerts", len(alerts))
    incidents = load_incidents()
    c3.metric("Open incidents", int(incidents.get("status", pd.Series(dtype=str)).isin(["Open", "Investigating", "Contained"]).sum()) if not incidents.empty else 0)
    left, right = st.columns(2)
    with left:
        if st.download_button("Download daily summary (CSV)", summary.to_csv(index=False).encode("utf-8-sig"), f"security_summary_{report_date.isoformat()}.csv", "text/csv"):
            audit_event("daily_security_summary_exported", f"date={report_date}; format=csv")
    with right:
        if st.download_button("Download daily summary (PDF)", make_pdf(summary), f"security_summary_{report_date.isoformat()}.pdf", "application/pdf"):
            audit_event("daily_security_summary_exported", f"date={report_date}; format=pdf")
    if not alerts.empty:
        st.markdown("#### Alerts created that day")
        st.dataframe(alerts, hide_index=True, width="stretch")


def make_config_backup():
    watchlist = load_ioc_watchlist(enabled_only=False)
    rows = watchlist.astype(object).where(pd.notna(watchlist), None).to_dict("records")
    return {
        "format": "ai-cyber-threat-intelligence-config",
        "version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "detection_settings": get_detection_settings(),
        "ioc_watchlist": [
            {"indicator_type": row["indicator_type"], "indicator_value": row["indicator_value"], "label": row["label"], "enabled": bool(row["enabled"]), "source": row.get("source") or "Analyst supplied", "expires_at": row.get("expires_at")}
            for row in rows
        ],
        "secrets_included": False,
    }


def restore_config_backup(payload, replace_existing=False):
    if not isinstance(payload, dict) or payload.get("format") != "ai-cyber-threat-intelligence-config" or payload.get("version") != 1:
        raise ValueError("This is not a supported CTI configuration backup.")
    items = payload.get("ioc_watchlist")
    if not isinstance(items, list) or len(items) > 5000:
        raise ValueError("The backup watchlist must be a list of at most 5,000 indicators.")
    settings = payload.get("detection_settings", {})
    if not isinstance(settings, dict):
        raise ValueError("Detection settings in this backup are invalid.")
    endpoint_risk = max(0, min(100, int(settings.get("endpoint_alert_min_risk", 45))))
    anomaly_score = max(20, min(95, int(settings.get("ai_anomaly_min_score", 40))))
    cleaned = []
    allowed_types = {"ip address", "domain", "file hash"}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("A watchlist backup entry is malformed.")
        kind = str(item.get("indicator_type", "")).lower()
        if kind not in allowed_types:
            raise ValueError("A watchlist backup entry has an unsupported type.")
        value = validate_watchlist_indicator(kind, item.get("indicator_value", ""))
        expiry = item.get("expires_at")
        if expiry:
            try:
                expiry = datetime.fromisoformat(str(expiry)).date().isoformat()
            except ValueError as error:
                raise ValueError("A watchlist expiry date in the backup is invalid.") from error
        cleaned.append((kind, value, str(item.get("label") or "")[:120], int(bool(item.get("enabled", True))), str(item.get("source") or "Backup import")[:80], expiry))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with connect_db() as connection:
        if replace_existing:
            connection.execute("DELETE FROM ioc_watchlist")
        connection.executemany(
            "INSERT INTO ioc_watchlist (indicator_type, indicator_value, label, created_at, enabled, source, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET label=excluded.label, enabled=excluded.enabled, source=excluded.source, expires_at=excluded.expires_at",
            [(kind, value, label, now, enabled, source, expiry) for kind, value, label, enabled, source, expiry in cleaned],
        )
    save_detection_settings(endpoint_risk, anomaly_score)
    return len(cleaned), endpoint_risk, anomaly_score


def render_config_backup_restore():
    render_page_heading("Configuration Backup")
    st.write("Export or restore your IOC watchlist and detection thresholds.")
    st.warning("Backup contains indicator values and labels, but never includes passwords, SMTP credentials, API tokens, or API keys. Keep the downloaded file private.")
    payload = make_config_backup()
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    if st.download_button("Download configuration backup (JSON)", data, "cti_configuration_backup.json", "application/json"):
        audit_event("configuration_backup_exported", f"watchlist_entries={len(payload['ioc_watchlist'])}")
    st.markdown("#### Restore a backup")
    uploaded = st.file_uploader("Select a CTI configuration JSON file", type=["json"], key="config_backup_upload")
    replace_current = st.checkbox("Replace the current IOC watchlist", value=False, help="Leave unchecked to merge the backup entries. Detection thresholds are restored either way.")
    if uploaded is None:
        st.caption("Restore merges watchlist entries by default. Existing passwords and API settings are never changed.")
        return
    raw = uploaded.getvalue()
    if len(raw) > 2 * 1024 * 1024:
        st.error("The configuration file is larger than 2 MB.")
        return
    try:
        incoming = json.loads(raw.decode("utf-8"))
        if not isinstance(incoming, dict):
            raise ValueError("The uploaded JSON must contain a CTI configuration object.")
        if incoming.get("format") != "ai-cyber-threat-intelligence-config" or incoming.get("version") != 1:
            raise ValueError("Unsupported CTI configuration backup format.")
        st.json({"created_at_utc": incoming.get("created_at_utc"), "indicator_count": len(incoming.get("ioc_watchlist", [])), "detection_settings": incoming.get("detection_settings", {}), "secrets_included": False})
        if st.button("Restore configuration", type="primary", key="restore_config_button"):
            count, endpoint_risk, anomaly_score = restore_config_backup(incoming, replace_existing=replace_current)
            audit_event("configuration_backup_restored", f"entries={count}; replace={replace_current}; endpoint_min_risk={endpoint_risk}; ai_min_score={anomaly_score}")
            st.success(f"Configuration restored: {count} IOC entries and detection thresholds.")
            st.rerun()
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, AttributeError) as error:
        st.error(f"Could not restore this configuration: {error}")


def render_asset_inventory():
    render_page_heading("Multi-device Fleet View")
    st.write("Monitor enrolled endpoint sensors together, check their heartbeat, and assign readable names and tags.")
    st.caption("Device status comes from sensor heartbeats or the latest observed event. Inventory reflects reported telemetry, not a complete device or software scan.")
    try:
        events, source = load_sensor_events(limit=10000)
    except Exception as error:
        st.error(f"Could not load endpoint inventory: {type(error).__name__}")
        return
    try:
        sensors, heartbeat_source = load_cloud_sensor_heartbeats()
    except Exception:
        sensors, heartbeat_source = [], "unavailable"
    if events is None:
        events = pd.DataFrame()
    sensor_rows = []
    if not events.empty:
        if "sensor_id" not in events:
            events["sensor_id"] = "Local sensor"
        time_col = next((name for name in ("occurred_at", "created_at") if name in events), None)
        for sensor_id, group in events.groupby("sensor_id", dropna=False):
            times = pd.to_datetime(group[time_col], utc=True, errors="coerce") if time_col else pd.Series(dtype="datetime64[ns, UTC]")
            processes = sorted(set(group.get("process_name", pd.Series(dtype=str)).dropna().astype(str)) - {""})
            types = group.get("event_type", pd.Series("", index=group.index)).fillna("").astype(str)
            apps = sorted(set(group.loc[types.eq("application_installed"), "summary"].dropna().astype(str)))
            risks = pd.to_numeric(group.get("risk_score", pd.Series(0, index=group.index)), errors="coerce").fillna(0)
            sensor_rows.append({
                "Sensor ID": str(sensor_id),
                "Status": "Online" if time_col and not times.dropna().empty and (datetime.now(timezone.utc) - times.max().to_pydatetime()).total_seconds() <= 45 else "No recent event",
                "Latest event (UTC)": times.max().isoformat() if not times.dropna().empty else "Unknown",
                "Observed events": len(group),
                "Distinct processes": len(processes),
                "Installed-app events": len(apps),
                "Network events": int(types.str.startswith("network").sum()),
                "Highest observed risk": int(risks.max()) if len(risks) else 0,
            })
    for item in sensors:
        sensor_id = str(item.get("sensor_id") or "")
        if any(row["Sensor ID"] == sensor_id for row in sensor_rows):
            continue
        seen = pd.to_datetime(item.get("last_seen_at"), utc=True, errors="coerce")
        sensor_rows.append({
            "Sensor ID": sensor_id,
            "Status": "Online" if not pd.isna(seen) and (datetime.now(timezone.utc) - seen.to_pydatetime()).total_seconds() <= 45 else "Offline",
            "Latest event (UTC)": item.get("last_event_at") or "Unknown",
            "Observed events": 0, "Distinct processes": 0, "Installed-app events": 0, "Network events": 0, "Highest observed risk": 0,
        })
    heartbeat_by_id = {str(item.get("sensor_id") or ""): item for item in sensors}
    local_report = sensor_health_report(events, source) if source != "cloud" else None
    for row in sensor_rows:
        heartbeat = heartbeat_by_id.get(row["Sensor ID"])
        if heartbeat:
            seen = pd.to_datetime(heartbeat.get("last_seen_at"), utc=True, errors="coerce")
            age = (datetime.now(timezone.utc) - seen.to_pydatetime()).total_seconds() if not pd.isna(seen) else float("inf")
            row["Status"] = "Online" if age <= 45 else "Offline"
            row["Last heartbeat (UTC)"] = heartbeat.get("last_seen_at") or "Unknown"
        elif local_report is not None:
            local_status = str(local_report.get("status", "Unknown"))
            row["Status"] = "Online" if local_status == "Online" else "Offline" if local_status.lower().startswith(("offline", "stopped")) else local_status
            row["Last heartbeat (UTC)"] = local_report.get("last_heartbeat", "Unknown")
        else:
            row["Last heartbeat (UTC)"] = "Local heartbeat"
    with connect_db() as connection:
        for row in sensor_rows:
            connection.execute(
                "INSERT OR IGNORE INTO sensor_registry (sensor_id, display_name, tags, updated_at) VALUES (?, '', '', ?)",
                (row["Sensor ID"], datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
        registry = pd.read_sql_query("SELECT sensor_id, display_name, tags, criticality FROM sensor_registry", connection)
    registry_by_id = {str(item["sensor_id"]): item for item in registry.to_dict("records")}
    for row in sensor_rows:
        metadata = registry_by_id.get(row["Sensor ID"], {})
        row["Device"] = str(metadata.get("display_name") or row["Sensor ID"][:12])
        row["Tags"] = str(metadata.get("tags") or "")
        row["Criticality"] = str(metadata.get("criticality") or "Unclassified")
    criticality_bonus = {"Critical": 30, "High": 20, "Standard": 10, "Low": 0, "Unclassified": 5}
    fleet_priority = []
    for row in sensor_rows:
        event_risk = max(0, min(100, int(row.get("Highest observed risk", 0) or 0)))
        stale_bonus = 10 if str(row.get("Status", "")).lower() in ("offline", "no recent event") else 0
        priority = min(100, round(event_risk * 0.7 + criticality_bonus.get(row["Criticality"], 5) + stale_bonus))
        row["Triage priority"] = priority
        fleet_priority.append(priority)
    st.caption(f"Event source: {source} · Heartbeat source: {heartbeat_source} · Visible sensors: {len(sensor_rows)}")
    if not sensor_rows:
        st.info("No sensor inventory is available yet. Start the endpoint sensor and wait for its first event or heartbeat.")
        return
    fleet = pd.DataFrame(sensor_rows).sort_values("Triage priority", ascending=False, kind="stable")
    metrics = st.columns(4)
    metrics[0].metric("Devices", len(fleet))
    metrics[1].metric("Online", int(fleet["Status"].astype(str).eq("Online").sum()))
    metrics[2].metric("Offline / stale", int(fleet["Status"].astype(str).isin(["Offline", "No recent event"]).sum()))
    metrics[3].metric("Recent events", int(pd.to_numeric(fleet["Observed events"], errors="coerce").fillna(0).sum()))
    st.caption("Triage priority combines observed event risk, asset criticality, and stale status. It is a review-order aid, not a compromise probability or verdict.")
    if fleet_priority:
        st.metric("Highest-priority assets", sum(score >= 70 for score in fleet_priority))
    st.subheader("Sensor telemetry coverage")
    coverage_hours = st.selectbox(
        "Review window",
        [1, 6, 24, 168],
        index=2,
        format_func=lambda value: f"Last {value} hour(s)" if value < 24 else f"Last {value // 24} day(s)",
        key="sensor_coverage_window",
    )
    coverage_events = events.copy()
    if not coverage_events.empty and "sensor_id" not in coverage_events:
        coverage_events["sensor_id"] = "Local sensor"
    coverage_time_col = next((name for name in ("occurred_at", "created_at") if name in coverage_events), None)
    cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=int(coverage_hours))
    if not coverage_events.empty and coverage_time_col:
        coverage_events["_coverage_time"] = pd.to_datetime(coverage_events[coverage_time_col], errors="coerce", utc=True)
        coverage_events = coverage_events[coverage_events["_coverage_time"].ge(cutoff)].copy()
    elif not coverage_events.empty:
        st.warning("Event timestamps are unavailable, so the selected review window cannot be applied accurately.")
        coverage_events = coverage_events.iloc[0:0].copy()

    channel_matchers = {
        "File activity": lambda values: values.str.startswith("file_"),
        "Process starts": lambda values: values.str.startswith("process_"),
        "Installed apps": lambda values: values.eq("application_installed"),
        "Network connections": lambda values: values.str.contains("network|connection", regex=True),
    }
    coverage_rows = []
    missing_channels = []
    for sensor in sensor_rows:
        sensor_id = str(sensor["Sensor ID"])
        group = coverage_events[
            coverage_events.get("sensor_id", pd.Series("Local sensor", index=coverage_events.index))
            .fillna("Local sensor").astype(str).eq(sensor_id)
        ] if not coverage_events.empty else coverage_events
        types = group.get("event_type", pd.Series("", index=group.index)).fillna("").astype(str).str.lower()
        row = {
            "Device": str(sensor.get("Device") or sensor_id[:12]),
            "Sensor ID": sensor_id[:16],
            "Heartbeat": sensor.get("Status", "Unknown"),
        }
        missing = []
        for channel, matcher in channel_matchers.items():
            count = int(matcher(types).sum())
            row[channel] = count
            if count == 0:
                missing.append(channel)
                missing_channels.append((sensor_id, str(sensor.get("Device") or sensor_id[:12]), channel))
        row["No events observed"] = ", ".join(missing) if missing else "None"
        coverage_rows.append(row)
    st.caption(f"Counts are based on events in the most recent 10,000-record window and selected time range. ‘No events observed’ means no matching record was found; it does not prove a sensor failure.")
    st.dataframe(pd.DataFrame(coverage_rows), hide_index=True, width="stretch")
    if missing_channels:
        coverage_options = {
            f"{device} · {channel}": (sensor_id, device, channel)
            for sensor_id, device, channel in missing_channels
        }
        with st.form("sensor_coverage_review_form"):
            coverage_selection = st.selectbox("Potential gap to review", list(coverage_options))
            coverage_note = st.text_input("Analyst context (optional)", max_chars=240, placeholder="e.g. quiet workload, sensor filter, or expected behavior")
            coverage_submitted = st.form_submit_button("Create coverage review alert")
        if coverage_submitted:
            sensor_id, device, channel = coverage_options[coverage_selection]
            window_start = cutoff.isoformat()
            digest = hashlib.sha256(f"{sensor_id}|{channel}|{coverage_hours}|{cutoff.date().isoformat()}".encode("utf-8")).hexdigest()[:28]
            details = "\n".join([
                "Source: analyst-requested sensor telemetry coverage review",
                f"Device: {device}",
                f"Sensor ID: {sensor_id}",
                f"Channel with no observed events: {channel}",
                f"Review window: {coverage_hours} hour(s) since {window_start} UTC",
                f"Current heartbeat status: {next((item.get('Status', 'Unknown') for item in sensor_rows if str(item['Sensor ID']) == sensor_id), 'Unknown')}",
                f"Analyst context: {coverage_note.strip() or 'Not provided'}",
                "No endpoint scan or extra collection was started. A quiet event channel can be normal and requires verification.",
            ])
            created = add_alert(
                f"Telemetry coverage review: {channel} · {device[:60]}",
                "Medium",
                details,
                source_event_id=f"sensor-coverage-review:{digest}",
            )
            if created:
                st.success("Coverage review alert added to the Alert System.")
            else:
                st.info("This coverage review alert was already recorded for the selected time window.")
    status_filter = st.multiselect("Device status", sorted(fleet["Status"].dropna().astype(str).unique()), default=sorted(fleet["Status"].dropna().astype(str).unique()), key="fleet_status_filter")
    filtered_fleet = fleet[fleet["Status"].astype(str).isin(status_filter)]
    st.dataframe(filtered_fleet, hide_index=True, width="stretch")
    device_ids = fleet["Sensor ID"].astype(str).tolist()
    selected_sensor = st.selectbox("Device to label or inspect", device_ids, format_func=lambda value: f"{registry_by_id.get(value, {}).get('display_name') or value[:12]} · {value[:20]}")
    selected_meta = registry_by_id.get(selected_sensor, {})
    criticality_options = ["Critical", "High", "Standard", "Low", "Unclassified"]
    selected_criticality = str(selected_meta.get("criticality") or "Unclassified")
    if selected_criticality not in criticality_options:
        selected_criticality = "Unclassified"
    with st.form("sensor_registry_form"):
        display_name = st.text_input("Device name", value=str(selected_meta.get("display_name") or ""), max_chars=100)
        tags = st.text_input("Tags (comma-separated)", value=str(selected_meta.get("tags") or ""), max_chars=200, placeholder="finance, laptop, server")
        criticality = st.selectbox("Asset criticality", criticality_options, index=criticality_options.index(selected_criticality), help="Use your organization's asset inventory policy to classify business impact.")
        save_device = st.form_submit_button("Save device details")
    if save_device:
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO sensor_registry (sensor_id, display_name, tags, criticality, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(sensor_id) DO UPDATE SET display_name=excluded.display_name, tags=excluded.tags, criticality=excluded.criticality, updated_at=excluded.updated_at",
                (selected_sensor, display_name.strip(), tags.strip(), criticality, datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
        audit_event("fleet_device_details_updated", f"sensor_id={selected_sensor}; name={display_name.strip()[:100]}; criticality={criticality}")
        st.success("Device details saved.")
        st.rerun()
    if not events.empty:
        selected_events = events[events.get("sensor_id", pd.Series("Local sensor", index=events.index)).fillna("Local sensor").astype(str).eq(selected_sensor)].copy()
        st.markdown("#### Recent activity for selected device")
        if selected_events.empty:
            st.info("No event detail was included in the current event window for this device.")
        else:
            st.dataframe(selected_events[[column for column in ("occurred_at", "created_at", "event_type", "severity", "risk_score", "process_name", "remote_ip", "summary") if column in selected_events]].head(200), hide_index=True, width="stretch")
        process_rows = events[events.get("process_name", pd.Series("", index=events.index)).notna()].copy()
        if not process_rows.empty:
            st.markdown("#### Recently observed processes")
            st.dataframe(process_rows[[column for column in ("sensor_id", "occurred_at", "process_name", "event_type", "remote_ip", "risk_score") if column in process_rows]].head(300), hide_index=True, width="stretch")
        app_rows = events[events.get("event_type", pd.Series("", index=events.index)).astype(str).eq("application_installed")]
        if not app_rows.empty:
            st.markdown("#### Installed-application events")
            st.dataframe(app_rows[[column for column in ("sensor_id", "occurred_at", "summary", "details") if column in app_rows]].head(300), hide_index=True, width="stretch")
        st.download_button("Download fleet inventory (CSV)", fleet.to_csv(index=False).encode("utf-8-sig"), "multi_device_fleet.csv", "text/csv")


def render_suppression_rules():
    render_page_heading("Alert Suppression")
    if not require_admin():
        return
    st.write("Reduce repeated, approved activity from alert creation. Rules are exact matches and can expire automatically.")
    with st.form("suppression_rule_form", clear_on_submit=True):
        rule_type = st.selectbox("Match field", ["process", "remote_ip", "extension", "event_type"])
        rule_value = st.text_input("Exact value", max_chars=260)
        reason = st.text_input("Why this activity is trusted", max_chars=300)
        has_expiry = st.checkbox("Set an expiry date", value=True)
        expires_at = st.date_input("Rule expires (UTC)", value=datetime.now(timezone.utc).date() + timedelta(days=30), disabled=not has_expiry)
        submitted = st.form_submit_button("Save suppression rule")
    if submitted:
        value = rule_value.strip().lower()
        try:
            if rule_type == "remote_ip":
                value = str(ipaddress.ip_address(value))
            elif rule_type == "extension":
                value = value if value.startswith(".") else f".{value}"
                if not re.fullmatch(r"\.[a-z0-9]{1,12}", value):
                    raise ValueError("Enter a file extension such as .log or .exe.")
            elif not value or len(value) > 260 or any(ord(character) < 32 for character in value):
                raise ValueError("Enter a valid exact process or event-type value.")
            if not reason.strip():
                raise ValueError("Add a reason so analysts know why the activity is trusted.")
            expiry = expires_at.isoformat() if has_expiry else None
            with connect_db() as connection:
                connection.execute(
                    """INSERT INTO suppression_rules (rule_type, rule_value, reason, expires_at, enabled, created_at)
                       VALUES (?, ?, ?, ?, 1, ?)
                       ON CONFLICT(rule_type, rule_value) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at, enabled=1""",
                    (rule_type, value, reason.strip(), expiry, datetime.now(timezone.utc).isoformat(timespec="seconds")),
                )
            audit_event("suppression_rule_saved", f"type={rule_type}; value={value}; expires={expiry or 'never'}")
            st.success("Suppression rule saved. Matching new endpoint and IOC alerts will be suppressed until it expires or is disabled.")
            st.rerun()
        except ValueError as error:
            st.error(str(error))
    rules = load_suppression_rules()
    with connect_db() as connection:
        count_row = connection.execute("SELECT value FROM app_state WHERE key='suppressed_event_total'").fetchone()
    st.metric("Endpoint events suppressed since this database was created", int(count_row[0]) if count_row and str(count_row[0]).isdigit() else 0)
    if rules.empty:
        st.info("No suppression rules are configured.")
        return
    today = datetime.now(timezone.utc).date().isoformat()
    display = rules.copy()
    display["Status"] = display.apply(lambda row: "Expired" if row.get("expires_at") and str(row["expires_at"]) < today else "Active" if row.get("enabled") else "Disabled", axis=1)
    st.dataframe(display.rename(columns={"rule_type":"Match field","rule_value":"Exact value","reason":"Reason","expires_at":"Expires (UTC)","created_at":"Created (UTC)"})[["id","Match field","Exact value","Reason","Expires (UTC)","Status"]], hide_index=True, width="stretch")
    selected = st.selectbox("Rule to manage", rules["id"].astype(int).tolist(), key="suppression_rule_selected")
    selected_row = rules.loc[rules["id"] == selected].iloc[0]
    left, right = st.columns(2)
    with left:
        if st.button("Disable rule" if bool(selected_row["enabled"]) else "Enable rule", key="suppression_rule_toggle"):
            with connect_db() as connection:
                connection.execute("UPDATE suppression_rules SET enabled=? WHERE id=?", (0 if bool(selected_row["enabled"]) else 1, int(selected)))
            audit_event("suppression_rule_toggled", f"id={selected}; enabled={not bool(selected_row['enabled'])}")
            st.rerun()
    with right:
        if st.button("Delete rule", key="suppression_rule_delete"):
            with connect_db() as connection:
                connection.execute("DELETE FROM suppression_rules WHERE id=?", (int(selected),))
            audit_event("suppression_rule_deleted", f"id={selected}")
            st.rerun()


def render_access_roles():
    render_page_heading("Access & Roles")
    if not require_admin():
        return
    st.write("Accounts and passwords are read from private app settings. Passwords are never saved in the project database.")
    accounts = configured_accounts()
    if not accounts:
        st.error("No role accounts are configured. Add an Admin username and password to the private settings.")
        return
    st.dataframe(pd.DataFrame([{"Username": user, "Role": role, "Password stored": "Private settings only"} for user, _password, role in accounts]), hide_index=True, width="stretch")
    st.markdown("#### Configure accounts")
    st.write("Set these values in local .streamlit/secrets.toml or Streamlit Cloud App settings → Secrets. The legacy APP_USERNAME / APP_PASSWORD pair is treated as an Admin account.")
    st.code('APP_ADMIN_USERNAME = "admin-name"\nAPP_ADMIN_PASSWORD = "use-a-long-unique-password"\nAPP_ANALYST_USERNAME = "analyst-name"\nAPP_ANALYST_PASSWORD = "use-a-different-long-password"')
    st.markdown("#### Permissions")
    st.dataframe(pd.DataFrame([
        {"Role": "Admin", "Access": "All modules; manage suppression rules, scheduled reports, role settings, detection tuning, and configuration backups."},
        {"Role": "Analyst", "Access": "Review telemetry, investigate alerts/incidents, use response playbooks, and export reports."},
    ]), hide_index=True, width="stretch")
    st.caption("After changing account Secrets, restart the desktop app or let Streamlit Cloud redeploy. Role separation applies to the app UI; use network access controls for the host/API.")


def alert_playbook_kind(alert):
    text = f"{alert.get('title', '')} {alert.get('details', '')}".lower()
    if any(token in text for token in ("network_connection", "remote ip", "destination", "watchlist match", "c2")):
        return "network"
    if any(token in text for token in ("file_", "sha-256", "sha256", "file hash", "file created")):
        return "file"
    if any(token in text for token in ("process_", "process name", "application_installed")):
        return "process"
    return "default"


def render_response_playbook(alert):
    kind = alert_playbook_kind(alert)
    steps = RESPONSE_PLAYBOOKS[kind]
    st.markdown(f"#### Response playbook · {kind.title()}")
    st.caption("Guidance only. These steps do not block traffic, stop processes, quarantine files, or otherwise change the endpoint.")
    with connect_db() as connection:
        saved = {row[0]: bool(row[1]) for row in connection.execute("SELECT step_key, completed FROM response_playbook_progress WHERE alert_id = ?", (int(alert["id"]),)).fetchall()}
    checked = {}
    with st.form(f"response_playbook_form_{int(alert['id'])}"):
        for index, step in enumerate(steps):
            key = f"{kind}_{index}"
            widget_key = f"response_playbook_{int(alert['id'])}_{key}"
            if widget_key not in st.session_state:
                st.session_state[widget_key] = saved.get(key, False)
            checked[key] = st.checkbox(step, key=widget_key)
        submitted = st.form_submit_button("Save playbook progress")
    if submitted:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with connect_db() as connection:
            connection.executemany(
                """INSERT INTO response_playbook_progress (alert_id, step_key, completed, updated_at) VALUES (?, ?, ?, ?)
                   ON CONFLICT(alert_id, step_key) DO UPDATE SET completed=excluded.completed, updated_at=excluded.updated_at""",
                [(int(alert["id"]), key, int(done), now) for key, done in checked.items()],
            )
        record_alert_timeline(int(alert["id"]), "Response playbook updated", f"{kind.title()} playbook progress: {sum(checked.values())}/{len(steps)} steps complete.")
        audit_event("response_playbook_updated", f"alert_id={int(alert['id'])}; type={kind}; completed={sum(checked.values())}/{len(steps)}")
        st.success("Response playbook progress saved.")
        st.rerun()


def load_report_schedule():
    with connect_db() as connection:
        row = connection.execute("SELECT enabled, cadence, send_time_utc, recipient, last_sent_at, last_attempt_slot, last_error FROM scheduled_reports WHERE id=1").fetchone()
    return dict(zip(("enabled","cadence","send_time_utc","recipient","last_sent_at","last_attempt_slot","last_error"), row)) if row else {}


def save_report_schedule(enabled, cadence, send_time, recipient):
    with connect_db() as connection:
        connection.execute("UPDATE scheduled_reports SET enabled=?, cadence=?, send_time_utc=?, recipient=?, last_error='' WHERE id=1", (int(enabled), cadence, send_time, recipient))
    audit_event("scheduled_report_settings_saved", f"enabled={enabled}; cadence={cadence}; time_utc={send_time}; recipient={recipient[:120]}")


@st.fragment(run_every="15m")
def threat_feed_health_worker():
    try:
        load_feodo_feed()
    except Exception:
        pass
    last_success = read_app_state("threat_feed_last_success_at")
    parsed = pd.to_datetime(last_success, utc=True, errors="coerce") if last_success else pd.NaT
    if not pd.isna(parsed) and (datetime.now(timezone.utc) - parsed.to_pydatetime()).total_seconds() > 24 * 3600:
        add_alert(
            "Threat intelligence feed is stale", "Medium",
            f"Feodo Tracker last succeeded at {last_success}. Verify source connectivity before relying on this feed.",
            source_event_id=f"feed-stale:{datetime.now(timezone.utc).date().isoformat()}",
        )


@st.fragment(run_every="60s")
def scheduled_report_worker():
    schedule = load_report_schedule()
    if not schedule.get("enabled") or not schedule.get("recipient"):
        return
    try:
        hour, minute = (int(part) for part in str(schedule["send_time_utc"]).split(":"))
        now = datetime.now(timezone.utc)
        sent_at = pd.to_datetime(schedule.get("last_sent_at"), utc=True, errors="coerce")
        days = 1 if schedule.get("cadence") == "Daily" else 7
        due_date = now.date() if pd.isna(sent_at) else sent_at.date() + timedelta(days=days)
        due_at = datetime.combine(due_date, datetime.min.time(), tzinfo=timezone.utc).replace(hour=hour, minute=minute)
        if now < due_at:
            return
        slot = now.date().isoformat()
        if schedule.get("last_attempt_slot") == slot:
            return
        with connect_db() as connection:
            claimed = connection.execute(
                "UPDATE scheduled_reports SET last_attempt_slot=? WHERE id=1 AND (last_attempt_slot IS NULL OR last_attempt_slot != ?)",
                (slot, slot),
            )
            if claimed.rowcount == 0:
                return
        summary, _events, _alerts = build_daily_summary(now.date())
        body = "Scheduled security summary (UTC)\n\n" + "\n".join(f"{row['Metric']}: {row['Value']}" for row in summary.to_dict("records"))
        try:
            send_security_email(f"AI Cyber Threat Intelligence — {schedule['cadence'].lower()} summary", body, recipient_override=schedule["recipient"])
            with connect_db() as connection:
                connection.execute("UPDATE scheduled_reports SET last_sent_at=?, last_error='' WHERE id=1", (now.isoformat(timespec="seconds"),))
            audit_event("scheduled_security_report_sent", f"cadence={schedule['cadence']}; recipient={schedule['recipient'][:120]}")
            st.toast("Scheduled security summary sent.", icon="✉️")
        except Exception as error:
            with connect_db() as connection:
                connection.execute("UPDATE scheduled_reports SET last_error=? WHERE id=1", (str(error)[:500],))
            audit_event("scheduled_security_report_failed", f"error={str(error)[:300]}")
    except (TypeError, ValueError, KeyError):
        return


def render_scheduled_reports():
    render_page_heading("Scheduled Reports")
    if not require_admin():
        return
    current = load_report_schedule()
    st.write("Email a UTC daily or weekly security summary to an authorized recipient.")
    provider = setting("EMAIL_PROVIDER", "smtp").lower()
    provider_ready = bool(setting("RESEND_API_KEY")) and bool(setting("RESEND_FROM")) if provider == "resend" else bool(setting("SMTP_HOST")) and bool(setting("SMTP_FROM") or setting("SMTP_USERNAME"))
    st.caption(f"Delivery provider: {provider} · Credentials: {'configured' if provider_ready else 'incomplete'}. This schedule is opt-in and separate from the alert email switch.")
    if not provider_ready:
        st.info("Configure the selected email provider in private settings before enabling scheduled delivery.")
    with st.form("scheduled_report_settings_form"):
        enabled = st.checkbox("Enable scheduled summary email", value=bool(current.get("enabled")))
        cadence = st.selectbox("Frequency", ["Daily", "Weekly"], index=0 if current.get("cadence", "Daily") == "Daily" else 1)
        send_time = st.time_input("Send after this UTC time", value=datetime.strptime(current.get("send_time_utc", "09:00"), "%H:%M").time())
        recipient = st.text_input("Report recipient", value=current.get("recipient", ""), max_chars=254)
        submitted = st.form_submit_button("Save schedule")
    if submitted:
        parsed = parseaddr(recipient.strip())[1]
        if enabled and (parsed != recipient.strip() or any(ord(character) < 32 for character in recipient) or "@" not in parsed or "." not in parsed.rsplit("@", 1)[-1]):
            st.error("Enter a valid report recipient email address.")
        else:
            save_report_schedule(enabled, cadence, send_time.strftime("%H:%M"), parsed)
            st.success("Scheduled report settings saved.")
            st.rerun()
    updated = load_report_schedule()
    st.write(f"Enabled: {'Yes' if updated.get('enabled') else 'No'} · Last sent (UTC): {updated.get('last_sent_at') or 'Never'}")
    if updated.get("last_error"):
        st.error(f"Last delivery failed: {updated['last_error']}")
    st.warning("The in-app scheduler sends when this dashboard has an active session and is refreshing. It cannot guarantee delivery while the cloud app or desktop process is stopped; use an always-on mail scheduler for guaranteed delivery.")
    if st.button("Send a scheduled-report test now", disabled=not updated.get("recipient")):
        try:
            summary, _events, _alerts = build_daily_summary(datetime.now(timezone.utc).date())
            body = "Scheduled security summary test (UTC)\n\n" + "\n".join(f"{row['Metric']}: {row['Value']}" for row in summary.to_dict("records"))
            send_security_email("AI Cyber Threat Intelligence — scheduled report test", body, recipient_override=updated["recipient"])
            audit_event("scheduled_security_report_test_sent", f"recipient={updated['recipient'][:120]}")
            st.success("Test summary sent.")
        except Exception as error:
            st.error(f"Could not send the test summary: {error}")


def render_threat_feed_health():
    render_page_heading("Threat Feed Health")
    st.write("Check the last successful Feodo Tracker update and whether its cached data may be stale.")
    last_success = read_app_state("threat_feed_last_success_at")
    last_attempt = read_app_state("threat_feed_last_attempt_at")
    last_error = read_app_state("threat_feed_last_error")
    count = read_app_state("threat_feed_indicator_count", "Unknown")
    parsed = pd.to_datetime(last_success, utc=True, errors="coerce") if last_success else pd.NaT
    age_hours = (datetime.now(timezone.utc) - parsed.to_pydatetime()).total_seconds() / 3600 if not pd.isna(parsed) else None
    stale = age_hours is not None and age_hours > 24
    c1, c2, c3 = st.columns(3)
    c1.metric("Feed status", "Stale" if stale else "Fresh" if age_hours is not None else "Not checked")
    c2.metric("Last successful fetch (UTC)", str(last_success or "Never"))
    c3.metric("Indicators in last feed", str(count))
    st.write(f"Last attempt (UTC): {last_attempt or 'Never'}")
    c1, c2 = st.columns(2)
    c1.metric("VirusTotal API", "Configured" if setting("VT_API_KEY") else "Not configured")
    c2.metric("AbuseIPDB API", "Configured" if setting("ABUSEIPDB_API_KEY") else "Not configured")
    if last_error:
        st.error(f"Most recent feed error: {last_error}")
    if stale:
        st.warning("The last successful Feodo Tracker data is more than 24 hours old. Refresh the Threat Feed and confirm network access.")
        add_alert("Threat intelligence feed is stale", "Medium", f"Feodo Tracker last succeeded at {last_success}; current age is about {age_hours:.1f} hours. Verify source connectivity before relying on this feed.", source_event_id=f"feed-stale:{datetime.now(timezone.utc).date().isoformat()}")
    elif age_hours is None:
        st.info("Open Threat Feed and select Refresh threat feed to record the first successful fetch.")
    else:
        st.success(f"Feed data was last refreshed {age_hours:.1f} hours ago.")


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
                accounts = configured_accounts()
                if not accounts:
                    st.error("Authentication is not configured.")
                    st.code(
                        'APP_ADMIN_USERNAME = "admin"\n'
                        'APP_ADMIN_PASSWORD = "choose-a-long-unique-password"\n'
                        'APP_ANALYST_USERNAME = "analyst"\n'
                        'APP_ANALYST_PASSWORD = "a-different-unique-password"'
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
                    matched_account = next(
                        (
                            account for account in accounts
                            if hmac.compare_digest(username.strip(), account[0])
                            and hmac.compare_digest(password, account[1])
                        ),
                        None,
                    )
                    if matched_account:
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = username.strip()
                        st.session_state["user_role"] = matched_account[2]
                        audit_event("login_success", f"Configured {matched_account[2]} account authenticated.", username.strip())
                        st.rerun()
                    else:
                        audit_event("login_failure", f"Invalid sign-in attempt for username: {username.strip()[:80]}", username.strip() or "anonymous")
                        st.error("The username or password is incorrect.")
        st.stop()

    report = load_report()
    if "user_role" not in st.session_state:
        st.session_state["user_role"] = "Admin"
    st.sidebar.markdown(
        '<div class="cti-brand"><div class="cti-brand-mark">SOC</div>'
        '<div><div class="cti-brand-name">SOC WORKSTATION</div>'
        '<span class="cti-brand-sub">LIVE THREAT OPERATIONS</span></div></div>',
        unsafe_allow_html=True,
    )
    st.sidebar.markdown(
        f'<div class="cti-session"><span class="cti-dot"></span> {st.session_state["user_role"]} session active</div>',
        unsafe_allow_html=True,
    )
    if st.sidebar.button("Log out", width="stretch"):
        audit_event("logout", "User signed out.")
        st.session_state["authenticated"] = False
        st.session_state["email_alerts_enabled_this_session"] = False
        st.session_state.pop("username", None)
        st.session_state.pop("user_role", None)
        st.rerun()

    pages = [
        "Main Dashboard",
        "Security Operations Toolkit",
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
        "IOC Watchlist",
        "Detection Tuning",
        "Custom Detection Rule Builder",
        "Event Correlation Graph",
        "Threat Hunting",
        "Network Connection Map",
        "Daily Security Summary",
        "Configuration Backup",
        "Multi-device Fleet View",
        "Alert Suppression",
        "Scheduled Reports",
        "Access & Roles",
        "Threat Feed Health",
        "Audit Log & Access",
    ]
    if not is_admin():
        pages = [page for page in pages if page not in {"Alert Suppression", "Scheduled Reports", "Access & Roles", "Configuration Backup", "Detection Tuning", "IOC Watchlist"}]
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
        "Security Operations Toolkit": "⚒",
        "Incident Management": "▣",
        "Report Generator": "▤",
        "Log Analyzer": "⌁",
        "IOC Watchlist": "◈",
        "Detection Tuning": "⚙",
        "Custom Detection Rule Builder": "⌘",
        "Event Correlation Graph": "⤳",
        "Threat Hunting": "⌕",
        "Network Connection Map": "⇄",
        "Daily Security Summary": "▤",
        "Configuration Backup": "▣",
        "Multi-device Fleet View": "▦",
        "Alert Suppression": "⊘",
        "Scheduled Reports": "◷",
        "Access & Roles": "♙",
        "Threat Feed Health": "◌",
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
    elif page == "Security Operations Toolkit":
        render_security_operations_toolkit()
    elif page == "Incident Management":
        render_incident_management()
    elif page == "Report Generator":
        render_reports(report)
    elif page == "Log Analyzer":
        render_log_analyzer()
    elif page == "IOC Watchlist":
        render_ioc_watchlist()
    elif page == "Detection Tuning":
        render_detection_tuning()
    elif page == "Custom Detection Rule Builder":
        render_detection_rule_builder()
    elif page == "Event Correlation Graph":
        render_event_correlation_graph()
    elif page == "Threat Hunting":
        render_threat_hunting()
    elif page == "Network Connection Map":
        render_network_connection_map()
    elif page == "Daily Security Summary":
        render_daily_security_summary()
    elif page == "Configuration Backup":
        render_config_backup_restore()
    elif page == "Multi-device Fleet View":
        render_asset_inventory()
    elif page == "Alert Suppression":
        render_suppression_rules()
    elif page == "Scheduled Reports":
        render_scheduled_reports()
    elif page == "Access & Roles":
        render_access_roles()
    elif page == "Threat Feed Health":
        render_threat_feed_health()
    elif page == "Audit Log & Access":
        render_audit_log()
    threat_feed_health_worker()
    scheduled_report_worker()


if __name__ == "__main__":
    main()
