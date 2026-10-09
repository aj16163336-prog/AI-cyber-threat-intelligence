from datetime import datetime, timezone
from io import BytesIO, StringIO
import hmac
import ipaddress
import os
import sqlite3
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

from live_capture import capture_summary, list_interfaces

BASE_DIR = Path(__file__).parent
REPORT_PATH = BASE_DIR / "threat_report.csv"
DATABASE_PATH = BASE_DIR / "security_center.db"
FEODO_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
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
    try:
        value = st.secrets.get(name, default)
    except Exception:
        value = default
    return str(value or os.environ.get(name, default)).strip()


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
                status TEXT NOT NULL DEFAULT 'Open'
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


def load_alerts():
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY id DESC", connection
        )


def load_incidents():
    with connect_db() as connection:
        return pd.read_sql_query(
            "SELECT * FROM incidents ORDER BY id DESC", connection
        )


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
    page_width, page_height = letter
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
    pdf.drawString(45, y, f"Detected report records: {len(report)}")
    y -= 22
    pdf.drawString(45, y, "Sample rows (up to 35):")
    y -= 18

    for _, row in report.head(35).iterrows():
        text = (
            f"ID {row.get('id', '')} | "
            f"{row.get('predicted_category', '')} | "
            f"Risk {row.get('risk_score', '')} | "
            f"{row.get('risk_level', '')}"
        )
        pdf.drawString(45, y, text[:105])
        y -= 15
        if y < 55:
            pdf.showPage()
            y = page_height - 50
            pdf.setFont("Helvetica", 10)

    pdf.save()
    return buffer.getvalue()


def render_dashboard(report):
    st.title("Main Dashboard")
    st.caption("Network activity summary and UNSW-NB15 model results.")

    alerts = load_alerts()
    incidents = load_incidents()
    live = st.session_state.get("live_summary", {})

    total_records = len(report)
    critical = (
        int((report["risk_level"].astype(str) == "Critical").sum())
        if "risk_level" in report.columns
        else 0
    )
    average_score = (
        round(float(report["risk_score"].mean()), 1)
        if "risk_score" in report.columns and not report.empty
        else 0
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Dataset detections", total_records)
    col2.metric("Critical dataset risks", critical)
    col3.metric("Open alerts", int((alerts["status"] == "Open").sum()) if not alerts.empty else 0)
    col4.metric("Open incidents", int((incidents["status"] == "Open").sum()) if not incidents.empty else 0)

    if not report.empty and "risk_level" in report.columns:
        left, right = st.columns(2)
        with left:
            st.subheader("Risk levels")
            counts = report["risk_level"].astype(str).value_counts().reindex(
                ["Low", "Medium", "High", "Critical"], fill_value=0
            )
            st.bar_chart(counts)
        with right:
            st.subheader("Predicted attack categories")
            st.bar_chart(report["predicted_category"].value_counts())

    st.subheader("Live monitor")
    if live:
        a, b, c = st.columns(3)
        a.metric("Packets in last capture", live["packets"])
        b.metric("Packets per second", live["packets_per_second"])
        c.metric("Unique destination ports", len(live["destination_ports"]))
    else:
        st.info("No live capture is available yet. Start a capture from Live Monitor.")

    st.subheader("Recent alerts")
    if alerts.empty:
        st.write("No alerts have been recorded.")
    else:
        st.dataframe(alerts.head(5), hide_index=True, width="stretch")


def render_live_monitor():
    st.title("Live Network Monitor")
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
                st.bar_chart(pd.Series(summary["protocols"]).sort_values(ascending=False))
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
    st.title("Live Endpoint Security")
    st.write(
        "The local sensor records event metadata for files in Downloads, Desktop, and "
        "Documents, newly started processes, installed applications, and public "
        "outbound connections."
    )
    st.caption(
        "File contents and packet payloads are never uploaded. Full file paths stay in "
        "the local database; cloud sync sends only the folder label, filename, and SHA-256."
    )
    st.info(
        "Run the sensor separately from the dashboard: open a new VS Code terminal in "
        "the project folder and run `python endpoint_monitor.py`. Stop it with Ctrl+C. "
        "To sync events to the cloud, configure CTI_API_URL and CTI_API_TOKEN in the "
        "sensor terminal."
    )

    try:
        events, source = load_sensor_events()
    except Exception as error:
        st.error(f"Could not load sensor events: {error}")
        return

    st.caption("Event source: " + ("deployed API" if source == "cloud" else "this computer"))
    if events.empty:
        st.info("No events have arrived yet. Start the sensor, then refresh the event list.")
        if st.button("Refresh events"):
            st.rerun()
        return

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
    if st.button("Refresh events"):
        st.rerun()


def render_threat_feed():
    st.title("Threat Feed")
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
    st.title("IOC Analysis")
    st.write("Check an IP address against the current Feodo Tracker feed.")
    ioc_text = st.text_input("IPv4 address", placeholder="Example: 203.0.113.10")
    if st.button("Check IOC", type="primary"):
        try:
            address = ipaddress.ip_address(ioc_text.strip())
            if address.version != 4:
                st.warning("This feed contains IPv4 indicators only.")
                return
            feed = load_feodo_feed()
            if feed.empty:
                st.info("The threat feed is empty, so an indicator match cannot be checked right now.")
                return
            matches = feed[feed["dst_ip"] == str(address)]
            if matches.empty:
                st.success("No match for this IP was found in the current feed.")
            else:
                st.error("A feed match was found. An alert was created for analyst review.")
                st.dataframe(matches, hide_index=True, width="stretch")
                add_alert(
                    "IOC match from manual analysis",
                    "High",
                    f"Entered IPv4 matched {len(matches)} Feodo Tracker record(s).",
                    "",
                )
        except ValueError:
            st.error("Enter a valid IPv4 address.")
        except Exception as error:
            st.error(f"Could not check the indicator: {error}")


def render_analytics(report):
    st.title("Analytics Dashboard")
    if report.empty:
        st.info("threat_report.csv was not found. Run main.py to generate the report.")
        return

    left, right = st.columns(2)
    with left:
        st.subheader("Risk-level distribution")
        if "risk_level" in report:
            st.bar_chart(report["risk_level"].astype(str).value_counts())
    with right:
        st.subheader("Attack-category distribution")
        if "predicted_category" in report:
            st.bar_chart(report["predicted_category"].value_counts())

    if "risk_score" in report:
        st.subheader("Risk-score summary")
        st.write(report["risk_score"].describe())


def render_ai_engine(report):
    st.title("AI Engine")
    st.write("Historical UNSW-NB15 model results and current endpoint monitoring signals.")
    c1, c2 = st.columns(2)
    c1.metric("UNSW binary detection accuracy", "83.3%")
    c2.metric("UNSW attack-category accuracy", "73.0%")

    st.subheader("Detection and classification")
    st.write(
        "The Random Forest model in main.py predicts Normal vs Attack and attack "
        "categories using the UNSW-NB15 training and testing split."
    )
    if not report.empty:
        st.write(f"Generated dataset threat records: {len(report)}")
        st.dataframe(report.head(10), hide_index=True, width="stretch")

    st.subheader("Live anomaly signals")
    st.write(
        "The local sensor records file, process, and connection activity. Current live "
        "assessments use detection rules and IOC matches; raw endpoint events do not "
        "contain the 42 flow features used by the UNSW-NB15 model."
    )
    st.info(
        "UNSW-NB15 scores describe performance on that historical dataset. Live endpoint "
        "events are assessed with rules and the Feodo IP feed; the UNSW model is not used "
        "to classify endpoint events."
    )


def render_mitre_map():
    st.title("MITRE ATT&CK Map")
    st.write("Possible technique references associated with signals. Review each mapping.")
    mapping = pd.DataFrame(MITRE_ROWS)
    st.dataframe(mapping.drop(columns=["Reference"]), hide_index=True, width="stretch")
    for row in MITRE_ROWS:
        st.markdown(f"- [{row['Technique ID']} — {row['Technique']}]({row['Reference']})")


def render_alert_system():
    st.title("Alert System")
    alerts = load_alerts()
    if alerts.empty:
        st.info("No alerts have been recorded. Alerts are created by live capture or IOC matches.")
        return

    st.dataframe(alerts, hide_index=True, width="stretch")
    alert_ids = alerts["id"].astype(int).tolist()
    selected_id = st.selectbox("Alert to update", alert_ids)
    new_status = st.selectbox("New alert status", ["Open", "Acknowledged", "Closed"])
    if st.button("Save alert status"):
        with connect_db() as connection:
            connection.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (new_status, int(selected_id)),
            )
        st.success("Alert status updated.")
        st.rerun()


def render_incident_management():
    st.title("Incident Management")
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
        st.success("Incident status updated.")
        st.rerun()


def render_reports(report):
    st.title("Report Generator")
    if report.empty:
        st.info("threat_report.csv was not found. Run main.py to generate the report.")
        return

    st.write(f"Threat records ready: {len(report)}")
    st.download_button(
        "Download full CSV report",
        data=report.to_csv(index=False).encode("utf-8"),
        file_name="threat_report.csv",
        mime="text/csv",
        width="stretch",
    )

    try:
        pdf_data = make_pdf(report)
        st.download_button(
            "Download PDF report",
            data=pdf_data,
            file_name="threat_report.pdf",
            mime="application/pdf",
            width="stretch",
        )
    except ImportError:
        st.warning("Install the PDF package to enable PDF downloads.")
        st.code("pip install reportlab")

    alerts = load_alerts()
    if not alerts.empty:
        st.download_button(
            "Download alerts CSV",
            data=alerts.to_csv(index=False).encode("utf-8"),
            file_name="security_alerts.csv",
            mime="text/csv",
        )


def main():
    st.set_page_config(
        page_title="AI Cyber Threat Intelligence",
        page_icon="🛡️",
        layout="wide",
    )
    init_database()

    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        st.title("AI Cyber Threat Intelligence")
        st.subheader("Login")
        st.caption("Use the private login values stored in your local/deployment secrets.")
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
            submitted = st.form_submit_button("Login", type="primary")
        if submitted:
            if hmac.compare_digest(username.strip(), expected_username) and hmac.compare_digest(password, expected_password):
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("The username or password is incorrect.")
        st.stop()

    report = load_report()
    st.sidebar.title("Navigation")
    st.sidebar.success("Logged in")
    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()

    pages = [
        "Main Dashboard",
        "Live Monitor",
        "Endpoint Security",
        "Threat Feed",
        "IOC Analysis",
        "Analytics Dashboard",
        "AI Engine",
        "MITRE ATT&CK Map",
        "Alert System",
        "Incident Management",
        "Report Generator",
    ]
    page = st.sidebar.radio("Open module", pages)

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
    elif page == "MITRE ATT&CK Map":
        render_mitre_map()
    elif page == "Alert System":
        render_alert_system()
    elif page == "Incident Management":
        render_incident_management()
    elif page == "Report Generator":
        render_reports(report)


if __name__ == "__main__":
    main()
