# AI Cyber Threat Intelligence

Windows endpoint and network monitoring project with a local sensor, authenticated event API, threat-feed lookups, analyst dashboard, alert/incident tracking, and CSV/PDF reports.

## Current monitoring scope

- Local sensor watches `Downloads`, `Desktop`, and `Documents` for file create, move, and modification events; it calculates SHA-256 locally for files up to 100 MB.
- It observes newly started processes, newly registered Windows applications, and public outbound TCP/UDP connection metadata.
- It checks remote IPv4 destinations against the public Feodo Tracker C2 feed.
- The sensor stores full local paths in the laptop's SQLite database. Cloud sync sends only event metadata: folder label, filename, file hash, process name, remote IP/port, event summary, and risk fields. File contents and packet payloads are never uploaded.
- A file extension or feed match is a review signal, not proof that a file or device is infected. The sensor does not delete, quarantine, or block traffic.
- The UNSW-NB15 Random Forest remains a historical flow-dataset benchmark. It is kept separate from live endpoint signals; no mismatched live features are sent into that model.
- The AI Engine refreshes endpoint event metadata every 5 seconds and runs a rolling Isolation Forest after collecting enough events. The Explainable AI Assistant refreshes every 10 seconds. The Alert Center refreshes every 5 seconds and shows a combined risk score, severity, and signal reasons; these are triage signals, not a malware verdict.
- The Explainable AI Assistant presents the selected event's risk components, reasons, and suggested analyst checks. The AI Model Evaluation Lab measures accuracy, balanced accuracy, F1, per-class results, confusion matrix, and feature importance on a held-out split. CSV upload is enabled only in the local desktop app; the bundled UNSW-NB15 train/test files can also be evaluated when present.
- The local Isolation Forest remains the automatic live anomaly detector. OpenAI reviews have two modes: manual event/evaluation reviews require a consent checkbox and a button click; optional live event reviews can be enabled in AI Engine. When enabled and `OPENAI_API_KEY` is configured, the live reviewer queues only new events with risk 70 or higher plus an anomaly or threat-feed match, at most once per minute and 10 times per hour. It sends allow-listed event metadata (type/time, severity and risk scores, anomaly/IOC flags, rule-generated indicators, process name, and remote IP/port). It never sends file contents, full paths, file hashes, or raw CSV rows. Requests use the Responses API with `store: false` and no tools; provider API usage may be billed separately. GPT-5.4 Mini is the default model and can be changed with `OPENAI_MODEL`. The live ML detector works without an OpenAI key.
- AI Engine maintains a bounded, per-device baseline from unique endpoint events and flags new event types/processes or unusually high sensor risk after at least 20 prior events for that sensor. Analyst “Confirmed threat” or “Benign” feedback adjusts later scores for the same sensor/event-type/process fingerprint; it does not silently retrain the historical UNSW model. Baseline history is stored in the app's local SQLite database and capped at 20,000 events.
- AI attack-chain detection groups process, file, and network events from the same sensor within a 15-minute window and creates a deduplicated review alert for stronger multi-stage patterns. It is a metadata heuristic, not proof of compromise or an automatic response.
- AI rule suggestions use local pattern mining over repeated events with risk 60 or higher. Suggestions save as disabled drafts in Custom Detection Rule Builder; an Admin must review and enable a rule. No external AI service is required for suggestions.
- Model drift monitoring compares recent event types and risk levels with earlier sensor telemetry after enough unique history is available. A change can reflect a normal workload shift; the app raises a review alert and does not automatically change thresholds or model parameters.
- The Alert Center refreshes every 5 seconds and automatically promotes new sensor and live-model anomalies to deduplicated review alerts. It supports severity/status filters, acknowledgement and resolution, in-app notifications, and optional email alerts. Each alert has a saved investigation checklist and timeline for creation, status changes, checklist updates, and analyst notes; related alerts can be grouped into an incident.
- Sensor health/status displays local or cloud sensor liveness, heartbeat, last event, cloud sync, and pending upload count. A hosted dashboard only knows the latest authenticated sensor heartbeat; it cannot inspect the laptop process directly.
- The Log Analyzer scans authorized local text/CSV logs up to 5 MB for common failed sign-ins, suspicious script/credential terms, and malware-related log patterns. Log contents remain local and are not saved as an uploaded file.
- IOC Watchlist stores analyst-entered IP addresses, domains, and file hashes in the app database. New endpoint metadata and authorized local logs are checked against enabled exact-match indicators; matches create deduplicated High review alerts. The sensor currently reports remote IPs and file hashes, not DNS names, so a domain can match when it appears in available event text or an imported local log. A match is not proof of compromise.
- Detection Tuning saves a minimum endpoint risk score and AI anomaly score. The endpoint threshold filters lower-risk Review events; High/Critical sensor events remain eligible. The AI score cutoff filters weaker anomaly results and updates the metadata fallback detector.
- Incident Management records an incident timeline, links selected alerts, and exports the incident summary, linked alerts, and timeline as PDF or CSV. Older grouped incidents can recover alert links from their saved notes.
- Threat Hunting adds a 10-second refreshed event search with time range, event type, severity, risk, and text filters. It groups repeated or varied activity by process and lets an analyst promote a selected correlation to a deduplicated alert. This is a triage heuristic, not proof of malicious behavior.
- Alert assignment and SLA let an analyst assign an alert and set a review deadline; overdue open alerts are labeled and assignment changes are recorded in the alert timeline and audit log.
- Network Connection Map groups observed public destination IPs by process and port, shows counts and maximum sensor risk, and exports the relationship table as CSV. It is metadata-only and does not use an external geolocation service.
- IOC Watchlist entries include their source and optional expiry date. Expired entries stop matching new events automatically, while remaining visible in the watchlist for review.
- Daily Security Summary creates a UTC-date snapshot of event totals, higher-risk activity, destination IPs, new watchlist matches, alerts, and incidents, with CSV and PDF downloads.
- Configuration Backup exports/restores detection thresholds and IOC Watchlist entries as JSON. It deliberately excludes passwords, API keys, SMTP credentials, and other secrets; restore can merge entries or replace the current watchlist.
- Incident Management can download an evidence bundle ZIP containing incident metadata, linked alerts, incident and alert timelines, IOC matches, and log-finding alert records. Original uploaded log files are not retained or included.
- Alert grouping combines matching open alerts seen within 15 minutes and records occurrence count, last-seen time, and grouped activity in the investigation timeline. Exact event IDs remain deduplicated.
- Multi-device Fleet View summarizes sensors, recently observed processes, installed-application events, network activity, and risk scores. It represents observed telemetry, not a complete device or software scan.
- Multi-device Fleet View combines endpoint events with authenticated sensor heartbeats, shows online/offline and event counts, and lets analysts save a display name and comma-separated tags for each observed sensor. Sensor IDs are the stable device key; the view cannot inspect a device that has never checked in.
- Custom Detection Rule Builder saves admin-managed metadata rules using exact event type, process substring, remote IP, file extension, and minimum risk conditions. All populated conditions must match. Matching records create deduplicated alerts during the Alert System refresh; active alert-suppression rules still apply. Rules do not execute commands or change endpoint behavior.
- Event Correlation Graph visualizes up to 20 recent events related to a selected sensor, process, public or private IP, or file hash. Edges show shared metadata within the selected time window and are investigation leads, not proof of compromise.
- Alert Suppression supports exact process, destination IP, file-extension, and event-type rules, each with a reason and optional expiry. It prevents matching events from creating endpoint, IOC, and AI review alerts; it does not stop collection or block activity.
- Sensor integrity monitoring reports if the sensor program changes while it is running. Existing heartbeat monitoring reports a sensor that stops checking in. An integrity change can also be a legitimate update and needs review.
- Alert investigation includes saved response playbooks for network, file, process, and general events. Playbooks guide the analyst and never automatically stop processes, block traffic, or quarantine files.
- Scheduled Reports can send daily or weekly UTC summaries through the configured email provider. The in-app scheduler needs an active, refreshing dashboard session; delivery is not guaranteed while the app is stopped or asleep.
- Access & Roles supports Admin and optional Analyst accounts configured in private settings. Admin-only settings include detection tuning, configuration backup, IOC administration, suppression rules, scheduled reports, and access configuration. The legacy APP_USERNAME / APP_PASSWORD pair remains an Admin account. App roles do not replace host or API network controls.
- Threat Feed Health records the Feodo Tracker feed's last successful fetch, indicator count, errors, and age; it raises a review alert when the last successful data is more than 24 hours old. VirusTotal and AbuseIPDB configuration status is also shown.
- Sensor Health Alerts create one High alert after a previously reporting local/cloud sensor becomes offline/stale, then resolve it when the heartbeat/process recovers. A sensor with no prior heartbeat does not trigger an outage alert.
- Security Operations Toolkit adds configurable duplicate-alert grouping, saved threat-hunting searches, local/cloud sensor diagnostics, analyst-owned investigation cases with notes and linked alerts, clearly labeled synthetic alert tests (never uploaded or emailed), and administrator-controlled retention previews/purges. Retention preserves open alerts, active incidents, saved searches, and case notes; authenticated cloud API sensor events have a separate preview and purge endpoint.
- Sensor health uses a heartbeat every 10 seconds. The dashboard shows whether the sensor is online (heartbeat within 45 seconds), last heartbeat, last observed event, cloud sync state, and any locally queued events. The cloud API cannot inspect the laptop process directly; it reports the sensor's last authenticated check-in.
- The MITRE ATT&CK page maps matching live event text, alerts, and offline report categories to candidate techniques, with rationale and links. Mappings are tentative and require analyst review.
- IOC Analysis checks IPs against Feodo Tracker and can query VirusTotal for IPs, domains, or hashes when `VT_API_KEY` is configured. It can also check IP reputation with AbuseIPDB when `ABUSEIPDB_API_KEY` is configured. Analysts choose which enabled sources receive the entered indicator; file contents are never uploaded. VirusTotal may add queried indicators to its shared dataset, so do not submit confidential, sensitive, or personally identifying indicators.
- The local Log Analyzer accepts authorized text/CSV logs up to 5 MB, detects common failed-login and suspicious-script patterns, and creates deduplicated alerts. Log uploads are disabled outside the local desktop app.
- Analytics and reports include live event counts, severity and daily trends, filters, and PDF/CSV export. Audit records track sign-ins, IOC checks, report exports, and alert/incident updates.

## Local Windows run

Requirements: Windows, Python, VS Code, and Npcap for packet capture. The endpoint sensor itself reads Windows registry metadata and therefore runs on the Windows laptop; the deployed dashboard cannot inspect the laptop directly.

1. Install dependencies:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. If `.streamlit/secrets.toml` does not exist, copy `.streamlit/secrets.toml.example` to create it; otherwise add settings to the existing file without replacing its contents. Set your own long, unique `APP_PASSWORD`. Keep `secrets.toml` private; it is ignored by Git. Add `OPENAI_API_KEY` to enable the optional generative reviews and optionally choose `OPENAI_MODEL`; this is an OpenAI API key, separate from ChatGPT sign-in. Add `VT_API_KEY` for VirusTotal IP/domain/hash checks and `ABUSEIPDB_API_KEY` for AbuseIPDB IP checks as needed; never put real keys in the example file or commit them. In the desktop app, open **Alert System → Configure desktop email alerts** to save local SMTP settings; they are stored in an ignored local file and are not uploaded. Use port 587 with STARTTLS or port 465 with SSL. On Streamlit Cloud, direct Gmail SMTP may be blocked by hosted-network egress rules. In that case set `EMAIL_PROVIDER = "resend"`, add `RESEND_API_KEY`, `RESEND_FROM` (a sender authorized by Resend), and `ALERT_EMAIL_TO` in the app's private Secrets settings. For SMTP instead, use `EMAIL_PROVIDER = "smtp"` and the SMTP settings. Keep `EMAIL_ALERTS_ENABLED = "false"`; email notifications are off by default and require the in-app toggle each session. Never commit real email credentials. The Alert System includes a **Send test email** button to verify the configuration.

3. In one VS Code terminal, start the local endpoint sensor:

```powershell
python endpoint_monitor.py
```

The sensor checks common user folders, process starts, installed-app registration, and public outbound connections. Stop it with `Ctrl+C`.

4. In another VS Code terminal, start the dashboard:

```powershell
streamlit run app.py --server.address 127.0.0.1
```

5. Optional: regenerate the offline UNSW-NB15 benchmark report:

```powershell
python main.py
```

## Cloud deployment

The cloud dashboard is hosted on Streamlit Community Cloud. The Windows sensor must remain running on the laptop. It sends metadata to the authenticated API; the cloud server cannot sniff the laptop's Wi-Fi adapter by itself.

1. Push this project to a GitHub repository. Do not commit `.venv`, `.env`, `.streamlit/secrets.toml`, `security_center.db`, or `.sensor_id`.
2. Create the backend and PostgreSQL database from `render.yaml` in Render. Set/retain the generated `API_TOKEN` as a private secret and copy the backend HTTPS URL.
3. In Streamlit Community Cloud, deploy `app.py` from the GitHub repository. Add `APP_USERNAME`, `APP_PASSWORD`, `API_BASE_URL`, and `API_TOKEN` in the app's Secrets settings. Add `OPENAI_API_KEY` (and optionally `OPENAI_MODEL`) there to enable OpenAI reviews. Live reviews default to on when the key is present and can be turned off in AI Engine; manual reviews still require per-review consent. Never commit the key or send it through chat.
4. In the Windows PowerShell terminal where the sensor will run, set the same API URL and token for that session, then start `python endpoint_monitor.py`:

```powershell
$env:CTI_API_URL = "https://YOUR-API.onrender.com"
$env:CTI_API_TOKEN = "YOUR-PRIVATE-TOKEN"
python endpoint_monitor.py
```

The sensor queues events locally if the API is sleeping or unreachable, and retries later. It reports a heartbeat and pending-event count to the API every 10 seconds. After changing this feature, deploy the updated API service on Render and the updated Streamlit app, then restart the Windows sensor. Free Render PostgreSQL databases expire after 30 days; use a non-expiring database plan for long-term storage.

## Academic data and references

- Historical model data: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset). Cite the dataset in the submission.
- Threat intelligence: [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/). Treat matches as indicators to investigate, not confirmed incidents.
- Technique references: [MITRE ATT&CK](https://attack.mitre.org/).

## Scope and limits

The system monitors the folders, Windows processes, application registrations, and network connections listed above. Coverage depends on Windows permissions and the events visible to the sensor; it does not inspect encrypted content, cover every Windows event channel, or automatically remediate threats. Live anomaly-model training must use flow features aligned to the sensor before its results can be used to classify live activity.
