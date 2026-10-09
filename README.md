# AI Cyber Threat Intelligence

Windows endpoint and network monitoring project with a local sensor, authenticated event API, threat-feed lookups, analyst dashboard, alert/incident tracking, and CSV/PDF reports.

## Current monitoring scope

- Local sensor watches `Downloads`, `Desktop`, and `Documents` for file create, move, and modification events; it calculates SHA-256 locally for files up to 100 MB.
- It observes newly started processes, newly registered Windows applications, and public outbound TCP/UDP connection metadata.
- It checks remote IPv4 destinations against the public Feodo Tracker C2 feed.
- The sensor stores full local paths in the laptop's SQLite database. Cloud sync sends only event metadata: folder label, filename, file hash, process name, remote IP/port, event summary, and risk fields. File contents and packet payloads are never uploaded.
- A file extension or feed match is a review signal, not proof that a file or device is infected. The sensor does not delete, quarantine, or block traffic.
- The UNSW-NB15 Random Forest remains a historical flow-dataset benchmark. It is kept separate from live endpoint signals; no mismatched live features are sent into that model.

## Local Windows run

Requirements: Windows, Python, VS Code, and Npcap for packet capture. The endpoint sensor itself reads Windows registry metadata and therefore runs on the Windows laptop; the deployed dashboard cannot inspect the laptop directly.

1. Install dependencies:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and set your own long, unique `APP_PASSWORD`. Keep `secrets.toml` private; it is ignored by Git.

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
3. In Streamlit Community Cloud, deploy `app.py` from the GitHub repository. Add `APP_USERNAME`, `APP_PASSWORD`, `API_BASE_URL`, and `API_TOKEN` in the app's Secrets settings.
4. In the Windows PowerShell terminal where the sensor will run, set the same API URL and token for that session, then start `python endpoint_monitor.py`:

```powershell
$env:CTI_API_URL = "https://YOUR-API.onrender.com"
$env:CTI_API_TOKEN = "YOUR-PRIVATE-TOKEN"
python endpoint_monitor.py
```

The sensor queues events locally if the API is sleeping or unreachable, and retries later. Free Render PostgreSQL databases expire after 30 days; use a non-expiring database plan for long-term storage.

## Academic data and references

- Historical model data: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset). Cite the dataset in the submission.
- Threat intelligence: [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/). Treat matches as indicators to investigate, not confirmed incidents.
- Technique references: [MITRE ATT&CK](https://attack.mitre.org/).

## Scope and limits

The system monitors the folders, Windows processes, application registrations, and network connections listed above. Coverage depends on Windows permissions and the events visible to the sensor; it does not inspect encrypted content, cover every Windows event channel, or automatically remediate threats. Live anomaly-model training must use flow features aligned to the sensor before its results can be used to classify live activity.
