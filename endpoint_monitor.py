"""Local Windows endpoint sensor for the AI Cyber Threat Intelligence project.

Watches selected user folders and observes newly started processes and public
network connections. It records metadata only; it never uploads file contents.
Run locally with: python endpoint_monitor.py
"""

from __future__ import annotations

from datetime import datetime, timezone
import csv
import hashlib
import ipaddress
import os
from pathlib import Path
import sqlite3
import socket
import time
import uuid
import winreg

import requests

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CTI_DB_PATH", str(BASE_DIR / "security_center.db")))
WATCH_PATHS = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path(os.environ.get("TEMP", str(Path.home() / "AppData" / "Local" / "Temp"))),
]
if os.environ.get("OneDrive"):
    WATCH_PATHS.extend([
        Path(os.environ["OneDrive"]) / "Desktop",
        Path(os.environ["OneDrive"]) / "Documents",
    ])
WATCH_PATHS = list(dict.fromkeys(WATCH_PATHS))
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".msi", ".msp", ".ps1", ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".hta", ".lnk", ".reg", ".jar",
    ".docm", ".xlsm", ".iso", ".img",
}
MAX_HASH_BYTES = 100 * 1024 * 1024
POLL_SECONDS = 5
APP_SCAN_SECONDS = 30
FEODO_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
_feed_expires = 0.0
_feodo_ips = set()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    with sqlite3.connect(DB_PATH, timeout=10) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS endpoint_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_uid TEXT UNIQUE,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                file_path TEXT,
                file_sha256 TEXT,
                process_name TEXT,
                remote_ip TEXT,
                remote_port INTEGER,
                risk_score INTEGER NOT NULL DEFAULT 0,
                details TEXT,
                synced INTEGER NOT NULL DEFAULT 0
            )"""
        )
        existing = {
            row[1] for row in db.execute("PRAGMA table_info(endpoint_events)").fetchall()
        }
        if "event_uid" not in existing:
            db.execute("ALTER TABLE endpoint_events ADD COLUMN event_uid TEXT")
        if "synced" not in existing:
            db.execute(
                "ALTER TABLE endpoint_events ADD COLUMN synced INTEGER NOT NULL DEFAULT 0"
            )


def save_event(event_type, severity, summary, *, file_path=None,
               file_sha256=None, process_name=None, remote_ip=None,
               remote_port=None, risk_score=0, details=None):
    init_db()
    with sqlite3.connect(DB_PATH, timeout=10) as db:
        db.execute(
            """INSERT INTO endpoint_events
               (event_uid, created_at, event_type, severity, summary, file_path,
                file_sha256, process_name, remote_ip, remote_port,
                risk_score, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (uuid.uuid4().hex, utc_now(), event_type, severity, summary, file_path, file_sha256,
             process_name, remote_ip, remote_port, int(risk_score), details),
        )
        db.execute(
            "DELETE FROM endpoint_events WHERE id NOT IN "
            "(SELECT id FROM endpoint_events ORDER BY id DESC LIMIT 10000)"
        )


def _sensor_id():
    path = BASE_DIR / ".sensor_id"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = uuid.uuid4().hex
    path.write_text(value, encoding="utf-8")
    return value


def _folder_label(file_path):
    if not file_path:
        return None
    path = Path(file_path)
    for root in WATCH_PATHS:
        try:
            path.relative_to(root)
            return root.name
        except ValueError:
            continue
    return "Other"


def sync_pending_events():
    """Send minimal event metadata to the configured HTTPS API, if enabled."""
    api_url = os.environ.get("CTI_API_URL", "").strip().rstrip("/")
    token = os.environ.get("CTI_API_TOKEN", "").strip()
    if not api_url or not token:
        return 0

    init_db()
    with sqlite3.connect(DB_PATH, timeout=10) as db:
        rows = db.execute(
            """SELECT id, event_uid, created_at, event_type, severity, summary,
                      file_path, file_sha256, process_name, remote_ip,
                      remote_port, risk_score, details
               FROM endpoint_events WHERE synced = 0 ORDER BY id LIMIT 100"""
        ).fetchall()
    if not rows:
        return 0

    sensor_id = _sensor_id()
    events = []
    local_ids = []
    for row in rows:
        (
            local_id, event_uid, created_at, event_type, severity, summary,
            file_path, file_sha256, process_name, remote_ip, remote_port,
            risk_score, details,
        ) = row
        file_name = Path(file_path).name if file_path and event_type.startswith("file_") else None
        events.append({
            "event_id": f"{sensor_id}:{event_uid or local_id}",
            "sensor_id": sensor_id,
            "occurred_at": created_at,
            "event_type": event_type,
            "severity": severity,
            "summary": summary,
            "folder": _folder_label(file_path) if file_name else None,
            "file_name": file_name,
            "file_sha256": file_sha256,
            "process_name": process_name,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "risk_score": risk_score,
            "details": details,
        })
        local_ids.append(local_id)

    try:
        response = requests.post(
            f"{api_url}/v1/events",
            json={"events": events},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as error:
        print(f"Cloud sync pending; events remain saved locally: {error}")
        return 0

    placeholders = ",".join("?" for _ in local_ids)
    with sqlite3.connect(DB_PATH, timeout=10) as db:
        db.execute(
            f"UPDATE endpoint_events SET synced = 1 WHERE id IN ({placeholders})",
            local_ids,
        )
    return len(local_ids)


def load_feodo_ips():
    """Download and cache the public Feodo Tracker IPv4 indicator list."""
    global _feed_expires, _feodo_ips
    now = time.monotonic()
    if now < _feed_expires:
        return _feodo_ips
    try:
        response = requests.get(FEODO_FEED_URL, timeout=8)
        response.raise_for_status()
        candidates = set()
        for row in csv.reader(response.text.splitlines()):
            if not row or row[0].lstrip().startswith("#") or len(row) < 2:
                continue
            try:
                address = ipaddress.ip_address(row[1].strip())
                if address.version == 4:
                    candidates.add(str(address))
            except ValueError:
                continue
        _feodo_ips = candidates
        _feed_expires = now + 900
    except requests.RequestException:
        _feed_expires = now + 60
    return _feodo_ips


def sha256_file(path: Path):
    try:
        if not path.is_file() or path.stat().st_size > MAX_HASH_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def wait_until_stable(path: Path, timeout=12):
    """Wait for a download/write to finish before hashing it."""
    previous_size = None
    stable_checks = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            current_size = path.stat().st_size
        except OSError:
            time.sleep(1)
            continue
        if current_size == previous_size:
            stable_checks += 1
            if stable_checks >= 2:
                return True
        else:
            stable_checks = 0
            previous_size = current_size
        time.sleep(1)
    return False


class FileEvents(FileSystemEventHandler):
    def _record(self, value, kind):
        path = Path(value)
        if not path.is_file():
            return
        if not wait_until_stable(path):
            return
        extension = path.suffix.lower()
        flagged = extension in SUSPICIOUS_EXTENSIONS
        score = 55 if flagged else 10
        severity = "Review" if flagged else "Info"
        digest = sha256_file(path)
        save_event(
            "file_" + kind,
            severity,
            f"{kind.title()} file detected: {path.name}" +
            (f" ({extension})" if extension else ""),
            file_path=str(path),
            file_sha256=digest,
            risk_score=score,
            details=(
                "Extension is on the review list; this is not a malware verdict. "
                "File content was not uploaded."
                if flagged else "File metadata and SHA-256 recorded locally; no malware verdict."
            ),
        )

    def on_created(self, event):
        if not event.is_directory:
            self._record(event.src_path, "created")

    def on_moved(self, event):
        if not event.is_directory:
            self._record(event.dest_path, "moved_into")

    def on_modified(self, event):
        if not event.is_directory:
            self._record(event.src_path, "modified")


def process_key(process):
    try:
        return int(process.info["pid"]), float(process.info["create_time"])
    except (psutil.Error, KeyError, TypeError, ValueError):
        return None


def process_snapshot():
    found = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        key = process_key(proc)
        if key is None:
            continue
        found[key] = {
            "pid": key[0],
            "name": proc.info.get("name") or "unknown",
            "exe": proc.info.get("exe") or "",
        }
    return found


def is_user_writable_path(value):
    lowered = str(value).lower().replace("/", "\\")
    roots = [
        str(Path.home() / "Downloads").lower().replace("/", "\\"),
        str(Path.home() / "AppData" / "Local" / "Temp").lower().replace("/", "\\"),
        str(Path.home() / "Desktop").lower().replace("/", "\\"),
    ]
    return any(lowered.startswith(root) for root in roots)


def observe_new_processes(previous):
    current = process_snapshot()
    for key, item in current.items():
        if key in previous:
            continue
        risky_location = is_user_writable_path(item["exe"])
        save_event(
            "process_started",
            "Review" if risky_location else "Info",
            f"New process started: {item['name']}",
            process_name=item["name"],
            file_path=item["exe"] or None,
            risk_score=60 if risky_location else 10,
            details=(
                f"PID {item['pid']}; running from a user-writable folder. "
                "Location alone does not prove malicious activity."
                if risky_location else f"PID {item['pid']}; process start observed."
            ),
        )
    return current


def installed_app_snapshot():
    """Read installed-app registration keys; this does not alter the registry."""
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM-64", 0),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM-32", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU", 0),
    ]
    result = {}
    for root, subkey, hive, view in roots:
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | view) as key:
                count = winreg.QueryInfoKey(key)[0]
                for index in range(count):
                    try:
                        child_name = winreg.EnumKey(key, index)
                        with winreg.OpenKey(key, child_name, 0, winreg.KEY_READ) as child:
                            display_name = winreg.QueryValueEx(child, "DisplayName")[0]
                            version = _registry_value(child, "DisplayVersion")
                            publisher = _registry_value(child, "Publisher")
                            install_location = _registry_value(child, "InstallLocation")
                            if display_name:
                                identity = f"{hive}:{child_name}:{version or ''}"
                                result[identity] = {
                                    "name": str(display_name).strip(),
                                    "version": str(version or "").strip(),
                                    "publisher": str(publisher or "").strip(),
                                    "location": str(install_location or "").strip(),
                                }
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue
    return result


def _registry_value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return ""


def observe_new_installed_apps(previous):
    current = installed_app_snapshot()
    for identity, item in current.items():
        if identity in previous:
            continue
        user_location = is_user_writable_path(item["location"])
        severity = "Review" if user_location or not item["publisher"] else "Info"
        save_event(
            "application_installed",
            severity,
            f"Installed application detected: {item['name']}",
            process_name=item["name"],
            risk_score=45 if severity == "Review" else 10,
            details=(
                f"Version: {item['version'] or 'unknown'}; "
                f"Publisher: {item['publisher'] or 'not listed'}. "
                "Registration was detected; this is not a malware verdict."
            ),
        )
    return current


def observe_connections(seen, bad_ips):
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as error:
        return f"Connection visibility limited: {error}"

    for conn in connections:
        if not conn.raddr or conn.status not in ("ESTABLISHED", "SYN_SENT"):
            continue
        try:
            remote_ip = str(conn.raddr.ip)
            remote_port = int(conn.raddr.port)
            address = ipaddress.ip_address(remote_ip)
        except (AttributeError, ValueError, TypeError):
            continue
        if not address.is_global:
            continue
        key = (conn.pid, remote_ip, remote_port, conn.type)
        if key in seen:
            continue
        seen.add(key)
        process_name = None
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except psutil.Error:
                pass
        matched = remote_ip in bad_ips
        transport = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        save_event(
            "network_connection",
            "Critical" if matched else "Info",
            (
                f"Threat-feed match: outbound connection to {remote_ip}:{remote_port}"
                if matched else f"Outbound connection observed to {remote_ip}:{remote_port}"
            ),
            process_name=process_name,
            remote_ip=remote_ip,
            remote_port=remote_port,
            risk_score=95 if matched else 5,
            details=(
                f"{transport}; destination matched Feodo Tracker C2 IP feed; investigate and verify."
                if matched else f"{transport} connection metadata only; remote IP requires threat-intelligence review."
            ),
        )
    if len(seen) > 20000:
        seen.clear()
    return None


def run_sensor():
    init_db()
    observer = Observer()
    handler = FileEvents()
    watched = []
    for folder in WATCH_PATHS:
        if folder.is_dir():
            observer.schedule(handler, str(folder), recursive=True)
            watched.append(str(folder))
    if not watched:
        raise RuntimeError("Downloads/Desktop/Documents folders were not found.")

    print("Local endpoint sensor is running. Stop with Ctrl+C.")
    print("Watching folders:")
    for folder in watched:
        print(" -", folder)
    print("File contents stay local; SHA-256 and event metadata are stored locally.")
    observer.start()
    previous = process_snapshot()
    installed_apps = installed_app_snapshot()
    seen_connections = set()
    last_sync = 0.0
    last_app_scan = time.monotonic()
    bad_ips = load_feodo_ips()
    try:
        while True:
            previous = observe_new_processes(previous)
            if time.monotonic() - last_app_scan >= APP_SCAN_SECONDS:
                installed_apps = observe_new_installed_apps(installed_apps)
                last_app_scan = time.monotonic()
            bad_ips = load_feodo_ips()
            warning = observe_connections(seen_connections, bad_ips)
            if warning:
                print(warning)
            if time.monotonic() - last_sync >= 10:
                sync_pending_events()
                last_sync = time.monotonic()
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("Stopping local endpoint sensor...")
    finally:
        observer.stop()
        observer.join(timeout=5)


if __name__ == "__main__":
    run_sensor()
