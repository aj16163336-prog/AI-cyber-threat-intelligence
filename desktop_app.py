"""Run the local Streamlit dashboard inside a standalone Windows window."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

BASE_DIR = Path(__file__).resolve().parent


def choose_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def endpoint_sensor_running() -> bool:
    try:
        import psutil
    except ImportError:
        return False

    sensor_script = str((BASE_DIR / "endpoint_monitor.py").resolve()).casefold()
    base_dir = str(BASE_DIR.resolve()).casefold()
    for process in psutil.process_iter(["cmdline", "cwd"]):
        try:
            if process.pid == os.getpid():
                continue
            command = process.info.get("cmdline") or []
            working_directory = process.info.get("cwd")
        except (psutil.Error, OSError):
            continue

        if any(str(Path(argument).resolve()).casefold() == sensor_script for argument in command):
            return True
        if working_directory and str(Path(working_directory).resolve()).casefold() == base_dir:
            if any(Path(argument).name.casefold() == "endpoint_monitor.py" for argument in command):
                return True
    return False


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    try:
        import webview
    except ImportError:
        print("Desktop window support is missing. Run Start_Desktop_App.bat again while connected to the internet.")
        return 1

    port = choose_port()
    address = f"http://127.0.0.1:{port}"
    health_url = f"{address}/_stcore/health"
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(BASE_DIR / "app.py"),
        "--server.address=127.0.0.1",
        f"--server.port={port}",
        "--server.headless=true",
        "--browser.gatherUsageStats=false",
    ]
    log_path = BASE_DIR / "desktop_dashboard.log"
    child_environment = os.environ.copy()
    child_environment["CTI_DESKTOP_MODE"] = "1"
    sensor_log_path = BASE_DIR / "endpoint_sensor.log"

    sensor_process = None
    server = None
    with log_path.open("a", encoding="utf-8") as log_file, sensor_log_path.open(
        "a", encoding="utf-8"
    ) as sensor_log:
        try:
            if not endpoint_sensor_running():
                sensor_process = subprocess.Popen(
                    [sys.executable, "-u", str(BASE_DIR / "endpoint_monitor.py")],
                    cwd=BASE_DIR,
                    env=child_environment,
                    stdout=sensor_log,
                    stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                sensor_log.write("Desktop app started the endpoint sensor.\n")
                sensor_log.flush()
            else:
                sensor_log.write("An endpoint sensor is already running for this project.\n")
                sensor_log.flush()

            server = subprocess.Popen(
                command,
                cwd=BASE_DIR,
                env=child_environment,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            deadline = time.monotonic() + 60
            ready = False
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    break
                try:
                    with urlopen(health_url, timeout=1) as response:
                        if response.status == 200:
                            ready = True
                            break
                except (OSError, URLError):
                    time.sleep(0.4)

            if not ready:
                print(f"The local dashboard did not start. Details are in: {log_path}")
                return 1

            webview.create_window(
                "AI Cyber Threat Intelligence",
                address,
                width=1440,
                height=900,
                min_size=(960, 640),
            )
            webview.start()
            return 0
        finally:
            stop_process(server)
            stop_process(sensor_process)


if __name__ == "__main__":
    raise SystemExit(main())
