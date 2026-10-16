@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Project Python environment was not found.
  echo Open the project folder and check that .venv exists.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -c "import webview" >nul 2>&1
if errorlevel 1 (
  echo Installing desktop window support. Internet is needed for this first setup.
  ".venv\Scripts\python.exe" -m pip install -r requirements-desktop.txt
  if errorlevel 1 (
    echo Setup failed. Check your internet connection and try again.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" desktop_app.py
if errorlevel 1 echo The desktop dashboard could not start. See desktop_dashboard.log in this folder.
pause
