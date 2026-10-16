@echo off
setlocal
cd /d "%~dp0"
set "CTI_API_URL=https://ai-cti-api.onrender.com"
title AI Cyber Threat Intelligence - Endpoint Sensor
if not exist ".venv\Scripts\python.exe" (
  echo Python virtual environment was not found in this project folder.
  echo Please open the project folder and check that .venv exists.
  pause
  exit /b 1
)
if not defined CTI_API_TOKEN (
  echo Cloud sync token is not set in Windows yet.
  echo The sensor will still monitor this laptop and save events locally,
  echo but events will not appear in the cloud dashboard until the token is configured.
  echo.
)
echo Starting the endpoint sensor. Keep this window open while monitoring.
echo To stop it, press Ctrl+C.
echo.
".venv\Scripts\python.exe" endpoint_monitor.py
echo.
echo Sensor stopped.
pause
