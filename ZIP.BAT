@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0zip.ps1"
endlocal
