@echo off
rem PLC Guardian control panel. Opens http://127.0.0.1:8765 in your browser.
rem First run builds the web UI and needs Node.js (npm); after that only Python is needed.
cd /d "%~dp0"
python gui.py
