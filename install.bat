@echo off
echo Installing CyberMonitor Agent...
python -m pip install requests psutil wmi
python monitor.py
pause
