@echo off
title ThreatSense AI — Faculty Demo Launcher
color 0A

echo.
echo  ================================================================
echo  ^|                                                              ^|
echo  ^|              ThreatSense AI  v0.1.0                         ^|
echo  ^|        Multi-Layer Cybersecurity Detection Platform          ^|
echo  ^|                                                              ^|
echo  ^|         22 Detectors  ^|  5 Domains  ^|  398 Tests            ^|
echo  ^|                                                              ^|
echo  ================================================================
echo.

:: ── Check Python ────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo  [ERROR] Python not found. Please install Python 3.11+
    pause
    exit /b 1
)

:: ── Check Node ───────────────────────────────────────────────────────────────
node --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo  [ERROR] Node.js not found. Please install Node.js 18+
    pause
    exit /b 1
)

echo  [1/4] Checking dependencies...

:: ── Backend dependencies ─────────────────────────────────────────────────────
cd /d "%~dp0backend"
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo  [1/4] Installing backend dependencies ^(first run only^)...
    pip install -e . -q
)

:: ── Frontend dependencies ─────────────────────────────────────────────────────
cd /d "%~dp0frontend"
if not exist "node_modules" (
    echo  [1/4] Installing frontend dependencies ^(first run only^)...
    npm install --silent
)

echo  [OK] Dependencies ready.
echo.

:: ── Start Backend ─────────────────────────────────────────────────────────────
echo  [2/4] Starting FastAPI backend on http://localhost:8000 ...
cd /d "%~dp0backend"
start "ThreatSense AI — Backend" cmd /k "color 0B && echo  ThreatSense AI Backend && echo  API Docs: http://localhost:8000/docs && echo. && python -m uvicorn app.main:app --reload --port 8000"

:: ── Wait for backend to boot ──────────────────────────────────────────────────
echo  [2/4] Waiting for backend to start...
timeout /t 5 /nobreak >nul

:: ── Verify backend is alive ───────────────────────────────────────────────────
:wait_backend
python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" >nul 2>&1
if errorlevel 1 (
    timeout /t 2 /nobreak >nul
    goto wait_backend
)
echo  [OK] Backend is live.
echo.

:: ── Start Frontend ────────────────────────────────────────────────────────────
echo  [3/4] Starting React dashboard on http://localhost:5173 ...
cd /d "%~dp0frontend"
start "ThreatSense AI — Frontend" cmd /k "color 0D && echo  ThreatSense AI Frontend Dashboard && echo  Open: http://localhost:5173 && echo. && npm run dev -- --host"

:: ── Wait for frontend to boot ─────────────────────────────────────────────────
timeout /t 5 /nobreak >nul

:: ── Open browser ─────────────────────────────────────────────────────────────
echo  [4/4] Opening browser...
start "" "http://localhost:5173"

echo.
echo  ================================================================
echo  ^|                 ALL SYSTEMS RUNNING                         ^|
echo  ================================================================
echo  ^|                                                              ^|
echo  ^|   Dashboard  :  http://localhost:5173                       ^|
echo  ^|   API        :  http://localhost:8000                       ^|
echo  ^|   API Docs   :  http://localhost:8000/docs                  ^|
echo  ^|                                                              ^|
echo  ^|   To run Evaluation:                                         ^|
echo  ^|     cd backend                                               ^|
echo  ^|     python ../eval/run_eval.py                               ^|
echo  ^|            --data ../eval/data/sample_urls.csv               ^|
echo  ^|                                                              ^|
echo  ^|   To run Ablation (Phase B):                                 ^|
echo  ^|     python ../eval/run_ablation.py                           ^|
echo  ^|            --data ../eval/data/sample_urls.csv               ^|
echo  ^|                                                              ^|
echo  ================================================================
echo.
echo  Press any key to exit this launcher (servers keep running).
pause >nul
