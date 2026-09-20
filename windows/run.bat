@echo off
rem NetMonGuru for Windows - first run creates a virtual environment and
rem installs the three dependencies; later runs start immediately.
rem Right-click -> "Run as administrator" (or start from an elevated Windows
rem Terminal) for per-process bandwidth and the connection kill switch.
setlocal
cd /d "%~dp0"

where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
%PY% --version >nul 2>nul || (
  echo Python 3.9+ was not found. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PY% -m venv .venv || (pause & exit /b 1)
  ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || (pause & exit /b 1)
)

".venv\Scripts\python.exe" -m netmonguru %*
if errorlevel 1 pause
endlocal
