@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title MCChat

echo ============================================
echo   MCChat - Windows launcher
echo ============================================
echo.

where py >nul 2>nul
if not errorlevel 1 (
    set "PY=py"
) else (
    where python >nul 2>nul
    if not errorlevel 1 (
        set "PY=python"
    ) else (
        echo [ERROR] Python not found.
        echo         Install Python 3.8+ from https://www.python.org/
        echo         and check "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
)

%PY% -c "import cryptography" >nul 2>nul
if errorlevel 1 (
    echo [INFO] cryptography is missing, installing ...
    %PY% -m pip install cryptography
    if errorlevel 1 (
        echo [ERROR] Failed to install cryptography.
        echo         Run manually: %PY% -m pip install cryptography
        pause
        exit /b 1
    )
)

set "NODE_NAME=%COMPUTERNAME%"
set /p "INPUT_NAME=Node name [%COMPUTERNAME%]: "
if defined INPUT_NAME set "NODE_NAME=%INPUT_NAME%"

:ASK_IFACE
set "IFACE="
set /p "IFACE=Direct-link IPv4 address (e.g. 192.168.77.11): "
if defined IFACE goto HAVE_IFACE
echo [ERROR] The interface IP is required. Do not rely on auto-detection.
goto ASK_IFACE

:HAVE_IFACE
echo.
echo Starting: %PY% mcchat.py --name "%NODE_NAME%" --iface %IFACE%
echo.
%PY% mcchat.py --name "%NODE_NAME%" --iface %IFACE%
echo.
echo MCChat exited.
pause
endlocal
