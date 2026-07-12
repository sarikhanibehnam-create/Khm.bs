@echo off
chcp 65001 >nul
echo ============================================
echo    Mehr Automotive Procurement System
echo ============================================
echo.
echo Starting server...
cd /d "%~dp0"

start "" /b cmd /c "ping 127.0.0.1 -n 3 >nul & start http://localhost:8765"

echo.
echo Server running at: http://localhost:8765
echo To stop the server, close this window.
echo.

where python >nul 2>nul
if errorlevel 1 goto trypy
python server.py
goto end

:trypy
py server.py

:end
pause
