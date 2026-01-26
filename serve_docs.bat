@echo off
REM Start VS Code
start "" /b "C:\Users\esraa\AppData\Local\Programs\Microsoft VS Code\Code.exe" .
REM Start Python scripts
start /b "mkdocs" python -m mkdocs serve
REM Open all URLs in one Edge window with multiple tabs
REM Wait until the mkdocs server is ready
:wait_for_server
curl --silent --head http://127.0.0.1:8000/ | findstr /C:"200 OK" >nul
if errorlevel 1 (
    timeout /t 2 >nul
    goto wait_for_server
)
start "AllApps" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" http://127.0.0.1:8000/
start /b "DAT" python .\run_command_api.py 
@REM start command parser app http://localhost:5000/run/start%20c:%5CUsers%5Cmshus%5COneDrive%5CDesktop%5Csalah%5CCERT%5CSessions%5CSessions%5Cdocs%5C02-SuezCanalUniversity%5Cfiles%5CAI_in_Cybersecuirty.pptx
@REM start "AllApps" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" http://127.0.0.1:8050/ http://127.0.0.1:8051/ http://127.0.0.1:8052/ http://127.0.0.1:8000/
REM Wait for user to close CMD
pause
REM Optionally, kill the Edge browser window (all tabs)
taskkill /F /IM msedge.exe