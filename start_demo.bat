@echo off
cd /d "%~dp0"
echo RAZTA live demo
if "%OPENROUTER_API_KEY%"=="" set /p OPENROUTER_API_KEY=Paste your OpenRouter key and press Enter (or just press Enter for Replay-only): 
python demo_server.py
pause
