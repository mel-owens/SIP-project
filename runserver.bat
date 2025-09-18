@echo off
cd /d C:\Users\melle\email_security_plugin
call venv\Scripts\activate
python -m uvicorn app.main:app --reload
pause
