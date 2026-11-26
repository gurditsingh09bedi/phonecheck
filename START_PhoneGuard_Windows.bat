@echo off
title PhoneGuard - Android privacy checker
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel% neq 0 (
  echo Python nahi mila. https://www.python.org/downloads/ se install karo
  echo ^(install ke time "Add Python to PATH" tick karna^).
  pause
  exit /b
)
python phoneguard.py
pause
