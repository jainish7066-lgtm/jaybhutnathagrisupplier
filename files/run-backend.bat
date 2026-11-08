@echo off
title Jay Bhutnath Agri - Backend
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed.
  echo Download the LTS version from https://nodejs.org , install it, then double-click this file again.
  pause
  exit /b
)
if not exist .env (
  for /f %%i in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set SECRET=%%i
  (
    echo PORT=3000
    echo JWT_SECRET=%SECRET%
    echo ADMIN_USER=jaybhutnathadmin
    echo ADMIN_PASS=adminbhutnath321
  ) > .env
  echo Created .env settings file.
)
if not exist node_modules (
  echo Installing packages, please wait...
  call npm install
)
echo.
echo Starting backend at http://localhost:3000  (keep this window open, press Ctrl+C to stop)
echo.
start "" cmd /c "timeout /t 3 >nul & start http://localhost:3000"
node server.js
pause
