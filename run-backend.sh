#!/usr/bin/env bash
cd "$(dirname "$0")"
command -v node >/dev/null || { echo "Install Node.js (LTS) from https://nodejs.org, then run this again."; exit 1; }
if [ ! -f .env ]; then
  printf "PORT=3000\nJWT_SECRET=%s\nADMIN_USER=jaybhutnathadmin\nADMIN_PASS=adminbhutnath321\n" "$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" > .env
  echo "Created .env settings file."
fi
[ -d node_modules ] || { echo "Installing packages..."; npm install; }
echo "Starting backend at http://localhost:3000 (Ctrl+C to stop)"
node server.js
