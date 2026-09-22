#!/usr/bin/env bash
# One-shot setup for the modern-web-storage session-crawl tool.
# Creates a local Python venv with Playwright (+ Firefox/WebKit for those capture options),
# then starts serve.py on http://127.0.0.1:8099.
#
# It does NOT install: Docker (must be running) + the az-dast image, the login browser
# (Chrome capture uses the system Google Chrome), or a scan target. You provide those.
#   Load the image once:   docker load < az-dast-arm64.tgz
#
# Usage:   ./setup.sh
set -euo pipefail
cd "$(dirname "$0")"

VENV=.venv-pw
PORT=8099

command -v python3 >/dev/null 2>&1 || { echo "[setup] python3 not found - install Python 3 first"; exit 1; }

# 1. Python venv + Playwright
if [ ! -d "$VENV" ]; then
  echo "[setup] creating venv: $VENV"
  python3 -m venv "$VENV"
fi
echo "[setup] installing Playwright into $VENV"
"$VENV/bin/pip" install --upgrade pip >/dev/null
"$VENV/bin/pip" install --quiet playwright
# Chrome capture uses the system Google Chrome (channel=chrome); Firefox/WebKit need Playwright's
# own builds. Installing both makes every browser option in the page work.
echo "[setup] installing Playwright browsers (firefox webkit) - one-time download"
"$VENV/bin/playwright" install firefox webkit

# 2. Warn (do not fail) if the Docker side is not ready - crawl/scan need it, capture does not
if ! command -v docker >/dev/null 2>&1; then
  echo "[setup] WARNING: docker not found. Crawl/scan need Docker running and the az-dast image."
elif ! docker image inspect az-dast:testing >/dev/null 2>&1; then
  echo "[setup] WARNING: image az-dast:testing not loaded. Run: docker load < az-dast-arm64.tgz"
fi

# 3. Start the server (foreground; Ctrl+C to stop)
echo "[setup] starting serve.py on http://127.0.0.1:$PORT  (Ctrl+C to stop)"
exec "$VENV/bin/python" serve.py
