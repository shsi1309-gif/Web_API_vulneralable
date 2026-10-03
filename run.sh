#!/bin/bash
# ==============================================================================
# Automated Web & API Vulnerability Scanner Startup Script
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
fi

echo "============================================================"
echo " 🛡️ Antigravity Automated Web & API Vulnerability Scanner"
echo "============================================================"
echo " [1] Starting Intentionally Vulnerable Target Lab on :8888..."
./venv/bin/python test_target/vulnerable_app.py &
TARGET_PID=$!

echo " [2] Starting Main FastAPI Backend & Dashboard UI on :8000..."
./venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 &
SCANNER_PID=$!

cleanup() {
    echo ""
    echo "[*] Shutting down services..."
    kill $TARGET_PID 2>/dev/null || true
    kill $SCANNER_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM

echo ""
echo "✅ Application Ready!"
echo "👉 Dashboard UI: http://localhost:8000"
echo "👉 REST API Docs: http://localhost:8000/docs"
echo "👉 Test Target:   http://localhost:8888"
echo ""
echo "Press Ctrl+C to stop all services."

wait
