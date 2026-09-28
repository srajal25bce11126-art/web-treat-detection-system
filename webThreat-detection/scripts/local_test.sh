#!/usr/bin/env bash
# scripts/local_test.sh
# Starts FastAPI with uvicorn, waits 2 seconds, sends 3 test requests to /predict, and prints responses.

set -e

PORT=8000
HOST="127.0.0.1"
BASE_URL="http://${HOST}:${PORT}"

echo "============================================================"
echo "  PHISHING DETECTION API - LOCAL BASH SANITY TEST"
echo "============================================================"

# Ensure server cleanup upon script exit (Ctrl+C, normal completion, or error)
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    echo ""
    echo "Stopping test server (PID: $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    echo "Server stopped cleanly."
  fi
}
trap cleanup EXIT INT TERM

# 1. Start server in background
echo "[1/3] Starting uvicorn server on ${BASE_URL}..."
uvicorn app.main:app --host "$HOST" --port "$PORT" &
SERVER_PID=$!

# 2. Wait 2 seconds for the server to bind and load
echo "[2/3] Waiting 2 seconds for server initialization..."
sleep 2

# Verify server responded to health check
if ! curl -s "${BASE_URL}/" > /dev/null; then
  echo "Error: Server did not respond at ${BASE_URL}/"
  exit 1
fi
echo "Server is running (PID: $SERVER_PID)."

echo ""
echo "[3/3] Sending test POST requests to /predict..."
echo ""

# Helper to format JSON output
format_json() {
  if command -v jq >/dev/null 2>&1; then
    jq .
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool
  else
    cat
  fi
}

# Test 1: Clearly safe URL
echo "------------------------------------------------------------"
echo "Test #1: Clearly Safe URL (Google)"
echo "URL: https://www.google.com"
curl -s -X POST "${BASE_URL}/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}' | format_json
echo "------------------------------------------------------------"
echo ""

# Test 2: Phishing-style URL with IP-like domain
echo "------------------------------------------------------------"
echo "Test #2: Phishing-Style URL (IP-like domain)"
echo "URL: http://192.168.1.1-login-verify.com"
curl -s -X POST "${BASE_URL}/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1-login-verify.com"}' | format_json
echo "------------------------------------------------------------"
echo ""

# Test 3: Phishing-style URL with credential deception & suspicious TLD
echo "------------------------------------------------------------"
echo "Test #3: Phishing-Style URL (Credential deception & suspicious TLD)"
echo "URL: http://paypal.com.account-security-update.xyz/login.php?user=client@verify"
curl -s -X POST "${BASE_URL}/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal.com.account-security-update.xyz/login.php?user=client@verify"}' | format_json
echo "------------------------------------------------------------"
echo ""

echo "Sanity check finished successfully."
