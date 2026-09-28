"""
Local sanity-check test script for Phishing Detection API.
Starts uvicorn in the background, sends 3 test requests to /predict,
prints responses, and cleans up the server process.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

# 3 Test URLs
TEST_URLS = [
    {
        "description": "Clearly Safe URL (Google)",
        "url": "https://www.google.com",
    },
    {
        "description": "Phishing-Style URL (IP-like suspicious domain)",
        "url": "http://192.168.1.1-login-verify.com",
    },
    {
        "description": "Phishing-Style URL (Credential deception & suspicious TLD)",
        "url": "http://paypal.com.account-security-update.xyz/login.php?user=client@verify",
    },
]


def wait_for_server(timeout: float = 10.0) -> bool:
    """Wait until the health check endpoint responds."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(f"{BASE_URL}/", headers={"User-Agent": "SanityCheck"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def send_prediction_request(url: str) -> None:
    """Send a POST /predict request and print the response."""
    endpoint = f"{BASE_URL}/predict"
    payload = json.dumps({"url": url}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "SanityCheck"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=25.0) as resp:
            status_code = resp.status
            body = json.loads(resp.read().decode("utf-8"))
            print(f"  HTTP Status: {status_code}")
            print(f"  Response:    {json.dumps(body, indent=2)}")
    except urllib.error.HTTPError as e:
        status_code = e.code
        body_text = e.read().decode("utf-8")
        try:
            body = json.loads(body_text)
            body_formatted = json.dumps(body, indent=2)
        except Exception:
            body_formatted = body_text
        print(f"  HTTP Status: {status_code} (Error)")
        print(f"  Response:    {body_formatted}")
    except Exception as e:
        print(f"  Request failed: {e}")


def main():
    print("=" * 60)
    print("  PHISHING DETECTION API - LOCAL SANITY TEST  ")
    print("=" * 60)

    # 1. Start server with uvicorn
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        SERVER_HOST,
        "--port",
        str(SERVER_PORT),
    ]

    print(f"\n[1/3] Starting server with: {' '.join(cmd)}")
    server_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        print("\n[2/3] Waiting for server to initialize (2 seconds)...")
        time.sleep(2.0)

        if not wait_for_server(timeout=8.0):
            print("Error: Server failed to start within timeout.")
            if server_process.poll() is not None:
                output, _ = server_process.communicate()
                print("Server output:\n", output)
            sys.exit(1)

        print("Server is up and responsive at", BASE_URL)

        # 2. Send test requests
        print("\n[3/3] Sending test POST requests to /predict...\n")
        for i, item in enumerate(TEST_URLS, 1):
            print("-" * 60)
            print(f"Test #{i}: {item['description']}")
            print(f"Target URL: {item['url']}")
            send_prediction_request(item["url"])
            print("-" * 60 + "\n")

    finally:
        # 3. Clean up server process
        print("Shutting down local test server...")
        server_process.terminate()
        try:
            server_process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            server_process.kill()
        print("Server stopped cleanly. Sanity check complete!\n")


if __name__ == "__main__":
    main()
