# Phishing Detection Shield - Chrome Extension (Manifest V3)

An automatic Google Chrome extension that scans websites in real time and displays a centered, frosted-glass **AI Threat Analysis** modal with a blurred, translucent website background.

---

## 🚀 Features

- **Automatic On-Page Detection**:
  - Automatically runs whenever you open any website (e.g. `https://snm.vitbhopal.ac.in/`, `https://www.wikipedia.org/`, or search results).
  - No need to click on the extension icon every time.
- **Centered Translucent Glassmorphic Modal**:
  - **Translucent Backdrop**: The visited website in the background is blurred and dimmed with frosted glass aesthetics (`backdrop-filter: blur(14px) brightness(0.65)`).
  - **Centered Threat Card**:
    - **Header**: `AI threat analysis` with dynamic status pill badge (`Caution`, `Danger`, `Safe`).
    - **Circular Risk Meter**: Animated circular gauge displaying threat percentage (e.g., `73% risk` in amber or `2% risk` in green).
    - **Headline & Description**: Contextual advice (*"Proceed with caution"*, *"The model sees patterns that resemble phishing domains."*, etc.).
    - **Active URL Box**: Monospace box showing the exact site URL.
    - **Top Signals**: Visual progress bars for `Subdomain depth`, `URL length`, and `HTTPS certificate`.
  - **Action Controls**:
    - **`Take me back`**: Immediately navigates back (`window.history.back()`) or to safety.
    - **`Proceed anyway`**: Smoothly dismisses the overlay and unblurs the page so you can interact with the website.
    - **`Report as safe`**: Whitelists false positives directly into `chrome.storage.local`.
- **Manual Trigger Support**:
  - If you dismiss the modal and want to inspect the site again at any time, clicking the extension icon in your Chrome toolbar immediately re-displays the centered overlay!
- **FastAPI Integration**:
  - Queries `http://127.0.0.1:8000/predict` via the background service worker (preventing any website CSP or CORS conflicts).

---

## 📦 How to Reload in Google Chrome

1. Open Google Chrome and go to `chrome://extensions`.
2. Click the **Reload (🔄)** button on the **Phishing Detection Shield** card.
3. Open any website in a new tab (e.g. `https://www.wikipedia.org/` or `https://snm.vitbhopal.ac.in/`).
4. The page will blur translucently, and the AI Threat Analysis card will appear in the dead center!
