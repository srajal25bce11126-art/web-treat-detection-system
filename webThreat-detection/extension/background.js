// background.js - Service Worker for Phishing Detection Shield

const BACKEND_API_URL = "http://127.0.0.1:8000/predict";

// Handle click on the toolbar extension icon
// Triggers the centered in-page overlay directly on the active tab
chrome.action.onClicked.addListener(async (tab) => {
  if (!tab || !tab.id || !tab.url) return;

  // Ignore internal/empty browser pages
  if (
    tab.url.startsWith("chrome://") ||
    tab.url.startsWith("edge://") ||
    tab.url.startsWith("about:") ||
    tab.url.startsWith("chrome-extension://") ||
    tab.url.startsWith("view-source:")
  ) {
    return;
  }

  try {
    // Send message to content script to display centered overlay
    await chrome.tabs.sendMessage(tab.id, { action: "TRIGGER_OVERLAY" });
  } catch (err) {
    // If content script was not already loaded on this tab, inject it on the fly
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content.js"],
      });
      await chrome.tabs.sendMessage(tab.id, { action: "TRIGGER_OVERLAY" });
    } catch (injectErr) {
      console.warn("Could not inject overlay into tab:", injectErr);
    }
  }
});

// Handle requests from content scripts (bypasses website CSP restrictions)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "ANALYZE_URL") {
    handleUrlAnalysis(message.url, sender ? sender.tab : null)
      .then((data) => sendResponse({ data }))
      .catch((err) => {
        console.warn("API inference error in background:", err);
        sendResponse({ data: null, error: err.message });
      });
    return true; // Keep message channel open for async response
  }

  if (message.action === "UPDATE_BADGE") {
    if (sender && sender.tab && sender.tab.id) {
      const isSafe = message.riskLevel === "Safe";
      chrome.action.setBadgeText({ text: isSafe ? "SAFE" : "WARN", tabId: sender.tab.id });
      chrome.action.setBadgeBackgroundColor({
        color: isSafe ? "#10B981" : "#F59E0B",
        tabId: sender.tab.id,
      });
    }
  }
});

// Fetch prediction from FastAPI and update tab badge
async function handleUrlAnalysis(url, tab) {
  try {
    const response = await fetch(BACKEND_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`Backend returned HTTP ${response.status}`);
    }

    const data = await response.json();

    // Update badge on sender tab
    if (tab && tab.id) {
      const isPhishing = data.prediction === "Phishing";
      const riskScore = data.risk_score !== undefined
        ? data.risk_score
        : (isPhishing ? Math.round(data.confidence * 100) : Math.max(2, Math.round((1 - data.confidence) * 100)));

      if (riskScore >= 70) {
        chrome.action.setBadgeText({ text: "WARN", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#EF4444", tabId: tab.id });
      } else if (riskScore >= 25) {
        chrome.action.setBadgeText({ text: "WARN", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#F59E0B", tabId: tab.id });
      } else {
        chrome.action.setBadgeText({ text: "SAFE", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#10B981", tabId: tab.id });
      }
    }

    return data;
  } catch (err) {
    console.warn("Backend API unavailable, returning null:", err);
    return null;
  }
}
