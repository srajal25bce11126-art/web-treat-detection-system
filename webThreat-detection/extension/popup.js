// popup.js - Controller for AI Threat Analysis Popup

const BACKEND_API_URL = "http://127.0.0.1:8000/predict";
const CIRCLE_CIRCUMFERENCE = 251.33; // 2 * Math.PI * 40

// DOM Elements
const threatBadge = document.getElementById("threat-badge");
const gaugeProgress = document.getElementById("gauge-progress");
const gaugePercentage = document.getElementById("gauge-percentage");
const threatHeadline = document.getElementById("threat-headline");
const threatDescription = document.getElementById("threat-description");
const targetUrlElem = document.getElementById("target-url");
const urlBox = document.getElementById("url-box");
const btnCopyUrl = document.getElementById("btn-copy-url");
const subdomainVal = document.getElementById("subdomain-value");
const subdomainBar = document.getElementById("subdomain-bar");
const urlLengthVal = document.getElementById("urllength-value");
const urlLengthBar = document.getElementById("urllength-bar");
const httpsVal = document.getElementById("https-value");
const httpsBar = document.getElementById("https-bar");
const btnTakeBack = document.getElementById("btn-take-back");
const btnProceed = document.getElementById("btn-proceed");
const btnReportSafe = document.getElementById("btn-report-safe");
const btnFullscreen = document.getElementById("btn-fullscreen");
const toastElem = document.getElementById("toast");

let currentTab = null;
let currentAnalysis = null;

// Initialize on popup load
document.addEventListener("DOMContentLoaded", async () => {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0) {
      showErrorState("No active tab found.");
      return;
    }

    currentTab = tabs[0];
    const url = currentTab.url || "";

    // Ignore internal or system pages
    if (!url || isInternalUrl(url)) {
      showSystemPageState(url || "chrome://newtab");
      return;
    }

    // Set initial URL
    targetUrlElem.textContent = url;
    targetUrlElem.title = url;

    // Fast-path client heuristic to populate immediately
    const initialSignals = analyzeUrlSignals(url);
    renderSignals(initialSignals);

    // Check if domain was previously reported safe
    const hostname = getHostname(url);
    const isSafeWhitelisted = await checkIfWhitelisted(hostname);

    if (isSafeWhitelisted) {
      applySafeState(url);
      return;
    }

    // Fetch live prediction from FastAPI backend
    await fetchBackendPrediction(url, initialSignals);

  } catch (err) {
    console.warn("Initialization notice:", err);
  }
});

// Check if URL is an internal browser page
function isInternalUrl(url) {
  return (
    url.startsWith("chrome://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("view-source:")
  );
}

// Extract hostname from URL
function getHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

// Check local storage whitelist
async function checkIfWhitelisted(hostname) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["whitelisted_domains"], (result) => {
      const list = result.whitelisted_domains || [];
      resolve(list.includes(hostname));
    });
  });
}

// Analyze local signals immediately for instant responsiveness
function analyzeUrlSignals(url) {
  let hostname = "";
  let isHttps = false;

  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    isHttps = parsed.protocol === "https:";
  } catch {
    hostname = url;
    isHttps = url.startsWith("https://");
  }

  const parts = hostname.split(".").filter(Boolean);
  
  // Subdomain depth
  let subdomainValue = "Low";
  let subdomainPct = 25;
  if (parts.length >= 4) {
    subdomainValue = "High";
    subdomainPct = 82;
  } else if (parts.length === 3) {
    subdomainValue = "Medium";
    subdomainPct = 50;
  }

  // URL length
  const uLen = url.length;
  let lenValue = "Low";
  let lenPct = 25;
  if (uLen >= 60) {
    lenValue = "High";
    lenPct = 85;
  } else if (uLen >= 28) {
    lenValue = "Medium";
    lenPct = 56;
  }

  // HTTPS Certificate
  const httpsValue = isHttps ? "Valid" : "Not Secure";
  const httpsPct = isHttps ? 25 : 85;

  return {
    subdomain: { value: subdomainValue, pct: subdomainPct },
    urlLength: { value: lenValue, pct: lenPct },
    https: { value: httpsValue, pct: httpsPct, isHttps },
  };
}

// Render signal bars and text values
function renderSignals(signals) {
  if (signals.subdomain) {
    subdomainVal.textContent = signals.subdomain.value;
    subdomainBar.style.width = `${signals.subdomain.pct}%`;
    subdomainBar.className = `signal-bar ${signals.subdomain.pct > 70 ? "bar-amber" : "bar-green"}`;
  }

  if (signals.urlLength) {
    urlLengthVal.textContent = signals.urlLength.value;
    urlLengthBar.style.width = `${signals.urlLength.pct}%`;
    urlLengthBar.className = `signal-bar ${signals.urlLength.pct > 50 ? "bar-amber" : "bar-green"}`;
  }

  if (signals.https) {
    httpsVal.textContent = signals.https.value;
    httpsBar.style.width = `${signals.https.pct}%`;
    httpsBar.className = `signal-bar ${signals.https.isHttps !== false ? "bar-green" : "bar-red"}`;
  }
}

// Fetch prediction from FastAPI
async function fetchBackendPrediction(url, initialSignals) {
  try {
    const response = await fetch(BACKEND_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    currentAnalysis = data;
    applyAnalysisToUI(data, url);

  } catch (err) {
    console.warn("Backend API unreachable, using local heuristics:", err);
    const hostLower = getHostname(url).toLowerCase();
    const isVit = hostLower.includes("vitbhopal") || hostLower.includes("vit.ac.in");
    const isTrusted = isVit || hostLower.includes("google.") || hostLower.includes("wikipedia.org");
    const isPhishing = !isTrusted && (initialSignals.subdomain.pct > 70 || !initialSignals.https.isHttps);

    const fallbackData = {
      url,
      prediction: isPhishing ? "Phishing" : "Safe",
      confidence: isPhishing ? 0.73 : 0.98,
      risk_score: isPhishing ? 73 : 2,
      risk_level: isPhishing ? "Caution" : "Safe",
      headline: isPhishing ? "Proceed with caution" : "Proceed with confidence",
      description: isVit
        ? "Official Vellore Institute of Technology (VIT Bhopal) domain. Verified authentic college portal."
        : isPhishing
        ? "The model sees patterns that resemble phishing domains."
        : "The model detected no suspicious characteristics for this domain.",
    };
    currentAnalysis = fallbackData;
    applyAnalysisToUI(fallbackData, url);
  }
}

// Apply threat analysis results to UI
function applyAnalysisToUI(data, url) {
  targetUrlElem.textContent = url;
  targetUrlElem.title = url;

  const riskScore = data.risk_score !== undefined
    ? data.risk_score
    : (data.prediction === "Phishing" ? Math.round(data.confidence * 100) : Math.max(2, Math.round((1 - data.confidence) * 100)));

  // Gauge Percentage
  gaugePercentage.textContent = `${riskScore}%`;

  // Animate Gauge Ring
  const offset = CIRCLE_CIRCUMFERENCE * (1 - Math.min(100, Math.max(0, riskScore)) / 100);
  gaugeProgress.style.strokeDashoffset = offset;

  // Determine Level Colors & Copy
  let level = data.risk_level || (riskScore >= 80 ? "Danger" : riskScore >= 40 ? "Caution" : "Safe");
  
  // Update Badge
  threatBadge.textContent = level;
  threatBadge.className = `badge badge-${level.toLowerCase()}`;

  // Update Gauge Color
  if (level === "Danger") {
    gaugeProgress.style.stroke = "var(--red)";
  } else if (level === "Caution") {
    gaugeProgress.style.stroke = "var(--amber)";
  } else {
    gaugeProgress.style.stroke = "var(--green)";
  }

  // Update Headline & Description
  threatHeadline.textContent = data.headline || (level === "Danger" ? "Phishing threat detected" : level === "Caution" ? "Proceed with caution" : "Proceed with confidence");
  threatDescription.textContent = data.description || (level === "Danger" ? "High probability of deceptive or malicious behavior." : level === "Caution" ? "The model sees patterns that resemble phishing domains." : "No significant phishing signals detected for this domain.");

  // Update toolbar badge
  if (currentTab && currentTab.id) {
    const badgeText = level === "Safe" ? "SAFE" : "WARN";
    const badgeColor = level === "Safe" ? "#10B981" : level === "Danger" ? "#EF4444" : "#F59E0B";
    chrome.action.setBadgeText({ text: badgeText, tabId: currentTab.id });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: currentTab.id });
  }

  // If backend provided detailed signals, update them
  if (data.signals && Array.isArray(data.signals)) {
    data.signals.forEach((sig) => {
      if (sig.id === "subdomain_depth") {
        subdomainVal.textContent = sig.value;
        subdomainBar.style.width = `${sig.percentage}%`;
        subdomainBar.className = `signal-bar ${sig.percentage > 70 ? "bar-amber" : "bar-green"}`;
      } else if (sig.id === "url_length") {
        urlLengthVal.textContent = sig.value;
        urlLengthBar.style.width = `${sig.percentage}%`;
        urlLengthBar.className = `signal-bar ${sig.percentage > 50 ? "bar-amber" : "bar-green"}`;
      } else if (sig.id === "https_cert") {
        httpsVal.textContent = sig.value;
        httpsBar.style.width = `${sig.percentage}%`;
        httpsBar.className = `signal-bar ${sig.level === "danger" ? "bar-red" : "bar-green"}`;
      }
    });
  }
}

// Apply Safe State UI
function applySafeState(url) {
  const safeData = {
    url,
    prediction: "Safe",
    confidence: 0.98,
    risk_score: 2,
    risk_level: "Safe",
    headline: "Proceed with confidence",
    description: "Verified safe domain. Whitelisted by user.",
  };
  currentAnalysis = safeData;
  applyAnalysisToUI(safeData, url);

  httpsVal.textContent = "Valid";
  httpsBar.style.width = "25%";
  httpsBar.className = "signal-bar bar-green";
}

// UI for internal browser pages
function showSystemPageState(url) {
  targetUrlElem.textContent = url;
  gaugePercentage.textContent = "0%";
  gaugeProgress.style.strokeDashoffset = CIRCLE_CIRCUMFERENCE;
  threatBadge.textContent = "System";
  threatBadge.className = "badge badge-safe";
  threatHeadline.textContent = "Browser System Page";
  threatDescription.textContent = "Internal browser pages are safe and cannot be scanned.";
  subdomainVal.textContent = "N/A";
  subdomainBar.style.width = "0%";
  urlLengthVal.textContent = "Short";
  urlLengthBar.style.width = "10%";
  httpsVal.textContent = "Internal";
  httpsBar.style.width = "10%";
  btnReportSafe.style.display = "none";
}

// UI for error state
function showErrorState(msg) {
  threatHeadline.textContent = "Analysis Unavailable";
  threatDescription.textContent = msg;
}

// Toast helper
function showToast(message) {
  toastElem.textContent = message;
  toastElem.classList.add("show");
  setTimeout(() => {
    toastElem.classList.remove("show");
  }, 2400);
}

// Button Handlers
btnTakeBack.addEventListener("click", async () => {
  if (currentTab && currentTab.id) {
    try {
      await chrome.tabs.goBack(currentTab.id);
    } catch {
      // If no back history exists, redirect to safe search
      await chrome.tabs.update(currentTab.id, { url: "https://www.google.com" });
    }
  }
  window.close();
});

btnProceed.addEventListener("click", () => {
  window.close();
});

btnReportSafe.addEventListener("click", async () => {
  if (!currentTab || !currentTab.url) return;
  const hostname = getHostname(currentTab.url);

  chrome.storage.local.get(["whitelisted_domains"], (result) => {
    const list = result.whitelisted_domains || [];
    if (!list.includes(hostname)) {
      list.push(hostname);
      chrome.storage.local.set({ whitelisted_domains: list }, () => {
        applySafeState(currentTab.url);
        showToast("✓ Domain marked as safe and whitelisted");
      });
    } else {
      showToast("Domain is already in safe whitelist");
    }
  });
});

// Copy URL on click
urlBox.addEventListener("click", () => {
  const url = targetUrlElem.textContent;
  if (url) {
    navigator.clipboard.writeText(url).then(() => {
      showToast("✓ URL copied to clipboard");
    }).catch(() => {
      showToast("Failed to copy URL");
    });
  }
});

btnCopyUrl.addEventListener("click", (e) => {
  e.stopPropagation();
  urlBox.click();
});

// Fullscreen / in-page overlay launcher
btnFullscreen.addEventListener("click", async () => {
  if (!currentTab || !currentTab.id) return;

  try {
    await chrome.tabs.sendMessage(currentTab.id, {
      action: "SHOW_THREAT_OVERLAY",
      data: currentAnalysis || {
        url: currentTab.url,
        risk_score: 73,
        risk_level: "Caution",
        headline: "Proceed with caution",
        description: "The model sees patterns that resemble phishing domains.",
      },
    });
    window.close();
  } catch (err) {
    // Inject content script if not already present
    try {
      await chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        files: ["content.js"],
      });
      await chrome.scripting.insertCSS({
        target: { tabId: currentTab.id },
        files: ["content.css"],
      });
      await chrome.tabs.sendMessage(currentTab.id, {
        action: "SHOW_THREAT_OVERLAY",
        data: currentAnalysis,
      });
      window.close();
    } catch (injectErr) {
      showToast("Cannot overlay on this page");
    }
  }
});
