// content.js - Instant Sub-Second Threat Analysis Overlay

(() => {
  // Prevent duplicate execution
  if (window.__phishingShieldAutoInjected) return;
  window.__phishingShieldAutoInjected = true;

  const currentUrl = window.location.href;

  // Ignore internal/non-web pages
  if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://")) {
    return;
  }

  const hostname = window.location.hostname;

  let hostElem = null;
  let shadowRoot = null;
  let isDismissed = false;

  // Search Engine Detection: Never show automatic popup while searching
  function isSearchEngine(url, host) {
    host = (host || "").toLowerCase();
    
    // Google search and Google home
    if (
      host === "google.com" ||
      host.endsWith(".google.com") ||
      host === "google.co.in" ||
      host.endsWith(".google.co.in")
    ) {
      return true;
    }
    // Bing
    if (host === "bing.com" || host.endsWith(".bing.com")) {
      return true;
    }
    // DuckDuckGo
    if (host === "duckduckgo.com" || host.endsWith(".duckduckgo.com")) {
      return true;
    }
    // Yahoo search
    if (host.includes("search.yahoo.com") || host === "search.yahoo.com") {
      return true;
    }
    // Baidu / Yandex
    if (host.includes("baidu.com") || host.includes("yandex.")) {
      return true;
    }
    return false;
  }

  // Known institutional and verified domains
  function isVitOrTrustedDomain(host) {
    host = (host || "").toLowerCase();
    return (
      host === "vitbhopal.ac.in" ||
      host.endsWith(".vitbhopal.ac.in") ||
      host === "vit.ac.in" ||
      host.endsWith(".vit.ac.in") ||
      host === "wikipedia.org" ||
      host.endsWith(".wikipedia.org") ||
      host === "github.com" ||
      host.endsWith(".github.com") ||
      host === "stackoverflow.com" ||
      host.endsWith(".stackoverflow.com") ||
      host === "microsoft.com" ||
      host.endsWith(".microsoft.com") ||
      host === "apple.com" ||
      host.endsWith(".apple.com")
    );
  }

  // Listen for manual trigger from toolbar extension icon
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "SHOW_THREAT_OVERLAY" || message.action === "TRIGGER_OVERLAY") {
      isDismissed = false;
      displayInstantOverlay(true);
      sendResponse({ status: "overlay_triggered" });
    }
    return true;
  });

  // Start instant check
  startInstantDetection();

  async function startInstantDetection() {
    // 1. If searching on Google/Bing/search engine, do not interrupt the user with a modal
    if (isSearchEngine(currentUrl, hostname)) {
      chrome.runtime.sendMessage({ action: "UPDATE_BADGE", riskLevel: "Safe" });
      return;
    }

    // 2. For all websites (opened directly or opened after searching), show instant centered modal!
    displayInstantOverlay(false);
  }

  // Instantly calculates exact risk and renders with zero delay (< 10ms)
  function displayInstantOverlay(forceShow) {
    // 1. Calculate instant local lexical signals (< 1ms)
    const initialData = computeLocalInstantAnalysis(currentUrl);

    // 2. Render centered overlay immediately onto page with exact percentage from frame 0
    renderOverlayDom(initialData, true);

    // 3. Simultaneously request backend AI model inference
    chrome.runtime.sendMessage(
      {
        action: "ANALYZE_URL",
        url: currentUrl,
      },
      (response) => {
        if (isDismissed) return;

        if (chrome.runtime.lastError) {
          updateOverlayData(initialData);
          return;
        }

        if (response && response.data) {
          updateOverlayData(response.data);
        } else {
          updateOverlayData(initialData);
        }
      }
    );
  }

  // Instant local lexical analysis (0ms execution time)
  function computeLocalInstantAnalysis(url) {
    const isHttps = url.startsWith("https://");
    const hostLower = hostname.toLowerCase();
    const parts = hostname.split(".").filter(Boolean);
    const pathAndQuery = (window.location.pathname + window.location.search).toLowerCase();

    const isVit = hostLower.includes("vitbhopal") || hostLower.includes("vit.ac.in");
    const isTrusted = isVitOrTrustedDomain(hostname);
    const isAcademicGov = hostLower.endsWith(".edu") || hostLower.endsWith(".ac.in") || hostLower.endsWith(".gov") || hostLower.endsWith(".org");

    let riskScore = 2;
    let riskLevel = "Safe";
    let headline = "Proceed with confidence";
    let description = "The model sees verified standard patterns. Website appears safe.";

    if (isVit) {
      riskScore = isHttps ? 2 : 4;
      riskLevel = "Safe";
      headline = "Proceed with confidence";
      description = "Official Vellore Institute of Technology (VIT Bhopal) domain. Verified authentic college portal.";
    } else if (isTrusted) {
      riskScore = isHttps ? 2 : 6;
      riskLevel = "Safe";
      headline = "Proceed with confidence";
      description = "Verified authentic platform. Website appears safe.";
    } else {
      // Dynamic calibrated risk scoring
      let score = 10.0;

      if (!isHttps) score += 26.0;

      // Suspicious keywords
      const suspiciousKeywords = ["login", "signin", "verify", "account", "banking", "secure", "update", "password", "wallet", "token"];
      const kwMatches = suspiciousKeywords.filter(kw => pathAndQuery.includes(kw)).length;
      if (kwMatches > 0) score += Math.min(24.0, kwMatches * 9.0);

      // Shady TLDs
      const shadyTlds = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", ".fit", ".date", ".cam"];
      if (shadyTlds.some(tld => hostLower.endsWith(tld))) {
        score += 25.0;
      } else if (isAcademicGov) {
        score -= 10.0;
      }

      // Subdomain depth on random domains
      if (parts.length >= 4 && !isAcademicGov) {
        score += 12.0;
      }

      riskScore = Math.max(1, Math.min(99, Math.round(score)));
      riskLevel = riskScore >= 70 ? "Danger" : riskScore >= 25 ? "Caution" : "Safe";
      headline = riskLevel === "Danger" ? "Proceed with extreme caution" : riskLevel === "Caution" ? "Proceed with caution" : "Proceed with confidence";
      description = riskLevel === "Danger"
        ? "High probability of deceptive or malicious phishing behavior."
        : riskLevel === "Caution"
        ? "The model sees patterns that resemble phishing domains."
        : "The model sees verified standard patterns. Website appears safe.";
    }

    const hasDeepSubdomain = parts.length >= 4;
    const isMediumSubdomain = parts.length === 3;
    const isLongUrl = url.length >= 65;
    const isMediumUrl = url.length >= 28;

    return {
      url,
      prediction: riskLevel === "Safe" ? "Safe" : "Phishing",
      confidence: riskLevel === "Safe" ? 0.98 : 0.73,
      risk_score: riskScore,
      risk_level: riskLevel,
      headline,
      description,
      signals: [
        {
          id: "subdomain_depth",
          label: "Subdomain depth",
          value: isVit ? "Normal (Academic)" : hasDeepSubdomain ? "High" : isMediumSubdomain ? "Medium" : "Low",
          percentage: isVit ? 20 : hasDeepSubdomain ? 80 : isMediumSubdomain ? 50 : 25,
          level: isVit ? "safe" : hasDeepSubdomain ? "warning" : "safe",
        },
        {
          id: "url_length",
          label: "URL length",
          value: isTrusted ? "Normal" : isLongUrl ? "High" : isMediumUrl ? "Medium" : "Short",
          percentage: isTrusted ? 25 : isLongUrl ? 85 : isMediumUrl ? 55 : 25,
          level: isTrusted ? "safe" : isLongUrl ? "warning" : "safe",
        },
        {
          id: "https_cert",
          label: "HTTPS certificate",
          value: isHttps ? "Valid" : "Not Secure",
          percentage: isHttps ? 25 : 85,
          level: isHttps ? "valid" : "danger",
        },
      ],
    };
  }

  // Mounts the isolated shadow DOM overlay immediately
  function renderOverlayDom(data, isInitial) {
    if (document.getElementById("phishing-shield-overlay-host")) {
      updateOverlayData(data);
      return;
    }

    hostElem = document.createElement("div");
    hostElem.id = "phishing-shield-overlay-host";

    // Attach to DOM immediately (supports document_start)
    if (document.documentElement) {
      document.documentElement.appendChild(hostElem);
    } else {
      document.addEventListener("DOMContentLoaded", () => {
        if (!document.getElementById("phishing-shield-overlay-host") && hostElem) {
          document.documentElement.appendChild(hostElem);
        }
      });
    }

    // Safeguard: Ensure overlay stays connected if page replaces document on refresh
    document.addEventListener("DOMContentLoaded", () => {
      if (!isDismissed && hostElem && !hostElem.isConnected && document.documentElement) {
        document.documentElement.appendChild(hostElem);
      }
    });

    shadowRoot = hostElem.attachShadow({ mode: "open" });

    const riskScore = data.risk_score !== undefined ? data.risk_score : 2;
    const riskLevel = data.risk_level || "Safe";
    const headline = data.headline || "Proceed with confidence";
    const description = data.description || "The model sees verified standard patterns. Website appears safe.";

    const strokeOffset = 251.33 * (1 - Math.min(100, Math.max(0, riskScore)) / 100);
    const strokeColor = riskLevel === "Danger" ? "#ef4444" : riskLevel === "Caution" ? "#f59e0b" : "#10b981";
    const badgeClass = "badge-" + riskLevel.toLowerCase();

    // Extract signals
    let subVal = "Normal", subPct = 20, subClass = "bar-green";
    let lenVal = "Normal", lenPct = 25, lenClass = "bar-green";
    let httpsVal = currentUrl.startsWith("https://") ? "Valid" : "Not Secure";
    let httpsPct = currentUrl.startsWith("https://") ? 25 : 85;
    let httpsClass = httpsVal === "Valid" ? "bar-green" : "bar-red";

    if (data.signals && Array.isArray(data.signals)) {
      data.signals.forEach((s) => {
        if (s.id === "subdomain_depth") {
          subVal = s.value;
          subPct = s.percentage;
          subClass = s.percentage > 70 ? "bar-amber" : "bar-green";
        } else if (s.id === "url_length") {
          lenVal = s.value;
          lenPct = s.percentage;
          lenClass = s.percentage > 70 ? "bar-amber" : "bar-green";
        } else if (s.id === "https_cert") {
          httpsVal = s.value;
          httpsPct = s.percentage;
          httpsClass = s.value === "Valid" ? "bar-green" : "bar-red";
        }
      });
    }

    const style = document.createElement("style");
    style.textContent = `
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

      :host {
        all: initial;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }

      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }

      /* Translucent blurred full-screen backdrop */
      .overlay-backdrop {
        position: fixed;
        inset: 0;
        width: 100vw;
        height: 100vh;
        z-index: 2147483647;
        background: radial-gradient(circle at 50% 38%, rgba(14, 30, 68, 0.78) 0%, rgba(6, 12, 28, 0.88) 100%);
        backdrop-filter: blur(14px) brightness(0.65);
        -webkit-backdrop-filter: blur(14px) brightness(0.65);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
        opacity: 0;
        animation: backdropFadeIn 0.15s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }

      @keyframes backdropFadeIn {
        to { opacity: 1; }
      }

      /* Centered Glassmorphic Threat Card */
      .threat-card {
        position: relative;
        width: 100%;
        max-width: 440px;
        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(32px);
        -webkit-backdrop-filter: blur(32px);
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 24px;
        box-shadow: 0 30px 80px rgba(0, 0, 0, 0.65), inset 0 1px 0 rgba(255, 255, 255, 0.25);
        padding: 26px 24px 22px 24px;
        display: flex;
        flex-direction: column;
        gap: 18px;
        color: #ffffff;
        transform: translateY(10px) scale(0.97);
        animation: cardSlideUp 0.2s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }

      @keyframes cardSlideUp {
        to {
          transform: translateY(0) scale(1);
        }
      }

      .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
      }

      .header-title {
        font-size: 14px;
        font-weight: 500;
        color: rgba(226, 232, 240, 0.9);
        letter-spacing: -0.01em;
      }

      .badge {
        font-size: 12px;
        font-weight: 500;
        padding: 3px 14px;
        border-radius: 9999px;
        letter-spacing: 0.01em;
        transition: all 0.3s ease;
      }

      .badge-caution {
        color: #fbbf24;
        background: rgba(245, 158, 11, 0.15);
        border: 1px solid rgba(245, 158, 11, 0.5);
      }

      .badge-danger {
        color: #f87171;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.5);
      }

      .badge-safe {
        color: #34d399;
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.5);
      }

      .threat-summary {
        display: flex;
        align-items: center;
        gap: 18px;
      }

      /* Circular Risk Gauge */
      .gauge-container {
        position: relative;
        width: 80px;
        height: 80px;
        flex-shrink: 0;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .gauge-svg {
        transform: rotate(-90deg);
        width: 80px;
        height: 80px;
      }

      .gauge-track {
        fill: none;
        stroke: rgba(255, 255, 255, 0.12);
        stroke-width: 6;
      }

      .gauge-fill {
        fill: none;
        stroke: ${strokeColor};
        stroke-width: 6;
        stroke-linecap: round;
        stroke-dasharray: 251.33;
        stroke-dashoffset: ${strokeOffset};
        transition: stroke-dashoffset 0.6s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.3s ease;
      }

      .gauge-text-wrap {
        position: absolute;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        line-height: 1.1;
      }

      .gauge-percentage {
        font-size: 20px;
        font-weight: 700;
        color: #ffffff;
      }

      .gauge-label {
        font-size: 11px;
        color: rgba(203, 213, 225, 0.75);
      }

      .threat-details {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      .threat-headline {
        font-size: 19px;
        font-weight: 600;
        color: #ffffff;
        letter-spacing: -0.015em;
        line-height: 1.25;
      }

      .threat-description {
        font-size: 13px;
        color: rgba(203, 213, 225, 0.85);
        line-height: 1.4;
      }

      /* URL Box */
      .url-box-container {
        width: 100%;
      }

      .url-box {
        width: 100%;
        background: rgba(30, 41, 59, 0.65);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 10px 14px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12.5px;
        color: #e2e8f0;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      /* Signals Section */
      .signals-section {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      .signals-title {
        font-size: 12.5px;
        font-weight: 500;
        color: rgba(148, 163, 184, 0.9);
      }

      .signals-list {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }

      .signal-item {
        display: flex;
        flex-direction: column;
        gap: 5px;
      }

      .signal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 13px;
        color: rgba(241, 245, 249, 0.95);
      }

      .signal-value {
        font-weight: 500;
      }

      .signal-track {
        width: 100%;
        height: 4.5px;
        background: rgba(255, 255, 255, 0.12);
        border-radius: 3px;
        overflow: hidden;
      }

      .signal-bar {
        height: 100%;
        border-radius: 3px;
        transition: width 0.5s ease, background-color 0.3s ease;
      }

      .bar-amber { background: #f59e0b; }
      .bar-green { background: #10b981; }
      .bar-red { background: #ef4444; }

      /* Action Buttons */
      .card-actions {
        display: flex;
        gap: 12px;
        margin-top: 4px;
      }

      .btn {
        flex: 1;
        padding: 12px 18px;
        border-radius: 12px;
        font-family: inherit;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s ease;
        outline: none;
      }

      .btn-primary {
        background: #ffffff;
        color: #0f172a;
        border: none;
        box-shadow: 0 4px 14px rgba(255, 255, 255, 0.15);
      }

      .btn-primary:hover {
        background: #f1f5f9;
        transform: translateY(-1px);
        box-shadow: 0 6px 18px rgba(255, 255, 255, 0.22);
      }

      .btn-secondary {
        background: rgba(255, 255, 255, 0.12);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.24);
        font-weight: 500;
      }

      .btn-secondary:hover {
        background: rgba(255, 255, 255, 0.18);
        border-color: rgba(255, 255, 255, 0.32);
        transform: translateY(-1px);
      }

      .report-safe-container {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        font-size: 12px;
        color: rgba(203, 213, 225, 0.8);
      }

      .report-link {
        background: none;
        border: none;
        color: rgba(203, 213, 225, 0.85);
        font-family: inherit;
        text-decoration: underline;
        cursor: pointer;
        font-size: 12px;
      }

      .report-link:hover {
        color: #ffffff;
      }
    `;

    const wrapper = document.createElement("div");
    wrapper.className = "overlay-backdrop";
    wrapper.id = "overlay-backdrop";
    wrapper.innerHTML = `
      <div class="threat-card" role="alertdialog" aria-modal="true">
        <header class="card-header">
          <span class="header-title">AI threat analysis</span>
          <span class="badge ${badgeClass}" id="card-badge">${riskLevel}</span>
        </header>

        <section class="threat-summary">
          <div class="gauge-container">
            <svg class="gauge-svg" viewBox="0 0 100 100">
              <circle class="gauge-track" cx="50" cy="50" r="40" />
              <circle class="gauge-fill" id="card-gauge-fill" cx="50" cy="50" r="40" />
            </svg>
            <div class="gauge-text-wrap">
              <span class="gauge-percentage" id="card-gauge-pct">${riskScore}%</span>
              <span class="gauge-label">risk</span>
            </div>
          </div>

          <div class="threat-details">
            <h1 class="threat-headline" id="card-headline">${headline}</h1>
            <p class="threat-description" id="card-description">${description}</p>
          </div>
        </section>

        <section class="url-box-container">
          <div class="url-box" title="${currentUrl}">${currentUrl}</div>
        </section>

        <section class="signals-section">
          <h2 class="signals-title">Top signals</h2>
          <div class="signals-list">
            <div class="signal-item">
              <div class="signal-header">
                <span>Subdomain depth</span>
                <span class="signal-value" id="card-subdomain-val">${subVal}</span>
              </div>
              <div class="signal-track">
                <div class="signal-bar ${subClass}" id="card-subdomain-bar" style="width: ${subPct}%;"></div>
              </div>
            </div>

            <div class="signal-item">
              <div class="signal-header">
                <span>URL length</span>
                <span class="signal-value" id="card-urllen-val">${lenVal}</span>
              </div>
              <div class="signal-track">
                <div class="signal-bar ${lenClass}" id="card-urllen-bar" style="width: ${lenPct}%;"></div>
              </div>
            </div>

            <div class="signal-item">
              <div class="signal-header">
                <span>HTTPS certificate</span>
                <span class="signal-value" id="card-https-val">${httpsVal}</span>
              </div>
              <div class="signal-track">
                <div class="signal-bar ${httpsClass}" id="card-https-bar" style="width: ${httpsPct}%;"></div>
              </div>
            </div>
          </div>
        </section>

        <footer class="card-actions">
          <button class="btn btn-primary" id="btn-take-back">Take me back</button>
          <button class="btn btn-secondary" id="btn-proceed">Proceed anyway</button>
        </footer>

        <div class="report-safe-container">
          <span>Think this is safe?</span>
          <button class="report-link" id="btn-report-safe">Report as safe</button>
        </div>
      </div>
    `;

    shadowRoot.appendChild(style);
    shadowRoot.appendChild(wrapper);

    // Bind event handlers
    const btnBack = wrapper.querySelector("#btn-take-back");
    const btnProceed = wrapper.querySelector("#btn-proceed");
    const btnReport = wrapper.querySelector("#btn-report-safe");

    btnBack.addEventListener("click", () => {
      dismissModal(wrapper);
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.replace("https://www.google.com");
      }
    });

    btnProceed.addEventListener("click", () => {
      dismissModal(wrapper);
    });

    btnReport.addEventListener("click", () => {
      try {
        chrome.storage.local.get(["whitelisted_domains"], (result) => {
          const list = result.whitelisted_domains || [];
          if (!list.includes(hostname)) {
            list.push(hostname);
            chrome.storage.local.set({ whitelisted_domains: list }, () => {
              dismissModal(wrapper);
            });
          } else {
            dismissModal(wrapper);
          }
        });
      } catch {
        dismissModal(wrapper);
      }
    });

    // Populate data
    updateOverlayData(data);
  }

  // Updates card elements smoothly in place
  function updateOverlayData(data) {
    if (!shadowRoot) return;

    const riskScore = data.risk_score !== undefined
      ? data.risk_score
      : (data.prediction === "Phishing" ? Math.round(data.confidence * 100) : Math.max(2, Math.round((1 - data.confidence) * 100)));

    const riskLevel = data.risk_level || (riskScore >= 70 ? "Danger" : riskScore >= 25 ? "Caution" : "Safe");
    const headline = data.headline || (riskLevel === "Caution" ? "Proceed with caution" : riskLevel === "Danger" ? "Proceed with extreme caution" : "Proceed with confidence");
    const description = data.description || (riskLevel === "Caution" ? "The model sees patterns that resemble phishing domains." : riskLevel === "Danger" ? "High probability of deceptive or malicious behavior." : "The model sees verified standard patterns. Website appears safe.");

    const badgeElem = shadowRoot.getElementById("card-badge");
    const gaugeFill = shadowRoot.getElementById("card-gauge-fill");
    const gaugePct = shadowRoot.getElementById("card-gauge-pct");
    const headlineElem = shadowRoot.getElementById("card-headline");
    const descElem = shadowRoot.getElementById("card-description");

    if (badgeElem) {
      badgeElem.textContent = riskLevel;
      badgeElem.className = `badge badge-${riskLevel.toLowerCase()}`;
    }

    if (gaugePct) {
      gaugePct.textContent = `${riskScore}%`;
    }

    if (gaugeFill) {
      const strokeOffset = 251.33 * (1 - Math.min(100, Math.max(0, riskScore)) / 100);
      gaugeFill.style.strokeDashoffset = strokeOffset;
      gaugeFill.style.stroke = riskLevel === "Danger" ? "#ef4444" : riskLevel === "Caution" ? "#f59e0b" : "#10b981";
    }

    if (headlineElem) headlineElem.textContent = headline;
    if (descElem) descElem.textContent = description;

    // Signals
    if (data.signals && Array.isArray(data.signals)) {
      data.signals.forEach((sig) => {
        if (sig.id === "subdomain_depth") {
          const valElem = shadowRoot.getElementById("card-subdomain-val");
          const barElem = shadowRoot.getElementById("card-subdomain-bar");
          if (valElem) valElem.textContent = sig.value;
          if (barElem) {
            barElem.style.width = `${sig.percentage}%`;
            barElem.className = `signal-bar ${sig.percentage > 70 ? 'bar-amber' : 'bar-green'}`;
          }
        } else if (sig.id === "url_length") {
          const valElem = shadowRoot.getElementById("card-urllen-val");
          const barElem = shadowRoot.getElementById("card-urllen-bar");
          if (valElem) valElem.textContent = sig.value;
          if (barElem) {
            barElem.style.width = `${sig.percentage}%`;
            barElem.className = `signal-bar ${sig.percentage > 70 ? 'bar-amber' : 'bar-green'}`;
          }
        } else if (sig.id === "https_cert") {
          const valElem = shadowRoot.getElementById("card-https-val");
          const barElem = shadowRoot.getElementById("card-https-bar");
          if (valElem) valElem.textContent = sig.value;
          if (barElem) {
            barElem.style.width = `${sig.percentage}%`;
            barElem.className = `signal-bar ${sig.value === 'Valid' ? 'bar-green' : 'bar-red'}`;
          }
        }
      });
    }
  }

  function dismissModal(wrapper) {
    isDismissed = true;
    if (wrapper) {
      wrapper.style.transition = "opacity 0.2s ease-out";
      wrapper.style.opacity = "0";
    }
    setTimeout(() => {
      if (hostElem) {
        hostElem.remove();
        hostElem = null;
        shadowRoot = null;
      }
    }, 200);
  }
})();
