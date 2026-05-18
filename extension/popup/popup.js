/**
 * Popup UI for Remote Signer browser extension.
 *
 * Communicates with background.js via chrome.runtime.sendMessage.
 * Zero direct network I/O — all API calls go through the background worker.
 */
(function () {
  "use strict";

  // ── State ────────────────────────────────────────────────────────────
  let config = null;
  let isSettingsDirty = false;

  // ── DOM refs ─────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);

  const views = {
    loading: $("loadingView"),
    connected: $("connectedView"),
    disconnected: $("disconnectedView"),
    settings: $("settingsView"),
  };

  const els = {
    connectionDot: $("connectionDot"),
    statusText: $("statusText"),
    versionBadge: $("versionBadge"),
    serverUrlDisplay: $("serverUrlDisplay"),
    accountList: $("accountList"),
    accountCount: $("accountCount"),
    rulesStat: $("rulesStat"),
    signersStat: $("signersStat"),
    requestsStat: $("requestsStat"),
    roleStat: $("roleStat"),
    chainSelect: $("chainSelect"),
    signerBanner: $("signerBanner"),
    signerBannerText: $("signerBannerText"),
    signerBannerAction: $("signerBannerAction"),
    // Settings
    inputUrl: $("inputUrl"),
    inputKeyId: $("inputKeyId"),
    inputPrivateKey: $("inputPrivateKey"),
    togglePwBtn: $("togglePwBtn"),
    connectionError: $("connectionError"),
    connectionSuccess: $("connectionSuccess"),
    testConnectionBtn: $("testConnectionBtn"),
    saveConfigBtn: $("saveConfigBtn"),
    backToMainBtn: $("backToMainBtn"),
    // Actions
    settingsBtn: $("settingsBtn"),
    managementBtn: $("managementBtn"),
    disconnectedSettingsBtn: $("disconnectedSettingsBtn"),
    disconnectedReason: $("disconnectedReason"),
  };

  // ── View switching ───────────────────────────────────────────────────

  function showView(name) {
    Object.keys(views).forEach((key) => {
      views[key].classList.toggle("hidden", key !== name);
    });
  }

  // ── Background IPC ───────────────────────────────────────────────────

  function send(msg) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(msg, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
    });
  }

  // ── Format helpers ───────────────────────────────────────────────────

  function shortenAddress(addr) {
    if (!addr || addr.length < 10) return addr || "";
    return addr.slice(0, 6) + "..." + addr.slice(-4);
  }

  function formatChainName(chainId) {
    const names = {
      1: "Ethereum",
      137: "Polygon",
      10: "Optimism",
      42161: "Arbitrum",
      8453: "Base",
      56: "BSC",
      11155111: "Sepolia",
    };
    return names[chainId] || `Chain ${chainId}`;
  }

  // ── Dashboard render ─────────────────────────────────────────────────

  function renderAccounts(signers, activeAddress) {
    els.accountList.innerHTML = "";
    if (!signers || signers.length === 0) {
      els.accountList.innerHTML =
        '<div class="account-item account-item--empty">No accounts</div>';
      els.accountCount.textContent = "0";
      return;
    }
    const usableCount = signers.filter((s) => s.enabled && !s.locked).length;
    els.accountCount.textContent = String(usableCount);

    const activeLower = (activeAddress || "").toLowerCase();
    signers.forEach((s) => {
      const addr = s.address;
      const usable = s.enabled && !s.locked;
      const isActive = usable && addr.toLowerCase() === activeLower;

      const div = document.createElement("div");
      div.className = "account-item" +
        (isActive ? " account-item--active" : "") +
        (usable ? "" : " account-item--disabled");
      div.dataset.address = addr;

      let statusIcon = "";
      let title = "";
      if (s.locked) { statusIcon = "🔒"; title = "Locked — contact your administrator"; }
      else if (!s.enabled) { statusIcon = "⛔"; title = "Disabled"; }
      if (title) div.title = title;

      div.innerHTML = `
        <span class="account-marker">${isActive ? "✓" : ""}</span>
        <span class="account-address">${shortenAddress(addr)}</span>
        <span class="account-type">${escapeText(s.type || "")}</span>
        ${statusIcon ? `<span class="account-status">${statusIcon}</span>` : ""}
        <button class="account-copy" title="Copy address" data-copy="${addr}">📋</button>
      `;

      const copyBtn = div.querySelector(".account-copy");
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(copyBtn.dataset.copy).catch(() => {});
      });

      if (usable && !isActive) {
        div.addEventListener("click", () => onSwitchAccount(addr));
      }

      els.accountList.appendChild(div);
    });
  }

  function escapeText(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
  }

  async function onSwitchAccount(address) {
    try {
      const resp = await send({ type: "popup:switchAccount", address });
      if (!resp || resp.ok !== true) {
        console.warn("[popup] switchAccount failed:", resp && resp.error);
        return;
      }
      // Re-init to pick up the new active address everywhere.
      await initPopup();
    } catch (err) {
      console.warn("[popup] switchAccount threw:", err);
    }
  }

  function renderDashboard(data) {
    els.rulesStat.textContent = data?.ruleCount ?? "-";
    els.signersStat.textContent = data?.signerCount ?? "-";
    els.requestsStat.textContent = data?.requestCount ?? "-";
    els.roleStat.textContent = data?.apiKeyRole ?? "-";
  }

  function renderConnectedState(state) {
    els.connectionDot.className = state.connected ? "dot connected" : "dot disconnected";
    els.statusText.textContent = state.connected ? "Connected" : "Disconnected";
    els.statusText.style.color = state.connected
      ? "var(--success)"
      : "var(--danger)";
  }

  // ── Main init ────────────────────────────────────────────────────────

  async function initPopup() {
    try {
      // Load config from background
      const configResp = await send({ type: "popup:getConfig" });
      config = configResp.config;

      // Fill settings form
      els.inputUrl.value = config.remoteSignerUrl || "";
      els.inputKeyId.value = config.apiKeyId || "";
      els.inputPrivateKey.value = config.apiKeyPrivateKey || "";
      els.chainSelect.value = String(config.selectedChain || 1);

      // Check connection state
      const stateResp = await send({ type: "popup:getState" });

      // Unconfigured → onboarding-style disconnected view.
      if (stateResp && stateResp.configured === false) {
        renderDisconnectedReason(null);
        showView("disconnected");
        els.connectionDot.className = "dot disconnected";
        return;
      }

      // Configured but cannot reach server / auth failed → disconnected with reason.
      if (!stateResp || stateResp.connected !== true) {
        renderDisconnectedReason(stateResp?.error || "Unable to reach Remote Signer");
        showView("disconnected");
        els.connectionDot.className = "dot disconnected";
        return;
      }

      // Connected. Server reachable, auth works. Signer readiness is informational.
      els.serverUrlDisplay.textContent = config.remoteSignerUrl;
      renderConnectedState(stateResp);
      renderSignerBanner(stateResp.signerStatus);
      renderAccounts(stateResp.signers || [], stateResp.activeAddress);

      const chainIdDecimal = parseInt(stateResp.chainId, 16);
      if (!Number.isNaN(chainIdDecimal)) {
        els.chainSelect.value = String(chainIdDecimal);
      }

      // Best-effort dashboard fetch — non-fatal if it fails.
      try {
        const dashboardResp = await send({ type: "popup:getDashboard" });
        renderDashboard(dashboardResp);
      } catch (err) {
        console.warn("[popup] dashboard fetch failed:", err);
      }

      showView("connected");
    } catch (err) {
      console.error("[popup] init error:", err);
      renderDisconnectedReason(err?.message);
      showView("disconnected");
      els.connectionDot.className = "dot disconnected";
    }
  }

  function renderDisconnectedReason(reason) {
    if (!els.disconnectedReason) return;
    if (reason) {
      els.disconnectedReason.textContent = reason;
      els.disconnectedReason.dataset.hasError = "true";
    } else {
      els.disconnectedReason.textContent = "Configure your connection in Settings";
      delete els.disconnectedReason.dataset.hasError;
    }
  }

  function renderSignerBanner(status) {
    if (!els.signerBanner || !els.signerBannerText) return;
    if (!status) {
      els.signerBanner.classList.add("hidden");
      return;
    }
    const { total, usable, locked, disabled } = status;
    if (usable > 0) {
      els.signerBanner.classList.add("hidden");
      return;
    }
    let msg;
    if (total === 0) {
      msg = "No signers on this server yet. Import or create one to start signing.";
    } else if (locked === total) {
      msg = `All ${total} signer${total === 1 ? "" : "s"} locked. Unlock to enable signing.`;
    } else if (disabled === total) {
      msg = `All ${total} signer${total === 1 ? "" : "s"} disabled. Enable one on the server.`;
    } else {
      msg = `${total} signer${total === 1 ? "" : "s"} found, none usable (${locked} locked, ${disabled} disabled).`;
    }
    els.signerBannerText.textContent = msg;
    els.signerBanner.classList.remove("hidden");
  }

  // ── Settings ─────────────────────────────────────────────────────────

  function showSettings() {
    els.connectionError.classList.add("hidden");
    els.connectionError.textContent = "";
    if (els.connectionSuccess) {
      els.connectionSuccess.classList.add("hidden");
      els.connectionSuccess.textContent = "";
    }
    showView("settings");
  }

  async function testConnection() {
    els.testConnectionBtn.disabled = true;
    els.testConnectionBtn.textContent = "Testing…";
    els.connectionError.classList.add("hidden");
    els.connectionError.textContent = "";
    if (els.connectionSuccess) {
      els.connectionSuccess.classList.add("hidden");
      els.connectionSuccess.textContent = "";
    }

    // Save temp config for the test
    const tempConfig = {
      remoteSignerUrl: els.inputUrl.value.trim(),
      apiKeyId: els.inputKeyId.value.trim(),
      apiKeyPrivateKey: els.inputPrivateKey.value.trim(),
      selectedChain: parseInt(els.chainSelect.value, 10) || 1,
    };

    try {
      const saveResp = await send({ type: "popup:saveConfig", config: tempConfig });
      if (saveResp && saveResp.ok === false) {
        els.connectionError.textContent = "Invalid configuration: " + (saveResp.error || "unknown error");
        els.connectionError.classList.remove("hidden");
        els.testConnectionBtn.disabled = false;
        els.testConnectionBtn.textContent = "Test Connection";
        return;
      }
      const result = await send({ type: "popup:testConnection" });
      if (result && result.ok) {
        const version = result.version ? `v${result.version}` : "connected";
        const signers = typeof result.signerCount === "number"
          ? `, ${result.signerCount} signer${result.signerCount === 1 ? "" : "s"}`
          : "";
        if (els.connectionSuccess) {
          els.connectionSuccess.textContent = `✓ Connection successful (${version}${signers})`;
          els.connectionSuccess.classList.remove("hidden");
        }
      } else {
        const errMsg = (result && result.error) || "Unknown error";
        els.connectionError.textContent = "Connection failed: " + errMsg;
        els.connectionError.classList.remove("hidden");
      }
    } catch (err) {
      els.connectionError.textContent = "Error: " + (err && err.message ? err.message : String(err));
      els.connectionError.classList.remove("hidden");
    } finally {
      els.testConnectionBtn.disabled = false;
      els.testConnectionBtn.textContent = "Test Connection";
    }
  }

  async function saveConfig() {
    els.saveConfigBtn.disabled = true;
    els.saveConfigBtn.textContent = "Saving...";
    els.connectionError.classList.add("hidden");
    els.connectionError.textContent = "";

    config = {
      remoteSignerUrl: els.inputUrl.value.trim(),
      apiKeyId: els.inputKeyId.value.trim(),
      apiKeyPrivateKey: els.inputPrivateKey.value.trim(),
      selectedChain: parseInt(els.chainSelect.value, 10) || 1,
    };

    const resp = await send({ type: "popup:saveConfig", config });
    if (resp && resp.ok === false) {
      els.connectionError.textContent = "Invalid configuration: " + (resp.error || "unknown error");
      els.connectionError.classList.remove("hidden");
      els.saveConfigBtn.disabled = false;
      els.saveConfigBtn.textContent = "Save";
      return;
    }
    showView("loading");
    await initPopup();
    els.saveConfigBtn.disabled = false;
    els.saveConfigBtn.textContent = "Save";
  }

  // ── Chain switching ──────────────────────────────────────────────────

  async function handleChainChange() {
    config.selectedChain = parseInt(els.chainSelect.value, 10) || 1;
    await send({ type: "popup:saveConfig", config });
    // Re-init to pick up new chain
    send({ type: "popup:getState" });
  }

  // ── Event wiring ─────────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", () => {
    initPopup();

    // Navigation
    els.settingsBtn.addEventListener("click", showSettings);
    els.disconnectedSettingsBtn.addEventListener("click", showSettings);
    els.backToMainBtn.addEventListener("click", () => {
      showView("loading");
      initPopup();
    });

    // Settings — private key is a textarea (so PEM fits); use CSS masking
    // instead of input[type=password] which has no equivalent on textarea.
    els.inputPrivateKey.classList.add("masked");
    els.togglePwBtn.textContent = "Show";
    els.togglePwBtn.addEventListener("click", () => {
      const masked = els.inputPrivateKey.classList.toggle("masked");
      els.togglePwBtn.textContent = masked ? "Show" : "Hide";
    });

    els.testConnectionBtn.addEventListener("click", testConnection);
    els.saveConfigBtn.addEventListener("click", saveConfig);

    if (els.signerBannerAction) {
      els.signerBannerAction.addEventListener("click", () => {
        send({ type: "popup:openManagement" });
      });
    }

    // Input change tracking
    [els.inputUrl, els.inputKeyId, els.inputPrivateKey].forEach((el) => {
      el.addEventListener("input", () => {
        isSettingsDirty = true;
      });
    });

    // Chain
    els.chainSelect.addEventListener("change", handleChainChange);

    // Management
    els.managementBtn.addEventListener("click", () => {
      send({ type: "popup:openManagement" });
    });
  });
})();
