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
    // Settings
    inputUrl: $("inputUrl"),
    inputKeyId: $("inputKeyId"),
    inputPrivateKey: $("inputPrivateKey"),
    togglePwBtn: $("togglePwBtn"),
    connectionError: $("connectionError"),
    testConnectionBtn: $("testConnectionBtn"),
    saveConfigBtn: $("saveConfigBtn"),
    backToMainBtn: $("backToMainBtn"),
    // Actions
    settingsBtn: $("settingsBtn"),
    managementBtn: $("managementBtn"),
    disconnectedSettingsBtn: $("disconnectedSettingsBtn"),
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

  function renderAccounts(accounts) {
    els.accountList.innerHTML = "";
    if (!accounts || accounts.length === 0) {
      els.accountList.innerHTML =
        '<div class="account-item" style="color:var(--text-muted);cursor:default;font-family:inherit">No accounts</div>';
      els.accountCount.textContent = "0";
      return;
    }
    els.accountCount.textContent = String(accounts.length);
    accounts.forEach((addr) => {
      const div = document.createElement("div");
      div.className = "account-item";
      div.innerHTML = `
        <span class="account-dot"></span>
        <span>${shortenAddress(addr)}</span>
        <span style="color:var(--text-muted);font-family:inherit;font-size:10px;margin-left:auto;cursor:pointer" title="Copy address" data-addr="${addr}">📋</span>
      `;
      const copyBtn = div.querySelector("[data-addr]");
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(copyBtn.dataset.addr).catch(() => {});
      });
      els.accountList.appendChild(div);
    });
  }

  function renderDashboard(data) {
    els.rulesStat.textContent = data.ruleCount ?? "-";
    els.signersStat.textContent = data.signerCount ?? "-";
    els.requestsStat.textContent = data.requestCount ?? "-";
    els.roleStat.textContent = data.apiKeyRole ?? "-";

    renderAccounts(data.signers || []);
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

      // Check provider state
      const stateResp = await send({ type: "popup:getState" });
      const isConnected = stateResp.connected;

      if (!config.apiKeyId || !config.apiKeyPrivateKey) {
        // No config — show disconnected state
        showView("disconnected");
        els.connectionDot.className = "dot disconnected";
        return;
      }

      els.serverUrlDisplay.textContent = config.remoteSignerUrl;

      if (isConnected) {
        renderConnectedState(stateResp);

        // Fetch dashboard data
        const dashboardResp = await send({ type: "popup:getDashboard" });
        renderDashboard(dashboardResp);

        // Set chain
        const chainIdDecimal = parseInt(stateResp.chainId, 16);
        els.chainSelect.value = String(chainIdDecimal);

        showView("connected");
      } else {
        // Connected state but provider not ready—attempt a connection test
        showView("disconnected");
        els.connectionDot.className = "dot disconnected";
      }
    } catch (err) {
      console.error("[popup] init error:", err);
      showView("disconnected");
      els.connectionDot.className = "dot disconnected";
    }
  }

  // ── Settings ─────────────────────────────────────────────────────────

  function showSettings() {
    els.connectionError.classList.add("hidden");
    showView("settings");
  }

  async function testConnection() {
    els.testConnectionBtn.disabled = true;
    els.testConnectionBtn.textContent = "Testing...";
    els.connectionError.classList.add("hidden");

    // Save temp config for the test
    const tempConfig = {
      remoteSignerUrl: els.inputUrl.value.trim(),
      apiKeyId: els.inputKeyId.value.trim(),
      apiKeyPrivateKey: els.inputPrivateKey.value.trim(),
      selectedChain: 1,
    };

    await send({ type: "popup:saveConfig", config: tempConfig });

    try {
      const result = await send({ type: "popup:testConnection" });
      if (result.ok) {
        els.connectionError.classList.add("hidden");
        showView("loading");
        await initPopup();
      } else {
        els.connectionError.textContent = "Connection failed: " + (result.error || "Unknown error");
        els.connectionError.classList.remove("hidden");
      }
    } catch (err) {
      els.connectionError.textContent = "Error: " + err.message;
      els.connectionError.classList.remove("hidden");
    } finally {
      els.testConnectionBtn.disabled = false;
      els.testConnectionBtn.textContent = "Test Connection";
    }
  }

  async function saveConfig() {
    els.saveConfigBtn.disabled = true;
    els.saveConfigBtn.textContent = "Saving...";

    config = {
      remoteSignerUrl: els.inputUrl.value.trim(),
      apiKeyId: els.inputKeyId.value.trim(),
      apiKeyPrivateKey: els.inputPrivateKey.value.trim(),
      selectedChain: parseInt(els.chainSelect.value, 10) || 1,
    };

    await send({ type: "popup:saveConfig", config });
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

    // Settings
    els.togglePwBtn.addEventListener("click", () => {
      const input = els.inputPrivateKey;
      input.type = input.type === "password" ? "text" : "password";
      els.togglePwBtn.textContent = input.type === "password" ? "Show" : "Hide";
    });

    els.testConnectionBtn.addEventListener("click", testConnection);
    els.saveConfigBtn.addEventListener("click", saveConfig);

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
