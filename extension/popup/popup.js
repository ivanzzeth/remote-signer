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
  // Tracks the last main view rendered by initPopup. The back button uses
  // it to navigate without re-fetching state (which would wipe unsaved
  // settings edits). Empty until initPopup has rendered once.
  let lastMainView = "";

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
    tabAccountsBtn: $("tabAccountsBtn"),
    tabActivityBtn: $("tabActivityBtn"),
    tabAccounts: $("tabAccounts"),
    tabActivity: $("tabActivity"),
    activityList: $("activityList"),
    activityRefreshBtn: $("activityRefreshBtn"),
    requestDrawer: $("requestDrawer"),
    drawerCloseBtn: $("drawerCloseBtn"),
    drawerBody: $("drawerBody"),
    appbarChainBtn: $("appbarChainBtn"),
    appbarChainLabel: $("appbarChainLabel"),
    appbarSignerBtn: $("appbarSignerBtn"),
    appbarSignerLabel: $("appbarSignerLabel"),
    appbarAvatar: $("appbarAvatar"),
    chainDropdown: $("chainDropdown"),
    signerDropdown: $("signerDropdown"),
    roleBadge: $("roleBadge"),
    // Settings
    inputUrl: $("inputUrl"),
    inputKeyId: $("inputKeyId"),
    inputPrivateKey: $("inputPrivateKey"),
    togglePwBtn: $("togglePwBtn"),
    loadKeyFileBtn: $("loadKeyFileBtn"),
    keyFileInput: $("keyFileInput"),
    inputAutoApprove: $("inputAutoApprove"),
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

      // Attach the click handler to every usable row (even the already-
      // active one). The SDK switchAccount is a no-op when the target
      // matches the active signer, but handlePopupSwitchAccount also
      // re-applies the wallet-wide "use this signer everywhere"
      // intent to permitted origins. That second effect is the reason
      // a user might re-click the active row — to push it into a dApp
      // they've granted but who hasn't seen the new active yet.
      if (usable) {
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

  // ── Header chips (chain + signer) ────────────────────────────────────

  let lastSigners = [];
  let lastActiveAddress = null;

  function avatarColor(addr) {
    // Deterministic hue from the address so each signer gets a stable colour.
    if (!addr) return "#666";
    let h = 0;
    for (let i = 2; i < addr.length; i++) h = (h * 31 + addr.charCodeAt(i)) % 360;
    return `hsl(${h}, 65%, 55%)`;
  }

  function updateHeaderChips(stateResp) {
    if (!els.appbarChainBtn || !els.appbarSignerBtn) return;
    const connected = stateResp && stateResp.connected === true;
    if (!connected) {
      els.appbarChainBtn.classList.add("hidden");
      els.appbarSignerBtn.classList.add("hidden");
      return;
    }
    // Chain
    const chainIdHex = stateResp.chainId || "0x1";
    const chainIdDec = parseInt(chainIdHex, 16) || 1;
    els.appbarChainLabel.textContent = formatChainName(chainIdDec);
    els.appbarChainBtn.classList.remove("hidden");

    // Signer
    lastSigners = stateResp.signers || [];
    lastActiveAddress = stateResp.activeAddress || null;
    if (lastActiveAddress) {
      els.appbarSignerLabel.textContent = shortenAddress(lastActiveAddress);
      els.appbarAvatar.style.background = avatarColor(lastActiveAddress);
      els.appbarSignerBtn.classList.remove("hidden");
    } else {
      els.appbarSignerBtn.classList.add("hidden");
    }
  }

  function openDropdown(target) {
    closeAllDropdowns(target);
    target.classList.remove("hidden");
    // Click-outside to dismiss.
    setTimeout(() => {
      document.addEventListener("click", onOutsideClick, { once: true, capture: true });
    }, 0);
  }
  function closeAllDropdowns(except) {
    [els.chainDropdown, els.signerDropdown].forEach((d) => {
      if (d && d !== except) d.classList.add("hidden");
    });
  }
  function onOutsideClick(e) {
    const insideChain = els.chainDropdown.contains(e.target) || els.appbarChainBtn.contains(e.target);
    const insideSigner = els.signerDropdown.contains(e.target) || els.appbarSignerBtn.contains(e.target);
    if (!insideChain && !insideSigner) {
      closeAllDropdowns(null);
    } else {
      // Re-arm so the next click-out closes it.
      setTimeout(() => {
        document.addEventListener("click", onOutsideClick, { once: true, capture: true });
      }, 0);
    }
  }

  function buildChainDropdown() {
    const chains = [
      { id: 1, name: "Ethereum" },
      { id: 137, name: "Polygon" },
      { id: 10, name: "Optimism" },
      { id: 42161, name: "Arbitrum" },
      { id: 8453, name: "Base" },
      { id: 56, name: "BSC" },
      { id: 11155111, name: "Sepolia" },
    ];
    const current = parseInt(els.chainSelect.value, 10) || 1;
    els.chainDropdown.innerHTML = "";
    chains.forEach((c) => {
      const item = document.createElement("div");
      item.className = "appbar-dropdown-item" + (c.id === current ? " appbar-dropdown-item--active" : "");
      item.innerHTML = `
        <span class="item-marker">${c.id === current ? "✓" : ""}</span>
        <span class="item-text">${escapeText(c.name)}</span>
        <span class="item-meta">${c.id}</span>
      `;
      item.addEventListener("click", () => {
        els.chainSelect.value = String(c.id);
        els.appbarChainLabel.textContent = c.name;
        closeAllDropdowns(null);
        handleChainChange();
      });
      els.chainDropdown.appendChild(item);
    });
  }

  function buildSignerDropdown() {
    els.signerDropdown.innerHTML = "";
    if (!lastSigners.length) {
      els.signerDropdown.innerHTML = '<div class="appbar-dropdown-item appbar-dropdown-item--disabled"><span class="item-text">No signers</span></div>';
      return;
    }
    const activeLower = (lastActiveAddress || "").toLowerCase();
    lastSigners.forEach((s) => {
      const usable = s.enabled && !s.locked;
      const isActive = usable && s.address.toLowerCase() === activeLower;
      const item = document.createElement("div");
      item.className = "appbar-dropdown-item" +
        (isActive ? " appbar-dropdown-item--active" : "") +
        (usable ? "" : " appbar-dropdown-item--disabled");
      let badge = "";
      if (s.locked) badge = "🔒";
      else if (!s.enabled) badge = "⛔";
      item.innerHTML = `
        <span class="item-marker">${isActive ? "✓" : ""}</span>
        <span class="item-text">${shortenAddress(s.address)}</span>
        <span class="item-meta">${escapeText(s.type || "")} ${badge}</span>
      `;
      if (usable && !isActive) {
        item.addEventListener("click", () => {
          closeAllDropdowns(null);
          onSwitchAccount(s.address);
        });
      }
      els.signerDropdown.appendChild(item);
    });
  }

  function renderRoleBadge(role) {
    if (!els.roleBadge) return;
    if (!role || role === "unknown") {
      els.roleBadge.classList.add("hidden");
      return;
    }
    els.roleBadge.textContent = role;
    els.roleBadge.className = `role-badge role-badge--${role}`;
  }

  // ── Tabs + Activity ──────────────────────────────────────────────────

  let activeTab = "accounts";
  let activityLoaded = false;

  function selectTab(name) {
    activeTab = name;
    const tabs = [
      { btn: els.tabAccountsBtn, panel: els.tabAccounts, key: "accounts" },
      { btn: els.tabActivityBtn, panel: els.tabActivity, key: "activity" },
    ];
    tabs.forEach((t) => {
      const active = t.key === name;
      t.btn.classList.toggle("tabbar-btn--active", active);
      t.btn.setAttribute("aria-selected", String(active));
      t.panel.classList.toggle("hidden", !active);
    });
    if (name === "activity" && !activityLoaded) {
      loadActivity();
    }
  }

  function formatTimestamp(iso) {
    if (!iso) return "";
    try {
      const d = new Date(iso);
      const now = Date.now();
      const diff = (now - d.getTime()) / 1000;
      if (diff < 60) return `${Math.floor(diff)}s ago`;
      if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
      if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
      return d.toLocaleDateString();
    } catch {
      return iso;
    }
  }

  function statusClass(status) {
    return "activity-status--" + String(status || "").toLowerCase();
  }

  async function loadActivity() {
    els.activityList.innerHTML = '<div class="activity-empty">Loading…</div>';
    try {
      const resp = await send({ type: "popup:getActivity", limit: 20 });
      activityLoaded = true;
      if (!resp || resp.ok === false) {
        els.activityList.innerHTML = `<div class="activity-error">${escapeText((resp && resp.error) || "Failed to load")}</div>`;
        return;
      }
      const reqs = resp.requests || [];
      if (reqs.length === 0) {
        els.activityList.innerHTML = '<div class="activity-empty">No requests yet</div>';
        return;
      }
      els.activityList.innerHTML = "";
      reqs.forEach((r) => {
        const div = document.createElement("div");
        div.className = "activity-item";
        div.dataset.requestId = r.id;
        div.innerHTML = `
          <span class="activity-status ${statusClass(r.status)}">${escapeText(r.status || "")}</span>
          <div class="activity-main">
            <div class="activity-row1">
              <span class="activity-type">${escapeText(r.sign_type || "?")}</span>
              <span class="activity-chain">chain ${escapeText(r.chain_id || "?")}</span>
            </div>
            <div class="activity-row2">
              <span class="activity-addr">${shortenAddress(r.signer_address || "")}</span>
              <span class="activity-time">${escapeText(formatTimestamp(r.created_at))}</span>
            </div>
          </div>
        `;
        div.addEventListener("click", () => openRequestDrawer(r.id));
        els.activityList.appendChild(div);
      });
    } catch (err) {
      els.activityList.innerHTML = `<div class="activity-error">${escapeText(err?.message || String(err))}</div>`;
    }
  }

  async function openRequestDrawer(requestId) {
    els.drawerBody.innerHTML = '<div class="activity-empty">Loading…</div>';
    els.requestDrawer.classList.remove("hidden");
    try {
      const resp = await send({ type: "popup:getRequest", requestId });
      if (!resp || resp.ok === false) {
        els.drawerBody.innerHTML = `<div class="activity-error">${escapeText((resp && resp.error) || "Failed to load")}</div>`;
        return;
      }
      els.drawerBody.innerHTML = renderRequestDetail(resp.request);
    } catch (err) {
      els.drawerBody.innerHTML = `<div class="activity-error">${escapeText(err?.message || String(err))}</div>`;
    }
  }

  // Decode a hex-encoded personal_sign / EIP-191 message body back to
  // UTF-8 so operators can read the SIWE text in the activity drawer.
  // Returns null when the input isn't even-length valid hex or doesn't
  // decode as valid UTF-8.
  function decodeHexMessageToUtf8(maybeHex) {
    if (typeof maybeHex !== "string") return null;
    if (!maybeHex.startsWith("0x") || maybeHex.length % 2 !== 0) return null;
    const body = maybeHex.slice(2);
    if (!/^[0-9a-fA-F]*$/.test(body)) return null;
    const bytes = new Uint8Array(body.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(body.substr(i * 2, 2), 16);
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return null;
    }
  }

  function extractSiweChainId(messageText) {
    if (typeof messageText !== "string") return null;
    const m = messageText.match(/^\s*Chain ID:\s*(\d+)\s*$/m);
    return m ? parseInt(m[1], 10) : null;
  }

  function renderRequestDetail(r) {
    const row = (label, value) =>
      value
        ? `<div class="drawer-row"><span class="drawer-label">${escapeText(label)}</span><span class="drawer-value">${escapeText(value)}</span></div>`
        : "";

    // Decoded message preview: for personal_sign / EIP-191 we decode hex
    // to UTF-8 (SIWE text), for typed_data we pretty-print the JSON, for
    // transaction we pretty-print the tx object. Surfaces a chain-mismatch
    // warning when the SIWE text's Chain ID line disagrees with the
    // request's chain_id — the same failure mode that produced the
    // Polymarket 401 "Request Cancelled" symptom.
    let messageBlock = "";
    if (r.payload) {
      let decoded = null;
      let chainWarning = "";
      if (r.sign_type === "personal" || r.sign_type === "eip191" || r.sign_type === "raw_message") {
        const hex = r.payload.message ?? r.payload.raw_message;
        decoded = decodeHexMessageToUtf8(hex) ?? (typeof hex === "string" ? hex : null);
        if (decoded) {
          const siweChain = extractSiweChainId(decoded);
          if (siweChain != null && r.chain_id && siweChain !== parseInt(r.chain_id, 10)) {
            chainWarning = `<div class="drawer-warning">⚠ SIWE text says Chain ID ${siweChain} but the request was on chain ${escapeText(r.chain_id)}. The dApp's backend will reject this signature even though it's cryptographically valid.</div>`;
          }
        }
      } else if (r.sign_type === "typed_data" && r.payload.typed_data) {
        try { decoded = JSON.stringify(r.payload.typed_data, null, 2); } catch {}
      } else if (r.sign_type === "transaction" && r.payload.transaction) {
        try { decoded = JSON.stringify(r.payload.transaction, null, 2); } catch {}
      }
      if (decoded) {
        messageBlock =
          chainWarning +
          `<div class="drawer-row"><span class="drawer-label">Message</span><pre class="drawer-payload">${escapeText(decoded)}</pre></div>`;
      }
    }

    let payloadBlock = "";
    if (r.payload) {
      const pretty = (() => {
        try { return JSON.stringify(r.payload, null, 2); } catch { return String(r.payload); }
      })();
      payloadBlock = `<details class="drawer-row drawer-raw"><summary class="drawer-label">Raw payload</summary><pre class="drawer-payload">${escapeText(pretty)}</pre></details>`;
    }
    // No-match diagnostic: the rule engine's reason text gets pinned on
    // the request row when no whitelist matched (P3 #12 — replaces the
    // "rule mysteriously didn't fire, go grep server logs" failure mode
    // with a one-line in-popup explanation).
    const noMatchBlock = r.last_no_match_reason && !r.rule_matched_id
      ? `<div class="drawer-warning" data-testid="no-match-reason">⚠ No whitelist rule matched: ${escapeText(r.last_no_match_reason)}</div>`
      : "";

    return [
      row("Request ID", r.id),
      row("Status", r.status),
      row("Sign type", r.sign_type),
      row("Chain", r.chain_id),
      row("Signer", r.signer_address),
      row("Rule matched", r.rule_matched_id),
      row("Approved by", r.approved_by),
      row("Approved at", r.approved_at),
      row("Created", r.created_at),
      row("Completed", r.completed_at),
      r.signature ? row("Signature", r.signature) : "",
      r.error_message ? row("Error", r.error_message) : "",
      noMatchBlock,
      messageBlock,
      payloadBlock,
    ].join("");
  }

  function closeRequestDrawer() {
    els.requestDrawer.classList.add("hidden");
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

      // Fill settings form. Default the API Key ID to "agent" to match
      // the standard `~/.remote-signer/apikeys/agent.key.priv` bootstrap.
      els.inputUrl.value = config.remoteSignerUrl || "";
      els.inputKeyId.value = config.apiKeyId || "agent";
      els.inputPrivateKey.value = config.apiKeyPrivateKey || "";
      els.chainSelect.value = String(config.selectedChain || 1);
      // Auto-approve defaults to ON; treat undefined as true so users
      // upgrading from a pre-toggle build don't suddenly see prompts.
      if (els.inputAutoApprove) els.inputAutoApprove.checked = config.autoApproveConnections !== false;

      // Check connection state
      const stateResp = await send({ type: "popup:getState" });

      // Unconfigured → onboarding-style disconnected view.
      if (stateResp && stateResp.configured === false) {
        renderDisconnectedReason(null);
        showView("disconnected");
        lastMainView = "disconnected";
        els.connectionDot.className = "dot disconnected";
        return;
      }

      // Configured but cannot reach server / auth failed → disconnected with reason.
      if (!stateResp || stateResp.connected !== true) {
        renderDisconnectedReason(stateResp?.error || "Unable to reach Remote Signer");
        showView("disconnected");
        lastMainView = "disconnected";
        els.connectionDot.className = "dot disconnected";
        return;
      }

      // Connected. Server reachable, auth works. Signer readiness is informational.
      els.serverUrlDisplay.textContent = config.remoteSignerUrl;
      renderConnectedState(stateResp);
      renderSignerBanner(stateResp.signerStatus);
      renderAccounts(stateResp.signers || [], stateResp.activeAddress);
      updateHeaderChips(stateResp);

      // Reset activity state — list will be re-fetched if the user opens
      // the tab. Don't auto-fetch on every popup open to save the API call.
      activityLoaded = false;
      if (activeTab === "activity") loadActivity();
      closeRequestDrawer();

      const chainIdDecimal = parseInt(stateResp.chainId, 16);
      if (!Number.isNaN(chainIdDecimal)) {
        els.chainSelect.value = String(chainIdDecimal);
      }

      // Best-effort dashboard fetch — non-fatal if it fails.
      try {
        const dashboardResp = await send({ type: "popup:getDashboard" });
        renderDashboard(dashboardResp);
        renderRoleBadge(dashboardResp && dashboardResp.apiKeyRole);
      } catch (err) {
        console.warn("[popup] dashboard fetch failed:", err);
      }

      showView("connected");
      lastMainView = "connected";
    } catch (err) {
      console.error("[popup] init error:", err);
      renderDisconnectedReason(err?.message);
      showView("disconnected");
      lastMainView = "disconnected";
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

  // ── Key file loader (FSA API + drag-drop + legacy input fallback) ────

  // IndexedDB helpers for persisting the last-used FileSystemFileHandle.
  // Browser security prevents <input type=file> from opening with a
  // custom default directory, so we instead remember which file the
  // user picked and re-open it directly on subsequent runs.
  const HANDLE_DB_NAME = "remote-signer-popup";
  const HANDLE_STORE = "kv";
  const HANDLE_KEY = "keyFileHandle";

  function openHandleDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(HANDLE_DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(HANDLE_STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function loadStoredFileHandle() {
    try {
      const db = await openHandleDB();
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(HANDLE_STORE, "readonly");
        const req = tx.objectStore(HANDLE_STORE).get(HANDLE_KEY);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
      });
    } catch {
      return null;
    }
  }

  async function saveStoredFileHandle(handle) {
    try {
      const db = await openHandleDB();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(HANDLE_STORE, "readwrite");
        tx.objectStore(HANDLE_STORE).put(handle, HANDLE_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch {
      /* non-fatal: handle persistence is a nice-to-have */
    }
  }

  async function clearStoredFileHandle() {
    try {
      const db = await openHandleDB();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(HANDLE_STORE, "readwrite");
        tx.objectStore(HANDLE_STORE).delete(HANDLE_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch {}
  }

  function setKeyFileError(msg) {
    if (!msg) {
      els.connectionError.classList.add("hidden");
      els.connectionError.textContent = "";
      return;
    }
    els.connectionError.textContent = msg;
    els.connectionError.classList.remove("hidden");
  }

  function applyLoadedKey(text) {
    els.inputPrivateKey.value = (text || "").trim();
    els.inputPrivateKey.classList.remove("masked");
    els.togglePwBtn.textContent = "Hide";
  }

  function updateKeyFileButton(filename) {
    if (!els.loadKeyFileBtn) return;
    if (filename) {
      els.loadKeyFileBtn.textContent = "Reload " + filename;
      els.loadKeyFileBtn.title =
        "Reload from the previously-picked " + filename +
        " (shift-click to choose a different file)";
      els.loadKeyFileBtn.dataset.filename = filename;
    } else {
      els.loadKeyFileBtn.textContent = "Load from file…";
      els.loadKeyFileBtn.title =
        "Load key from a local file (e.g. ~/.remote-signer/apikeys/agent.key.priv)";
      delete els.loadKeyFileBtn.dataset.filename;
    }
  }

  async function readFromHandle(handle) {
    let perm = await handle.queryPermission({ mode: "read" });
    if (perm !== "granted") {
      perm = await handle.requestPermission({ mode: "read" });
    }
    if (perm !== "granted") {
      throw new Error("Permission denied");
    }
    const file = await handle.getFile();
    return file.text();
  }

  async function pickFileWithFSA(startInHandle) {
    const opts = {
      multiple: false,
      types: [
        {
          description: "Remote-Signer API key",
          accept: { "text/plain": [".priv", ".pem", ".key", ".txt"] },
        },
      ],
    };
    if (startInHandle) opts.startIn = startInHandle;
    const [handle] = await window.showOpenFilePicker(opts);
    return handle;
  }

  async function loadKeyFromHandle(handle, source) {
    try {
      const text = await readFromHandle(handle);
      applyLoadedKey(text);
      setKeyFileError("");
      updateKeyFileButton(handle.name);
      if (source === "picker") await saveStoredFileHandle(handle);
    } catch (err) {
      // Stored handle may have been invalidated (file moved/deleted, or
      // user-revoked permission). Drop it and fall back to a fresh pick.
      if (source === "stored") {
        await clearStoredFileHandle();
        updateKeyFileButton(null);
      }
      setKeyFileError("Failed to read file: " + (err && err.message ? err.message : String(err)));
    }
  }

  function setupKeyFileLoader() {
    if (!els.loadKeyFileBtn) return;
    const hasFSA = typeof window.showOpenFilePicker === "function";

    // Pre-warm the button label with whichever filename was last used so
    // returning users see "Reload agent.key.priv" immediately.
    let storedHandle = null;
    if (hasFSA) {
      loadStoredFileHandle().then((h) => {
        if (h && typeof h.name === "string") {
          storedHandle = h;
          updateKeyFileButton(h.name);
        }
      });
    }

    els.loadKeyFileBtn.addEventListener("click", async (event) => {
      setKeyFileError("");
      // Modern path: prefer the persisted handle for zero-friction reload.
      if (hasFSA && storedHandle && !event.shiftKey) {
        await loadKeyFromHandle(storedHandle, "stored");
        return;
      }
      if (hasFSA) {
        try {
          const handle = await pickFileWithFSA(storedHandle);
          storedHandle = handle;
          await loadKeyFromHandle(handle, "picker");
        } catch (err) {
          // AbortError = user closed dialog; not an error worth surfacing.
          if (err && err.name !== "AbortError") {
            setKeyFileError("Failed to open file: " + (err.message || String(err)));
          }
        }
        return;
      }
      // Legacy fallback (Firefox/Safari etc.): trigger the <input type=file>.
      els.keyFileInput.click();
    });

    // Legacy fallback's change handler. Also used when the user is on a
    // Chromium build that's missing showOpenFilePicker for some reason.
    if (els.keyFileInput) {
      els.keyFileInput.addEventListener("change", async () => {
        const file = els.keyFileInput.files && els.keyFileInput.files[0];
        if (!file) return;
        try {
          const text = await file.text();
          applyLoadedKey(text);
          setKeyFileError("");
          updateKeyFileButton(file.name);
        } catch (err) {
          setKeyFileError("Failed to read file: " + (err && err.message ? err.message : String(err)));
        } finally {
          els.keyFileInput.value = "";
        }
      });
    }

    // Drag-and-drop onto the textarea reads the dropped file as a key.
    const dropTarget = els.inputPrivateKey;
    dropTarget.addEventListener("dragover", (e) => {
      if (e.dataTransfer && Array.from(e.dataTransfer.items).some((it) => it.kind === "file")) {
        e.preventDefault();
        dropTarget.classList.add("drop-target");
      }
    });
    dropTarget.addEventListener("dragleave", () => dropTarget.classList.remove("drop-target"));
    dropTarget.addEventListener("drop", async (e) => {
      dropTarget.classList.remove("drop-target");
      const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (!file) return;
      e.preventDefault();
      try {
        const text = await file.text();
        applyLoadedKey(text);
        setKeyFileError("");
        updateKeyFileButton(file.name);
      } catch (err) {
        setKeyFileError("Failed to read dropped file: " + (err && err.message ? err.message : String(err)));
      }
    });
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
      autoApproveConnections: els.inputAutoApprove ? els.inputAutoApprove.checked : true,
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
      autoApproveConnections: els.inputAutoApprove ? els.inputAutoApprove.checked : true,
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
      // Just navigate views — don't re-fetch state (which would wipe
      // unsaved edits to the settings form). lastMainView holds the most
      // recent main view rendered by initPopup; if it's empty (no init
      // ran yet) we full-init so the popup doesn't strand on settings.
      if (!lastMainView) {
        showView("loading");
        initPopup();
      } else {
        showView(lastMainView);
      }
    });

    // Settings — private key is a textarea (so PEM fits); use CSS masking
    // instead of input[type=password] which has no equivalent on textarea.
    els.inputPrivateKey.classList.add("masked");
    els.togglePwBtn.textContent = "Show";
    els.togglePwBtn.addEventListener("click", () => {
      const masked = els.inputPrivateKey.classList.toggle("masked");
      els.togglePwBtn.textContent = masked ? "Show" : "Hide";
    });

    // "Load from file…" — three input paths:
    //
    //   1. File System Access API (Chromium): showOpenFilePicker returns a
    //      FileSystemFileHandle which we persist in IndexedDB. On subsequent
    //      popup opens the button switches to "Reload from <filename>" — one
    //      click re-reads the same file with no dialog, sidestepping the
    //      "navigate to ~/.remote-signer/apikeys/ every time" friction.
    //      Browsers won't let extensions set a custom starting path, so the
    //      persisted handle is the closest we can get.
    //
    //   2. Drag-and-drop onto the textarea: handy when the apikeys folder
    //      is already open in Finder.
    //
    //   3. Legacy <input type=file> fallback: for browsers without FSA API
    //      and as the click target when showOpenFilePicker rejects.
    setupKeyFileLoader();

    els.testConnectionBtn.addEventListener("click", testConnection);
    els.saveConfigBtn.addEventListener("click", saveConfig);

    if (els.signerBannerAction) {
      els.signerBannerAction.addEventListener("click", () => {
        send({ type: "popup:openManagement" });
      });
    }

    // Tabs
    if (els.tabAccountsBtn && els.tabActivityBtn) {
      els.tabAccountsBtn.addEventListener("click", () => selectTab("accounts"));
      els.tabActivityBtn.addEventListener("click", () => selectTab("activity"));
    }
    if (els.activityRefreshBtn) {
      els.activityRefreshBtn.addEventListener("click", () => {
        activityLoaded = false;
        loadActivity();
      });
    }
    if (els.drawerCloseBtn) {
      els.drawerCloseBtn.addEventListener("click", closeRequestDrawer);
    }

    // Header chips
    if (els.appbarChainBtn) {
      els.appbarChainBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        buildChainDropdown();
        openDropdown(els.chainDropdown);
      });
    }
    if (els.appbarSignerBtn) {
      els.appbarSignerBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        buildSignerDropdown();
        openDropdown(els.signerDropdown);
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
