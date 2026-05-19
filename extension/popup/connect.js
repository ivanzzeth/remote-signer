/**
 * Connect popup — opened by chrome.windows.create() from the service
 * worker when a dApp's eth_requestAccounts / wallet_requestPermissions
 * lands on an origin we haven't permitted yet. Lets the user pick
 * which chain to expose to the dApp (MetaMask 12+ equivalent UX) and
 * grants/denies the connection.
 *
 * URL params:
 *   - requestId        the pending-connect handle the SW is waiting on
 *   - origin           the dApp's origin (display only)
 *   - suggestedChainId decimal chain id pre-selected in the chain dropdown
 */
(function () {
  "use strict";

  const params = new URLSearchParams(window.location.search);
  const requestId = params.get("requestId") || "";
  const origin = params.get("origin") || "";

  const $ = (id) => document.getElementById(id);
  const els = {
    originText: $("originText"),
    signerList: $("signerList"),
    chainSelect: $("chainSelect"),
    connectBtn: $("connectBtn"),
    cancelBtn: $("cancelBtn"),
    error: $("connectError"),
  };

  els.originText.textContent = origin || "—";

  function setError(msg) {
    if (!msg) {
      els.error.classList.add("hidden");
      els.error.textContent = "";
      return;
    }
    els.error.textContent = msg;
    els.error.classList.remove("hidden");
  }

  // Context fetch: signers usable on this wallet + chains the user has
  // registered. We populate the account list (single-select via radio
  // for now — multi-select can come later when the UI supports it) and
  // the chain dropdown.
  function loadContext() {
    chrome.runtime.sendMessage({ type: "connect:getContext", requestId }, (resp) => {
      if (!resp || !resp.ok) {
        setError(resp?.error || "Failed to load context");
        return;
      }
      // Signers
      els.signerList.innerHTML = "";
      const signers = Array.isArray(resp.signers) ? resp.signers : [];
      if (signers.length === 0) {
        const empty = document.createElement("div");
        empty.className = "signer-empty";
        empty.textContent = "No usable signers — open Settings first.";
        els.signerList.appendChild(empty);
      } else {
        signers.forEach((s, idx) => {
          const row = document.createElement("label");
          row.className = "signer-item";
          if (s.locked || !s.enabled) row.classList.add("disabled");
          const input = document.createElement("input");
          input.type = "checkbox";
          input.value = s.address;
          input.checked = idx === 0; // pre-check the active signer
          input.disabled = !!s.locked || s.enabled === false;
          input.addEventListener("change", recomputeConnectButton);
          const label = document.createElement("span");
          label.textContent = s.address;
          row.appendChild(input);
          row.appendChild(label);
          els.signerList.appendChild(row);
        });
      }
      // Chains
      els.chainSelect.innerHTML = "";
      const chains = Array.isArray(resp.chains) ? resp.chains : [];
      const suggested = parseInt(params.get("suggestedChainId") || String(resp.suggestedChainId || 1), 10);
      chains
        .sort((a, b) => a.chainId - b.chainId)
        .forEach((c) => {
          const opt = document.createElement("option");
          opt.value = String(c.chainId);
          opt.textContent = `${c.chainName || "Chain"} (${c.chainId})`;
          if (c.chainId === suggested) opt.selected = true;
          els.chainSelect.appendChild(opt);
        });
      recomputeConnectButton();
    });
  }

  function selectedAccounts() {
    return Array.from(els.signerList.querySelectorAll("input[type=checkbox]:checked")).map(
      (el) => el.value
    );
  }

  function recomputeConnectButton() {
    const accounts = selectedAccounts();
    const chainOk = !!els.chainSelect.value;
    els.connectBtn.disabled = !(accounts.length > 0 && chainOk);
  }

  els.connectBtn.addEventListener("click", () => {
    const accounts = selectedAccounts();
    const chainId = parseInt(els.chainSelect.value, 10);
    if (!accounts.length || !Number.isFinite(chainId)) return;
    els.connectBtn.disabled = true;
    els.connectBtn.textContent = "Connecting…";
    chrome.runtime.sendMessage(
      { type: "connect:approve", requestId, accounts, chainId },
      (resp) => {
        if (!resp || !resp.ok) {
          setError(resp?.error || "Failed to approve");
          els.connectBtn.disabled = false;
          els.connectBtn.textContent = "Connect";
          return;
        }
        window.close();
      }
    );
  });

  els.cancelBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "connect:reject", requestId }, () => {
      window.close();
    });
  });

  // The SW also rejects automatically when the window is closed — but
  // a beforeunload tells it explicitly so the dApp's RPC promise
  // settles right away instead of waiting for chrome.windows.onRemoved.
  window.addEventListener("beforeunload", () => {
    if (!els.connectBtn.disabled) {
      // Only reject if the user hasn't already clicked Connect (which
      // sets disabled=true). Otherwise the SW already moved on.
      try {
        chrome.runtime.sendMessage({ type: "connect:reject", requestId });
      } catch {}
    }
  });

  loadContext();
})();
