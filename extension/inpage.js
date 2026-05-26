(() => {
  // src/inpage-proxy.ts
  function uuidv4() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === "x" ? r : r & 3 | 8;
      return v.toString(16);
    });
  }
  // Inline logger mirroring extension/src/logger.ts. inpage runs in
  // MAIN world (the dApp's page context) — no chrome.* access, so the
  // level lookup goes through a window-bridged value that content-script
  // pushes via postMessage when it changes. Default is "info" so the
  // page console always shows method dispatch and any error.
  const LOG_LEVEL_RANK_INPAGE = { debug: 0, info: 1, warn: 2, error: 3 };
  let __inpageLogLevel = "info";
  window.addEventListener("message", (event) => {
    const d = event.data;
    if (d && d.type === "remote-signer:log-level" && typeof d.level === "string"
        && d.level in LOG_LEVEL_RANK_INPAGE) {
      __inpageLogLevel = d.level;
    }
  });
  function ipLog(level, msg, fields) {
    if (LOG_LEVEL_RANK_INPAGE[level] < LOG_LEVEL_RANK_INPAGE[__inpageLogLevel]) return;
    const d = new Date();
    const pad = (n, w = 2) => n.toString().padStart(w, "0");
    const ts = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" +
      pad(d.getSeconds()) + "." + pad(d.getMilliseconds(), 3);
    const prefix = `[${ts}] [${level}] [inpage] ${msg}`;
    const fn = level === "error" ? console.error
      : level === "warn" ? console.warn : console.log;
    if (fields && Object.keys(fields).length > 0) fn(prefix, fields);
    else fn(prefix);
  }
  if (window.__web3AgentBrowserInjected) {
    ipLog("info", "already injected, skipping");
  } else {
    let emitEvent = function(event, ...args) {
      const handlers = eventListeners.get(event);
      if (handlers) {
        for (const handler of handlers) {
          try {
            handler(...args);
          } catch (e) {
            ipLog("error", "event handler threw", { event, error: e?.message || String(e) });
          }
        }
      }
    }, sendRequest = function(method, params) {
      return new Promise((resolve, reject) => {
        const id = uuidv4();
        ipLog("info", "→ content-script", {
          method,
          id,
          paramsLen: Array.isArray(params) ? params.length : 0
        });
        pendingRequests.set(id, { resolve, reject });
        window.postMessage(
          {
            type: "web3-eip1193-request",
            id,
            method,
            params
          },
          "*"
        );
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            ipLog("warn", "request timed out", { method, id });
            reject(new Error(`Request timed out: ${method}`));
          }
        }, 3e5);
      });
    }, getState = function() {
      return new Promise((resolve, reject) => {
        const id = uuidv4();
        pendingRequests.set(id, { resolve, reject });
        window.postMessage({ type: "web3-get-state", id }, "*");
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            reject(new Error("State sync timed out"));
          }
        }, 1e4);
      });
    };
    window.__web3AgentBrowserInjected = true;
    const pendingRequests = /* @__PURE__ */ new Map();
    const eventListeners = /* @__PURE__ */ new Map();
    let _accounts = [];
    let _chainId = "0x1";
    let _isConnected = false;
    window.addEventListener("message", (event) => {
      const data = event.data;
      if (!data || typeof data !== "object") return;
      if (data.type === "web3-eip1193-response" && data.id) {
        const pending = pendingRequests.get(data.id);
        if (pending) {
          pendingRequests.delete(data.id);
          if (data.error) {
            ipLog("error", "← extension error", {
              id: data.id,
              code: data.error.code,
              message: data.error.message,
            });
            const err = new Error(data.error.message || "Unknown error");
            err.code = data.error.code || -32603;
            err.data = data.error.data;
            pending.reject(err);
          } else {
            ipLog("debug", "← extension ok", { id: data.id });
            pending.resolve(data.result);
          }
        }
      }
      if (data.type === "web3-state-response" && data.id) {
        const pending = pendingRequests.get(data.id);
        if (pending) {
          pendingRequests.delete(data.id);
          pending.resolve(data);
        }
      }
      if (data.type === "web3-eip1193-event") {
        const { event: eventName, data: eventData } = data;
        if (eventName === "accountsChanged") {
          _accounts = eventData;
          emitEvent("accountsChanged", _accounts);
        } else if (eventName === "chainChanged") {
          _chainId = eventData;
          emitEvent("chainChanged", _chainId);
        } else if (eventName === "connect") {
          _isConnected = true;
          emitEvent("connect", eventData);
        } else if (eventName === "disconnect") {
          _isConnected = false;
          _accounts = [];
          emitEvent("disconnect", eventData);
        }
      }
    });
    const provider = {
      // EIP-1193 required method
      async request(args) {
        const result = await sendRequest(args.method, args.params);
        if (args.method === "eth_requestAccounts" || args.method === "eth_accounts") {
          if (Array.isArray(result)) {
            const prev = _accounts;
            _accounts = result;
            // EIP-1193 `connect` event semantics: emit on the first
            // successful state-establishing call from this dApp. The SW
            // already fired `connect` once during provider-create, but no
            // dApp listener was attached yet, so we synthesise it here.
            if (result.length > 0 && !_isConnected) {
              _isConnected = true;
              emitEvent("connect", { chainId: _chainId });
            }
            // Same for accountsChanged on first/changed accounts so
            // dApp listeners reliably hear it.
            if (
              args.method === "eth_requestAccounts" ||
              prev.length !== result.length ||
              prev.some((a, i) => a !== result[i])
            ) {
              emitEvent("accountsChanged", _accounts);
            }
          }
        }
        if (args.method === "eth_chainId" && typeof result === "string") {
          _chainId = result;
        }
        return result;
      },
      // Event methods
      on(event, handler) {
        if (!eventListeners.has(event)) {
          eventListeners.set(event, /* @__PURE__ */ new Set());
        }
        eventListeners.get(event).add(handler);
        // Connect-event timing: the SW emits `connect` exactly once at
        // provider-create time, and the initial state-sync (getState)
        // sets _isConnected=true even before any dApp listener attaches.
        // dApps that subscribe later would never see a connect event.
        // Fire one now, on the next microtask, so late-attached
        // listeners see the current state — matches MetaMask's
        // synthesised replay behaviour.
        if (event === "connect" && _isConnected) {
          queueMicrotask(() => {
            try {
              handler({ chainId: _chainId });
            } catch (e) {
              ipLog("error", "connect handler threw", { error: e?.message || String(e) });
            }
          });
        }
        return provider;
      },
      removeListener(event, handler) {
        eventListeners.get(event)?.delete(handler);
        return provider;
      },
      // Alias
      off(event, handler) {
        return provider.removeListener(event, handler);
      },
      addListener(event, handler) {
        return provider.on(event, handler);
      },
      // EIP-1193 properties
      get selectedAddress() {
        return _accounts[0] || null;
      },
      get chainId() {
        return _chainId;
      },
      get isMetaMask() {
        return false;
      },
      isConnected() {
        return _isConnected;
      },
      // Legacy send method (some dApps use this)
      send(methodOrPayload, paramsOrCallback) {
        if (typeof methodOrPayload === "string") {
          return provider.request({
            method: methodOrPayload,
            params: paramsOrCallback
          });
        }
        if (typeof paramsOrCallback === "function") {
          provider.request({
            method: methodOrPayload.method,
            params: methodOrPayload.params
          }).then((result) => paramsOrCallback(null, { id: methodOrPayload.id, jsonrpc: "2.0", result })).catch((err) => paramsOrCallback(err));
          return;
        }
        return provider.request({
          method: methodOrPayload.method,
          params: methodOrPayload.params
        });
      },
      // Legacy sendAsync method
      sendAsync(payload, callback) {
        provider.request({ method: payload.method, params: payload.params }).then((result) => callback(null, { id: payload.id, jsonrpc: "2.0", result })).catch((err) => callback(err));
      },
      // EIP-1193 enable (deprecated but some dApps use it)
      async enable() {
        return await provider.request({ method: "eth_requestAccounts" });
      },
      // Switch active account by address or index (non-EIP-1193 extension)
      async switchAccount(addressOrIndex) {
        return new Promise((resolve, reject) => {
          const id = uuidv4();
          const timer = setTimeout(() => {
            cleanup();
            reject(new Error("switchAccount timed out"));
          }, 15000);
          function handleResponse(event2) {
            const d = event2.data;
            if (!d || d.type !== "popup:accountSwitched" || d.id !== id) return;
            cleanup();
            if (d.ok === false) {
              reject(new Error(d.error || "switchAccount failed"));
            } else {
              resolve(d);
            }
          }
          function cleanup() {
            clearTimeout(timer);
            window.removeEventListener("message", handleResponse);
          }
          window.addEventListener("message", handleResponse);
          window.postMessage(
            { type: "popup:switchAccount", id, address: addressOrIndex },
            "*"
          );
        });
      }
    };
    Object.defineProperty(window, "ethereum", {
      value: provider,
      writable: false,
      configurable: false
    });
    try {
      Object.defineProperty(navigator, "webdriver", {
        get: () => false,
        configurable: true
      });
    } catch {
    }
    if (!window.chrome || !window.chrome.runtime) {
      window.chrome = window.chrome || {};
      window.chrome.runtime = {
        onConnect: { addListener() {
        }, removeListener() {
        } },
        sendMessage() {
        },
        connect() {
          return { onMessage: { addListener() {
          } }, postMessage() {
          } };
        }
      };
    }
    if (!window.chrome.loadTimes) {
      window.chrome.loadTimes = function() {
        return {
          requestTime: Date.now() / 1e3 - Math.random() * 100,
          startLoadTime: Date.now() / 1e3 - Math.random() * 50,
          commitLoadTime: Date.now() / 1e3 - Math.random() * 30,
          finishDocumentLoadTime: Date.now() / 1e3 - Math.random() * 20,
          finishLoadTime: Date.now() / 1e3 - Math.random() * 10,
          firstPaintTime: Date.now() / 1e3 - Math.random() * 5,
          firstPaintAfterLoadTime: 0,
          navigationType: "Other",
          wasFetchedViaSpdy: false,
          wasNpnNegotiated: true,
          npnNegotiatedProtocol: "h2",
          wasAlternateProtocolAvailable: false,
          connectionInfo: "h2"
        };
      };
    }
    try {
      Object.defineProperty(navigator, "plugins", {
        get: function() {
          const plugins = [
            {
              name: "Chrome PDF Plugin",
              filename: "internal-pdf-viewer",
              description: "Portable Document Format"
            },
            {
              name: "Chrome PDF Viewer",
              filename: "mhjfbmdgcfjbbpaeojofohoefgiehjai",
              description: "Portable Document Format"
            },
            {
              name: "Native Client",
              filename: "internal-nacl-plugin",
              description: "Native Client Executable"
            }
          ];
          plugins.item = function(i) {
            return this[i] || null;
          };
          plugins.namedItem = function(name) {
            return this.find((p) => p.name === name) || null;
          };
          plugins.refresh = function() {
          };
          return plugins;
        },
        configurable: true
      });
    } catch {
    }
    try {
      Object.defineProperty(navigator, "languages", {
        get: () => ["en-US", "en"],
        configurable: true
      });
    } catch {
    }
    const providerDetail = Object.freeze({
      info: Object.freeze({
        uuid: uuidv4(),
        name: "Remote Signer",
        icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96' viewBox='0 0 96 96'%3E%3Crect width='96' height='96' rx='16' fill='%23627EEA'/%3E%3Ctext x='48' y='66' font-size='48' fill='white' text-anchor='middle' font-family='sans-serif' font-weight='bold'%3ER%3C/text%3E%3C/svg%3E",
        rdns: "xyz.web3gate.agent-browser"
      }),
      provider
    });
    window.dispatchEvent(new Event("ethereum#initialized"));
    window.dispatchEvent(
      new CustomEvent("eip6963:announceProvider", { detail: providerDetail })
    );
    window.addEventListener("eip6963:requestProvider", () => {
      window.dispatchEvent(
        new CustomEvent("eip6963:announceProvider", { detail: providerDetail })
      );
    });
    ipLog("info", "provider injected + EIP-6963 announced");
    getState().then((state) => {
      _accounts = state.accounts || [];
      _chainId = state.chainId || "0x1";
      _isConnected = state.isConnected || false;
      ipLog("info", "initial state synced", {
        accounts: _accounts.length,
        chainId: _chainId,
        isConnected: _isConnected
      });
    }).catch((err) => {
      ipLog("warn", "initial state sync failed", { message: err?.message || String(err) });
    });
  }
})();
//# sourceMappingURL=inpage.js.map
