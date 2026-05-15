(() => {
  // src/inpage-proxy.ts
  function uuidv4() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === "x" ? r : r & 3 | 8;
      return v.toString(16);
    });
  }
  if (window.__web3AgentBrowserInjected) {
    console.log("[Web3 Agent Browser] Already injected, skipping");
  } else {
    let emitEvent = function(event, ...args) {
      const handlers = eventListeners.get(event);
      if (handlers) {
        for (const handler of handlers) {
          try {
            handler(...args);
          } catch (e) {
            console.error(`[Web3 Agent Browser] Event handler error (${event}):`, e);
          }
        }
      }
    }, sendRequest = function(method, params) {
      return new Promise((resolve, reject) => {
        const id = uuidv4();
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
            const err = new Error(data.error.message || "Unknown error");
            err.code = data.error.code || -32603;
            err.data = data.error.data;
            pending.reject(err);
          } else {
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
            _accounts = result;
            if (result.length > 0) _isConnected = true;
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
    console.log("[Web3 Agent Browser] Provider proxy injected and announced via EIP-6963");
    getState().then((state) => {
      _accounts = state.accounts || [];
      _chainId = state.chainId || "0x1";
      _isConnected = state.isConnected || false;
      console.log("[Web3 Agent Browser] State synced from background:", {
        accounts: _accounts.length,
        chainId: _chainId,
        isConnected: _isConnected
      });
    }).catch((err) => {
      console.warn("[Web3 Agent Browser] Initial state sync failed:", err.message);
    });
  }
})();
//# sourceMappingURL=inpage.js.map
