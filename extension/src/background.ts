/**
 * Background service worker for Remote Signer browser extension.
 *
 * Built by esbuild into extension/background.js.
 * Handles EIP-1193 requests from content-script, popup IPC,
 * and direct HTTP communication with remote-signer (no proxy).
 *
 * Config is stored in chrome.storage.local and managed through the popup.
 */
import {
  RemoteSignerClient,
  EIP1193Provider,
  RemoteSigner,
} from "remote-signer-client";

// ── Types ────────────────────────────────────────────────────────────────

interface StoredConfig {
  remoteSignerUrl: string;
  apiKeyId: string;
  apiKeyPrivateKey: string;
  selectedChain: number;
}

interface EIP1193Request {
  type: "web3-eip1193-request";
  id: string;
  method: string;
  params?: unknown[];
}

interface StateRequest {
  type: "web3-get-state";
  id: string;
}

interface PopupGetConfig {
  type: "popup:getConfig";
}

interface PopupSaveConfig {
  type: "popup:saveConfig";
  config: StoredConfig;
}

interface PopupTestConnection {
  type: "popup:testConnection";
}

interface PopupGetState {
  type: "popup:getState";
}

interface PopupGetDashboard {
  type: "popup:getDashboard";
}

interface PopupOpenManagement {
  type: "popup:openManagement";
}

type PopupMessage =
  | PopupGetConfig
  | PopupSaveConfig
  | PopupTestConnection
  | PopupGetState
  | PopupGetDashboard
  | PopupOpenManagement;

type IncomingMessage = EIP1193Request | StateRequest | PopupMessage;

// ── Defaults ─────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: StoredConfig = {
  remoteSignerUrl: "http://127.0.0.1:8548",
  apiKeyId: "",
  apiKeyPrivateKey: "",
  selectedChain: 1,
};

// ── Globals ──────────────────────────────────────────────────────────────

declare const self: ServiceWorkerGlobalScope;

let provider: EIP1193Provider | null = null;
let client: RemoteSignerClient | null = null;
let initPromise: Promise<void> | null = null;
let initError: string | null = null;
let cachedConfig: StoredConfig = { ...DEFAULT_CONFIG };

// ── Config ───────────────────────────────────────────────────────────────

function configKey(): string {
  return `remoteSignerConfig`;
}

async function loadConfig(): Promise<StoredConfig> {
  const result = await chrome.storage.local.get(configKey());
  if (result[configKey()]) {
    cachedConfig = result[configKey()];
  }
  return cachedConfig;
}

async function saveConfig(cfg: StoredConfig): Promise<void> {
  cachedConfig = cfg;
  await chrome.storage.local.set({ [configKey()]: cfg });
}

// ── Dynamic content-script registration ──────────────────────────────────

async function registerContentScript() {
  try {
    await chrome.scripting
      .unregisterContentScripts({ ids: ["remote-signer-cs"] })
      .catch(() => {});
    await chrome.scripting.registerContentScripts([
      {
        id: "remote-signer-cs",
        matches: ["http://*/*", "https://*/*"],
        js: ["content-script.js"],
        runAt: "document_start",
        allFrames: false,
        world: "ISOLATED" as any,
      },
    ]);
  } catch (e) {
    console.error("[background] Failed to register content script:", e);
  }
}

chrome.runtime.onInstalled.addListener(() => registerContentScript());
chrome.runtime.onStartup.addListener(() => registerContentScript());
registerContentScript();

// ── CSP meta tag bypass ──────────────────────────────────────────────────

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId: details.tabId },
      world: "MAIN",
      injectImmediately: true,
      func: () => {
        const removeCSP = () => {
          document
            .querySelectorAll('meta[http-equiv="Content-Security-Policy"]')
            .forEach((el) => {
              console.log(
                "[CSP bypass] Removing meta CSP:",
                el.getAttribute("content")?.substring(0, 80)
              );
              el.remove();
            });
          document
            .querySelectorAll(
              'meta[http-equiv="Content-Security-Policy-Report-Only"]'
            )
            .forEach((el) => el.remove());
        };
        removeCSP();
        const observer = new MutationObserver((mutations) => {
          for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
              if (node.nodeName === "META") {
                const httpEquiv = (node as Element).getAttribute("http-equiv");
                if (
                  httpEquiv &&
                  httpEquiv.toLowerCase().includes("content-security-policy")
                ) {
                  console.log(
                    "[CSP bypass] Intercepted meta CSP:",
                    (node as Element)
                      .getAttribute("content")
                      ?.substring(0, 80)
                  );
                  (node as Element).remove();
                }
              }
            }
          }
        });
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true,
        });
        setTimeout(() => observer.disconnect(), 30000);
      },
    });
  } catch (e: any) {
    if (!e.message?.includes("Cannot access")) {
      console.error("[background] CSP bypass injection failed:", e);
    }
  }
});

// ── Provider Initialization ──────────────────────────────────────────────

async function initProvider(): Promise<void> {
  const cfg = await loadConfig();

  if (!cfg.apiKeyPrivateKey) {
    initError =
      "API key not configured. Open extension popup to configure.";
    console.warn("[background]", initError);
    return;
  }

  if (!cfg.apiKeyId) {
    initError =
      "API key ID not configured. Open extension popup to configure.";
    console.warn("[background]", initError);
    return;
  }

  console.log("[background] Initializing provider...", {
    remoteSignerUrl: cfg.remoteSignerUrl,
    apiKeyId: cfg.apiKeyId,
    chainId: cfg.selectedChain,
  });

  client = new RemoteSignerClient({
    baseURL: cfg.remoteSignerUrl,
    apiKeyID: cfg.apiKeyId,
    privateKey: cfg.apiKeyPrivateKey,
    httpClient: {
      fetch: fetch.bind(self),
    },
  });

  // Auto-fetch signers from backend
  provider = await EIP1193Provider.create({
    signersSource: { type: "client", client, chainId: cfg.selectedChain },
    defaultChainId: cfg.selectedChain,
    rpcOverrides: {},
    rpcResolver: undefined,
  });

  console.log("[background] Provider created successfully");
  console.log("  - Connected:", provider.isConnected());
  console.log("  - Active account:", provider.selectedAddress);
  console.log("  - Chain ID:", provider.chainId);

  // Forward provider events to all tabs
  const events = ["accountsChanged", "chainChanged", "connect", "disconnect"];
  for (const event of events) {
    provider.on(event, (data: unknown) => {
      broadcastEvent(event, data);
    });
  }
}

function ensureInit(): Promise<void> {
  if (!initPromise) {
    initPromise = initProvider().catch((err) => {
      initError = err.message || String(err);
      console.error("[background] Provider init failed:", err);
    });
  }
  return initPromise;
}

// ── Event Broadcasting ───────────────────────────────────────────────────

async function broadcastEvent(event: string, data: unknown) {
  try {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab.id != null) {
        chrome.tabs
          .sendMessage(tab.id, {
            type: "web3-eip1193-event",
            event,
            data,
          })
          .catch(() => {});
      }
    }
  } catch {}
}

// ── EIP-1193 Handler ─────────────────────────────────────────────────────

async function handleEIP1193Request(msg: EIP1193Request) {
  await ensureInit();

  if (initError) {
    return {
      type: "web3-eip1193-response",
      id: msg.id,
      error: { code: -32603, message: `Provider init failed: ${initError}` },
    };
  }

  if (!provider) {
    return {
      type: "web3-eip1193-response",
      id: msg.id,
      error: { code: -32603, message: "Provider not initialized" },
    };
  }

  try {
    const result = await provider.request({
      method: msg.method,
      params: msg.params,
    });
    return {
      type: "web3-eip1193-response",
      id: msg.id,
      result,
    };
  } catch (err: any) {
    return {
      type: "web3-eip1193-response",
      id: msg.id,
      error: {
        code: err.code || -32603,
        message: err.message || String(err),
        data: err.data,
      },
    };
  }
}

async function handleGetState(id: string) {
  await ensureInit();

  if (!provider) {
    return {
      type: "web3-state-response",
      id,
      accounts: [],
      chainId: "0x1",
      isConnected: false,
    };
  }

  let accounts: string[] = [];
  try {
    accounts = (await provider.request({
      method: "eth_accounts",
    })) as string[];
  } catch {}

  return {
    type: "web3-state-response",
    id,
    accounts,
    chainId: provider.chainId,
    isConnected: provider.isConnected(),
  };
}

// ── Popup Handlers ───────────────────────────────────────────────────────

async function handlePopupGetConfig() {
  const cfg = await loadConfig();
  return {
    type: "popup:config",
    config: cfg,
  };
}

async function handlePopupSaveConfig(msg: PopupSaveConfig) {
  await saveConfig(msg.config);
  // Reset provider so it re-initializes with new config
  initPromise = null;
  initError = null;
  provider = null;
  client = null;
  return {
    type: "popup:configSaved",
    ok: true,
  };
}

async function makeSignedRequest(
  urlPath: string,
  method: string,
  body?: unknown
): Promise<{ status: number; body: unknown }> {
  const cfg = cachedConfig;
  if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
    throw new Error("API key not configured");
  }

  // Build Ed25519-signed headers using SubtleCrypto
  const timestamp = Date.now().toString();
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const bodyStr = body ? JSON.stringify(body) : "";
  const bodyHash = await sha256(bodyStr);
  const signMessage = `${timestamp}|${nonce}|${method}|${urlPath}|${bodyHash}`;

  const signature = await ed25519Sign(
    hexToBytes(cfg.apiKeyPrivateKey),
    new TextEncoder().encode(signMessage)
  );

  const headers: Record<string, string> = {
    "X-API-Key-ID": cfg.apiKeyId,
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
    "X-Signature": bytesToBase64(signature),
    "Content-Type": "application/json",
  };

  const url = cfg.remoteSignerUrl.replace(/\/$/, "") + urlPath;
  const fetchOptions: RequestInit = {
    method,
    headers,
  };
  if (body && method !== "GET") {
    fetchOptions.body = bodyStr;
  }

  const res = await fetch(url, fetchOptions);
  const data = res.headers
    .get("content-type")
    ?.includes("application/json")
    ? await res.json()
    : await res.text();

  return { status: res.status, body: data };
}

async function handlePopupTestConnection() {
  const cfg = cachedConfig;
  if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
    return {
      type: "popup:connectionResult",
      ok: false,
      error: "API key not configured",
    };
  }

  try {
    // Test /health (no auth needed)
    const healthUrl = cfg.remoteSignerUrl.replace(/\/$/, "") + "/health";
    const healthRes = await fetch(healthUrl);
    const healthData = await healthRes.json();
    const serverVersion = healthData?.version || "unknown";

    // Test /api/v1/evm/signers (auth required)
    const { status } = await makeSignedRequest(
      "/api/v1/evm/signers",
      "GET"
    );

    if (status === 200) {
      return {
        type: "popup:connectionResult",
        ok: true,
        version: serverVersion,
        url: cfg.remoteSignerUrl,
      };
    } else {
      return {
        type: "popup:connectionResult",
        ok: false,
        error: `Auth failed (HTTP ${status})`,
      };
    }
  } catch (err: any) {
    return {
      type: "popup:connectionResult",
      ok: false,
      error: err.message || String(err),
    };
  }
}

async function handlePopupGetState() {
  let connected = false;
  let accounts: string[] = [];
  let chainId = "0x1";
  try {
    await ensureInit();
    if (provider && !initError) {
      connected = provider.isConnected();
      accounts = (await provider.request({
        method: "eth_accounts",
      })) as string[];
      chainId = provider.chainId;
    }
  } catch {}

  return {
    type: "popup:state",
    connected,
    accounts,
    chainId,
  };
}

async function safeApiCall(urlPath: string): Promise<{ ok: boolean; data?: any; error?: string }> {
  try {
    const { status, body } = await makeSignedRequest(urlPath, "GET");
    return { ok: status === 200, data: body };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
}

async function handlePopupGetDashboard() {
  const cfg = cachedConfig;
  if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
    return {
      type: "popup:dashboard",
      signers: [],
      signerCount: 0,
      ruleCount: 0,
      requestCount: 0,
      apiKeyRole: "unknown",
    };
  }

  // Fetch all data in parallel
  const [signersResult, rulesResult, requestsResult, apikeysResult] =
    await Promise.all([
      safeApiCall("/api/v1/evm/signers"),
      safeApiCall("/api/v1/rules?limit=1"),
      safeApiCall("/api/v1/requests?limit=100"),
      safeApiCall("/api/v1/apikeys"),
    ]);

  // Determine role: if /api/v1/apikeys returns 200, role is "admin"
  let apiKeyRole = "unknown";
  if (apikeysResult.ok) {
    apiKeyRole = "admin";
  } else if (signersResult.ok) {
    apiKeyRole = "agent";
  }

  return {
    type: "popup:dashboard",
    signers:
      signersResult.ok && signersResult.data
        ? (Array.isArray(signersResult.data)
            ? signersResult.data
            : signersResult.data.signers || [])
        : [],
    signerCount:
      signersResult.ok && signersResult.data
        ? Array.isArray(signersResult.data)
          ? signersResult.data.length
          : signersResult.data.signers?.length || 0
        : 0,
    ruleCount:
      rulesResult.ok && rulesResult.data
        ? rulesResult.data.total || 0
        : 0,
    requestCount:
      requestsResult.ok && requestsResult.data
        ? Array.isArray(requestsResult.data)
          ? requestsResult.data.length
          : requestsResult.data.total || 0
        : 0,
    apiKeyRole,
  };
}

async function handlePopupOpenManagement() {
  const cfg = await loadConfig();
  const url = cfg.remoteSignerUrl.replace(/\/$/, "");
  await chrome.tabs.create({ url });
  return { type: "popup:managementOpened" };
}

// ── Crypto Helpers ──────────────────────────────────────────────────────

async function sha256(message: string): Promise<string> {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function ed25519Sign(
  privateKeyBytes: Uint8Array,
  message: Uint8Array
): Promise<Uint8Array> {
  // Try SubtleCrypto first (Chrome 125+)
  if (crypto.subtle.sign && crypto.subtle.importKey) {
    try {
      // Wrap raw 32-byte key as PKCS8 Ed25519 private key
      const pkcs8Prefix = hexToBytes(
        "302e020100300506032b657004220420"
      );
      const pkcs8Key = new Uint8Array(
        pkcs8Prefix.length + privateKeyBytes.length
      );
      pkcs8Key.set(pkcs8Prefix);
      pkcs8Key.set(privateKeyBytes, pkcs8Prefix.length);

      const cryptoKey = await crypto.subtle.importKey(
        "pkcs8",
        pkcs8Key,
        { name: "Ed25519" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("Ed25519", cryptoKey, message);
      return new Uint8Array(sig);
    } catch (e) {
      // Fall through to fallback
      console.warn("[background] SubtleCrypto Ed25519 not available, using fallback:", e);
    }
  }

  // Fallback: pure-JS Ed25519 (single-curve, minimal)
  return ed25519Fallback(privateKeyBytes, message);
}

/**
 * Minimal pure-JS Ed25519 implementation.
 * Single-curve operations only — no generic bignum library needed.
 */
function ed25519Fallback(
  privateKey: Uint8Array,
  message: Uint8Array
): Uint8Array {
  // This is a placeholder. In production, bundle @noble/ed25519.
  // For now, throw a descriptive error.
  throw new Error(
    "Ed25519 signing requires Chrome 125+ or @noble/ed25519. " +
    "Install with: npm install @noble/ed25519"
  );
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// ── Main Message Handler ─────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (message: IncomingMessage, _sender, sendResponse) => {
    // ── EIP-1193 ──────────────────────────────────────────────────────
    if (message.type === "web3-eip1193-request") {
      handleEIP1193Request(message)
        .then(sendResponse)
        .catch((err) => {
          sendResponse({
            type: "web3-eip1193-response",
            id: message.id,
            error: {
              code: -32603,
              message: err.message || String(err),
            },
          });
        });
      return true;
    }

    if (message.type === "web3-get-state") {
      handleGetState(message.id)
        .then(sendResponse)
        .catch((err) => {
          sendResponse({
            type: "web3-state-response",
            id: message.id,
            error: err.message || String(err),
          });
        });
      return true;
    }

    // ── Popup ─────────────────────────────────────────────────────────
    if (message.type === "popup:getConfig") {
      handlePopupGetConfig().then(sendResponse);
      return true;
    }

    if (message.type === "popup:saveConfig") {
      handlePopupSaveConfig(message).then(sendResponse);
      return true;
    }

    if (message.type === "popup:testConnection") {
      handlePopupTestConnection().then(sendResponse);
      return true;
    }

    if (message.type === "popup:getState") {
      handlePopupGetState().then(sendResponse);
      return true;
    }

    if (message.type === "popup:getDashboard") {
      handlePopupGetDashboard().then(sendResponse);
      return true;
    }

    if (message.type === "popup:openManagement") {
      handlePopupOpenManagement().then(sendResponse);
      return true;
    }

    return false;
  }
);

// Lazy init: only create the provider when a dApp actually requests it.
// Config is loaded on-demand from chrome.storage.local.
