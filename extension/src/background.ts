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
  /**
   * Address of the signer the user picked as active. The provider is
   * re-pointed at this address on init via switchAccount(). If unset or no
   * longer in the usable signer set, the provider falls back to its default
   * active index. Persisted so the choice survives popup reloads.
   */
  activeSignerAddress?: string;
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

interface PopupSwitchAccount {
  type: "popup:switchAccount";
  address: string;
}

interface PopupGetActivity {
  type: "popup:getActivity";
  limit?: number;
  status?: string;
}

interface PopupGetRequest {
  type: "popup:getRequest";
  requestId: string;
}

type PopupMessage =
  | PopupGetConfig
  | PopupSaveConfig
  | PopupTestConnection
  | PopupGetState
  | PopupGetDashboard
  | PopupOpenManagement
  | PopupSwitchAccount
  | PopupGetActivity
  | PopupGetRequest;

type IncomingMessage = EIP1193Request | StateRequest | PopupMessage;

// ── Defaults ─────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: StoredConfig = {
  remoteSignerUrl: "http://127.0.0.1:8548",
  // "agent" is the standard role name used by `remote-signer` when it
  // bootstraps a local instance (see `~/.remote-signer/apikeys/agent.key.priv`).
  // Defaulting the field saves the user a step on first run.
  apiKeyId: "agent",
  apiKeyPrivateKey: "",
  selectedChain: 1,
};

const EXTENSION_VERSION =
  (typeof chrome !== "undefined" && chrome.runtime?.getManifest?.()?.version) || "dev";
const CLIENT_VERSION_STRING = `RemoteSigner/v${EXTENSION_VERSION}/javascript`;

// ── Chain registry ───────────────────────────────────────────────────────
//
// EIP-1193 read RPC methods (eth_call, eth_getBalance, …) and the forwarded
// methods we add below (eth_sendRawTransaction, eth_feeHistory, …) need an
// HTTP RPC endpoint per chain. We seed a few well-known public endpoints and
// let dApps extend the set via wallet_addEthereumChain (EIP-3085).

interface ChainEntry {
  chainId: number;
  rpcUrls: string[];
  chainName?: string;
  nativeCurrency?: { name: string; symbol: string; decimals: number };
  blockExplorerUrls?: string[];
}

const DEFAULT_CHAINS: ChainEntry[] = [
  { chainId: 1, chainName: "Ethereum", rpcUrls: ["https://eth.llamarpc.com"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 10, chainName: "Optimism", rpcUrls: ["https://mainnet.optimism.io"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 56, chainName: "BNB Smart Chain", rpcUrls: ["https://bsc-dataseed.binance.org"], nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 } },
  { chainId: 137, chainName: "Polygon", rpcUrls: ["https://polygon-rpc.com"], nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 } },
  { chainId: 8453, chainName: "Base", rpcUrls: ["https://mainnet.base.org"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 42161, chainName: "Arbitrum One", rpcUrls: ["https://arb1.arbitrum.io/rpc"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 11155111, chainName: "Sepolia", rpcUrls: ["https://ethereum-sepolia-rpc.publicnode.com"], nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 } },
];

const chainRegistry: Map<number, ChainEntry> = new Map(
  DEFAULT_CHAINS.map((c) => [c.chainId, c])
);

function getRpcUrl(chainId: number): string | undefined {
  return chainRegistry.get(chainId)?.rpcUrls?.[0];
}

function rpcOverridesFromRegistry(): Record<number, string> {
  const out: Record<number, string> = {};
  for (const [chainId, cfg] of chainRegistry) {
    const url = cfg.rpcUrls?.[0];
    if (url) out[chainId] = url;
  }
  return out;
}

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
  cachedConfig = {
    ...cfg,
    apiKeyPrivateKey: normalizePrivateKey(cfg.apiKeyPrivateKey),
  };
  await chrome.storage.local.set({ [configKey()]: cachedConfig });
}

/**
 * Accept either:
 *   - hex (with or without 0x): the SDK already handles 32 or 64 byte hex
 *   - PEM-encoded PKCS8 Ed25519 private key (-----BEGIN PRIVATE KEY-----)
 *
 * For PEM input we base64-decode the body and slice the 32-byte seed at
 * offset 16 (the OCTET STRING immediately after the standard PKCS8/Ed25519
 * ASN.1 prefix). Works for both PKCS8 v1 (48 bytes total) and v2 (which
 * appends the public key after the seed). Returns hex; throws on malformed
 * input so the caller can surface a clear error.
 */
function normalizePrivateKey(input: string): string {
  if (!input) return input;
  const trimmed = input.trim();
  if (!trimmed.includes("-----BEGIN")) return trimmed; // hex path
  const m = trimmed.match(/-----BEGIN[^-]+-----([\s\S]+?)-----END[^-]+-----/);
  if (!m) {
    throw new Error("Malformed PEM: missing BEGIN/END markers");
  }
  const b64 = m[1].replace(/\s+/g, "");
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    throw new Error("Malformed PEM: body is not valid base64");
  }
  if (bin.length < 48) {
    throw new Error(`Malformed PEM: decoded ${bin.length} bytes, expected at least 48`);
  }
  // PKCS8 Ed25519: 16-byte ASN.1 prefix then 32-byte seed.
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = bin.charCodeAt(16 + i);
  return Array.from(seed)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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
    rpcOverrides: rpcOverridesFromRegistry(),
    rpcResolver: async (chainId: number) => {
      const url = getRpcUrl(chainId);
      if (!url) throw new Error(`No RPC URL configured for chain ${chainId}`);
      return url;
    },
  });

  // Restore the user's previous active signer choice. If it's no longer in
  // the usable set (revoked, locked) we silently fall back to the provider's
  // default and clear the stored value so the popup picks a fresh one.
  if (cfg.activeSignerAddress && provider.isConnected()) {
    try {
      await provider.switchAccount(cfg.activeSignerAddress);
    } catch (err) {
      console.warn("[background] stored active signer no longer usable:", err);
      cfg.activeSignerAddress = undefined;
      await saveConfig(cfg);
    }
  }

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

  // Persist state-changing events so user choices survive an MV3
  // service-worker suspension. Without this, the SDK's in-memory state
  // wins for the current session but gets clobbered on next SW resume
  // when we re-init from chrome.storage.local. Symptoms we've seen:
  //   - wallet_switchEthereumChain(137) survives only until SW restart,
  //     then wagmi sees chain 1 and throws ConnectorChainMismatchError
  //     (Polymarket "Request Cancelled" after manual approval).
  //   - SDK-side account changes (e.g. switchAccount triggered from
  //     somewhere other than the popup) revert to the default signer on
  //     SW resume, so a dApp that already cached the new address sees
  //     accountsChanged go backwards on reconnect.
  provider.on("chainChanged", async (chainIdHex: unknown) => {
    if (typeof chainIdHex !== "string") return;
    const newChainId = parseInt(chainIdHex, 16);
    if (!Number.isFinite(newChainId) || newChainId <= 0) return;
    if (cachedConfig.selectedChain === newChainId) return;
    cachedConfig.selectedChain = newChainId;
    try {
      await chrome.storage.local.set({ [configKey()]: cachedConfig });
    } catch (err) {
      console.error("[background] Failed to persist chainChanged:", err);
    }
  });

  provider.on("accountsChanged", async (accounts: unknown) => {
    if (!Array.isArray(accounts) || accounts.length === 0) return;
    const active = typeof accounts[0] === "string" ? (accounts[0] as string).toLowerCase() : undefined;
    if (!active) return;
    if (cachedConfig.activeSignerAddress?.toLowerCase() === active) return;
    cachedConfig.activeSignerAddress = active;
    try {
      await chrome.storage.local.set({ [configKey()]: cachedConfig });
    } catch (err) {
      console.error("[background] Failed to persist accountsChanged:", err);
    }
  });
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

interface RpcError {
  code: number;
  message: string;
  data?: unknown;
}

/**
 * Forward a JSON-RPC call to the active chain's RPC endpoint.
 * Returns either a result or an RpcError shaped per JSON-RPC.
 */
async function forwardToRpc(
  method: string,
  params: unknown
): Promise<{ result?: unknown; error?: RpcError }> {
  const chainId = provider ? parseInt(provider.chainId, 16) : 1;
  const rpcUrl = getRpcUrl(chainId);
  if (!rpcUrl) {
    return {
      error: { code: -32603, message: `No RPC URL configured for chain ${chainId}` },
    };
  }
  try {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: Date.now(),
        method,
        params: Array.isArray(params) ? params : [],
      }),
    });
    const json: any = await res.json();
    if (json.error) {
      return { error: { code: json.error.code ?? -32603, message: json.error.message ?? "RPC error", data: json.error.data } };
    }
    return { result: json.result };
  } catch (err: any) {
    return { error: { code: -32603, message: err?.message || String(err) } };
  }
}

/**
 * Handle a wallet_addEthereumChain call (EIP-3085).
 * If the chain is already known, returns null. Otherwise adds it to the registry.
 */
function handleAddEthereumChain(params: unknown): { result?: null; error?: RpcError } {
  const first = Array.isArray(params) ? (params[0] as any) : undefined;
  const chainIdHex = first?.chainId;
  if (typeof chainIdHex !== "string" || !chainIdHex.startsWith("0x")) {
    return { error: { code: -32602, message: "Invalid chainId parameter" } };
  }
  const chainId = parseInt(chainIdHex, 16);
  if (!Number.isFinite(chainId) || chainId <= 0) {
    return { error: { code: -32602, message: "Invalid chainId parameter" } };
  }
  const rpcUrls: string[] = Array.isArray(first?.rpcUrls) ? first.rpcUrls : [];
  // If the chain is already in our registry, return null (per spec).
  if (chainRegistry.has(chainId)) return { result: null };
  if (rpcUrls.length === 0) {
    return { error: { code: -32602, message: "wallet_addEthereumChain requires rpcUrls" } };
  }
  chainRegistry.set(chainId, {
    chainId,
    rpcUrls,
    chainName: typeof first?.chainName === "string" ? first.chainName : undefined,
    nativeCurrency: first?.nativeCurrency,
    blockExplorerUrls: Array.isArray(first?.blockExplorerUrls) ? first.blockExplorerUrls : undefined,
  });
  return { result: null };
}

/**
 * Try to handle a method outside the SDK provider. The SDK rejects anything
 * not in its switch with code 4200 (unsupportedMethod); we cover the rest of
 * the MetaMask-compatible surface so dApps like Uniswap/Polymarket/DeBank
 * don't fall over on chain-add, fee queries, or permission probes.
 *
 * Returns { handled: false } to fall through to the SDK.
 */
async function tryHandleExtraMethod(
  msg: EIP1193Request
): Promise<{ handled: false } | { handled: true; result?: unknown; error?: RpcError }> {
  const { method, params } = msg;

  switch (method) {
    // ── Legacy / informational ─────────────────────────────────────────────
    case "web3_clientVersion":
      return { handled: true, result: CLIENT_VERSION_STRING };
    case "net_listening":
      return { handled: true, result: true };
    case "net_peerCount":
      return { handled: true, result: "0x0" };

    // ── Permissions (EIP-2255) ─────────────────────────────────────────────
    case "wallet_getPermissions":
      return { handled: true, result: [{ parentCapability: "eth_accounts" }] };
    case "wallet_revokePermissions":
      // We don't gate accounts behind per-origin permissions today, but a
      // dApp can still call this on logout. Emit accountsChanged([]) so the
      // dApp UI updates, and return null.
      broadcastEvent("accountsChanged", []);
      return { handled: true, result: null };

    // ── Watch asset (EIP-747) ─────────────────────────────────────────────
    case "wallet_watchAsset":
      // We don't maintain a token list, but the spec says return true on success.
      return { handled: true, result: true };

    // ── Capabilities (EIP-5792) ───────────────────────────────────────────
    case "wallet_getCapabilities":
      // No atomic-batch support yet — return empty caps per spec.
      return { handled: true, result: {} };

    // ── Chain management (EIP-3085 / 3326) ────────────────────────────────
    case "wallet_addEthereumChain":
      return { handled: true, ...handleAddEthereumChain(params) };

    case "wallet_switchEthereumChain": {
      const first = Array.isArray(params) ? (params[0] as any) : undefined;
      const chainIdHex = first?.chainId;
      if (typeof chainIdHex !== "string" || !chainIdHex.startsWith("0x")) {
        return { handled: true, error: { code: -32602, message: "Missing or invalid chainId parameter" } };
      }
      const chainId = parseInt(chainIdHex, 16);
      if (!chainRegistry.has(chainId)) {
        // Per spec, return 4902 so the dApp knows to call wallet_addEthereumChain.
        return {
          handled: true,
          error: { code: 4902, message: `Unrecognized chain ID "${chainIdHex}". Try adding the chain with wallet_addEthereumChain.` },
        };
      }
      // Chain is known — let the SDK perform the actual switch.
      return { handled: false };
    }

    // ── Forwarded read / send methods ─────────────────────────────────────
    // The SDK enumerates most read methods but misses these. Forward to the
    // active chain's RPC endpoint.
    case "eth_sendRawTransaction":
    case "eth_maxPriorityFeePerGas":
    case "eth_feeHistory":
    case "eth_getProof":
    case "eth_blobBaseFee":
    case "eth_syncing":
      return { handled: true, ...(await forwardToRpc(method, params)) };

    default:
      return { handled: false };
  }
}

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

  // Pre-SDK dispatch for MetaMask-compatible methods the SDK doesn't cover.
  const extra = await tryHandleExtraMethod(msg);
  if (extra.handled) {
    if (extra.error) {
      return { type: "web3-eip1193-response", id: msg.id, error: extra.error };
    }
    return { type: "web3-eip1193-response", id: msg.id, result: extra.result };
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
  try {
    await saveConfig(msg.config);
  } catch (err: any) {
    return {
      type: "popup:configSaved",
      ok: false,
      error: err?.message || String(err),
    };
  }
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

/**
 * Build a transient RemoteSignerClient for popup-driven API calls.
 *
 * We reuse the SDK rather than rolling our own Ed25519/PKCS8 path so that
 * 64-byte Go-style private keys (seed+pubkey) work — the SDK's parsePrivateKey
 * slices to the 32-byte seed before passing it to @noble/ed25519.
 */
function buildPopupClient(cfg: StoredConfig): RemoteSignerClient {
  return new RemoteSignerClient({
    baseURL: cfg.remoteSignerUrl,
    apiKeyID: cfg.apiKeyId,
    privateKey: cfg.apiKeyPrivateKey,
    httpClient: { fetch: fetch.bind(self) },
  });
}

async function handlePopupTestConnection() {
  const cfg = cachedConfig;
  if (!cfg.remoteSignerUrl) {
    return {
      type: "popup:connectionResult",
      ok: false,
      error: "Remote Signer URL not configured",
    };
  }
  if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
    return {
      type: "popup:connectionResult",
      ok: false,
      error: "API key not configured",
    };
  }

  let popupClient: RemoteSignerClient;
  try {
    popupClient = buildPopupClient(cfg);
  } catch (err: any) {
    return {
      type: "popup:connectionResult",
      ok: false,
      error: `Invalid configuration: ${err.message || String(err)}`,
    };
  }

  // 1) Health probe (no auth) — verifies URL reachability.
  let serverVersion = "unknown";
  try {
    const health = await popupClient.health();
    serverVersion = health?.version || "unknown";
  } catch (err: any) {
    return {
      type: "popup:connectionResult",
      ok: false,
      error: `Cannot reach server: ${err.message || String(err)}`,
    };
  }

  // 2) Authenticated probe — verifies API key signing.
  let signerCount = 0;
  try {
    const list = await popupClient.evm.signers.list();
    signerCount = list?.signers?.length ?? 0;
  } catch (err: any) {
    const status = err?.statusCode;
    const msg = err?.message || String(err);
    return {
      type: "popup:connectionResult",
      ok: false,
      error: status ? `Auth failed (HTTP ${status}): ${msg}` : `Auth failed: ${msg}`,
    };
  }

  return {
    type: "popup:connectionResult",
    ok: true,
    version: serverVersion,
    url: cfg.remoteSignerUrl,
    signerCount,
  };
}

/**
 * Popup connection state. "connected" means "we can talk to the configured
 * server and auth works" — independent of whether the server has any usable
 * signers. Signer readiness is reported separately via signerStatus so the
 * UI can show actionable copy ("import a signer", "unlock the locked one")
 * instead of a misleading "Not connected".
 */
async function handlePopupGetState() {
  const cfg = cachedConfig;

  // Without configured credentials we treat the popup as "not configured".
  // This is distinct from "configured but can't reach the server".
  if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey || !cfg.remoteSignerUrl) {
    return {
      type: "popup:state",
      connected: false,
      configured: false,
      accounts: [],
      chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
      error: null,
      signerStatus: null,
    };
  }

  // Build a transient SDK client to probe /health + signers without coupling
  // popup state to the EIP1193Provider's "needs at least one signer to be
  // connected" semantics. The EIP1193Provider is still lazily initialised on
  // demand for dApp requests via ensureInit().
  let popupClient: RemoteSignerClient;
  try {
    popupClient = buildPopupClient(cfg);
  } catch (err: any) {
    return {
      type: "popup:state",
      connected: false,
      configured: true,
      accounts: [],
      chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
      error: `Invalid configuration: ${err?.message || String(err)}`,
      signerStatus: null,
    };
  }

  // 1) Server reachability (no auth).
  try {
    await popupClient.health();
  } catch (err: any) {
    return {
      type: "popup:state",
      connected: false,
      configured: true,
      accounts: [],
      chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
      error: `Cannot reach server: ${err?.message || String(err)}`,
      signerStatus: null,
    };
  }

  // 2) Auth + signer enumeration.
  let signers: any[] = [];
  try {
    const list = await popupClient.evm.signers.list();
    signers = (list as any)?.signers ?? [];
  } catch (err: any) {
    const status = err?.statusCode;
    const msg = err?.message || String(err);
    return {
      type: "popup:state",
      connected: false,
      configured: true,
      accounts: [],
      chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
      error: status ? `Auth failed (HTTP ${status}): ${msg}` : `Auth failed: ${msg}`,
      signerStatus: null,
    };
  }

  // At this point we're "connected" — the server is reachable and auth works.
  // Signer readiness is purely informational.
  const usable = signers.filter((s: any) => s.enabled && !s.locked);
  const locked = signers.filter((s: any) => s.locked);
  const disabled = signers.filter((s: any) => !s.enabled);

  const accounts: string[] = usable.map((s: any) => s.address).filter(Boolean);
  const chainId = `0x${(cfg.selectedChain || 1).toString(16)}`;

  // Compute the active address. Prefer the live provider if available
  // (kept in sync via popup:switchAccount + wallet_switchEthereumChain),
  // otherwise fall back to the stored choice, otherwise to the first usable.
  let activeAddress: string | null = null;
  if (provider && provider.isConnected()) {
    activeAddress = provider.selectedAddress;
  }
  if (!activeAddress && cfg.activeSignerAddress) {
    const match = usable.find(
      (s: any) => s.address?.toLowerCase() === cfg.activeSignerAddress!.toLowerCase()
    );
    if (match) activeAddress = match.address;
  }
  if (!activeAddress && accounts.length > 0) {
    activeAddress = accounts[0];
  }

  return {
    type: "popup:state",
    connected: true,
    configured: true,
    accounts,
    activeAddress,
    // Full signer list with status flags so the popup can render the
    // locked/disabled rows greyed out alongside usable ones.
    signers: signers.map((s: any) => ({
      address: s.address,
      type: s.type,
      enabled: !!s.enabled,
      locked: !!s.locked,
    })),
    chainId,
    error: null,
    signerStatus: {
      total: signers.length,
      usable: usable.length,
      locked: locked.length,
      disabled: disabled.length,
    },
  };
}

async function safeSdkCall<T>(fn: () => Promise<T>): Promise<{ ok: boolean; data?: T; error?: string }> {
  try {
    const data = await fn();
    return { ok: true, data };
  } catch (err: any) {
    return { ok: false, error: err?.message || String(err) };
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

  let popupClient: RemoteSignerClient;
  try {
    popupClient = buildPopupClient(cfg);
  } catch {
    return {
      type: "popup:dashboard",
      signers: [],
      signerCount: 0,
      ruleCount: 0,
      requestCount: 0,
      apiKeyRole: "unknown",
    };
  }

  const [signersResult, rulesResult, requestsResult, apikeysResult] =
    await Promise.all([
      safeSdkCall(() => popupClient.evm.signers.list()),
      safeSdkCall(() => popupClient.evm.rules.list({ limit: 1 })),
      safeSdkCall(() => popupClient.evm.requests.list({ limit: 100 })),
      safeSdkCall(() => popupClient.apiKeys.list()),
    ]);

  let apiKeyRole = "unknown";
  if (apikeysResult.ok) {
    apiKeyRole = "admin";
  } else if (signersResult.ok) {
    apiKeyRole = "agent";
  }

  const signersData: any = signersResult.data ?? {};
  const signerList: any[] = Array.isArray(signersData)
    ? signersData
    : signersData.signers ?? [];

  const rulesData: any = rulesResult.data ?? {};
  const requestsData: any = requestsResult.data ?? {};

  return {
    type: "popup:dashboard",
    signers: signerList.map((s) => (typeof s === "string" ? s : s?.address)).filter(Boolean),
    signerCount: signerList.length,
    ruleCount: rulesData.total ?? (Array.isArray(rulesData.rules) ? rulesData.rules.length : 0),
    requestCount: requestsData.total ?? (Array.isArray(requestsData.requests) ? requestsData.requests.length : 0),
    apiKeyRole,
  };
}

async function handlePopupOpenManagement() {
  const cfg = await loadConfig();
  const url = cfg.remoteSignerUrl.replace(/\/$/, "");
  await chrome.tabs.create({ url });
  return { type: "popup:managementOpened" };
}

/**
 * List recent sign requests for the configured API key.
 *
 * The backend filters by api_key_id automatically so an agent only sees
 * their own requests. We pass the result through largely untouched — the
 * popup wants the full DTO to render status + sign_type + payload preview.
 */
async function handlePopupGetActivity(msg: PopupGetActivity) {
  const cfg = cachedConfig;
  if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
    return { type: "popup:activity", ok: false, error: "Not configured", requests: [] };
  }
  let popupClient: RemoteSignerClient;
  try {
    popupClient = buildPopupClient(cfg);
  } catch (err: any) {
    return { type: "popup:activity", ok: false, error: err?.message || String(err), requests: [] };
  }
  try {
    const filter: any = { limit: msg.limit ?? 20 };
    if (msg.status) filter.status = msg.status;
    const list = await popupClient.evm.requests.list(filter);
    return {
      type: "popup:activity",
      ok: true,
      requests: (list as any)?.requests ?? [],
      total: (list as any)?.total ?? 0,
      hasMore: !!(list as any)?.has_more,
    };
  } catch (err: any) {
    return { type: "popup:activity", ok: false, error: err?.message || String(err), requests: [] };
  }
}

/**
 * Fetch full detail for a single request (the popup's detail drawer needs
 * payload + signature + rule_matched_id, which the list view trims).
 */
async function handlePopupGetRequest(msg: PopupGetRequest) {
  const cfg = cachedConfig;
  if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
    return { type: "popup:request", ok: false, error: "Not configured" };
  }
  let popupClient: RemoteSignerClient;
  try {
    popupClient = buildPopupClient(cfg);
  } catch (err: any) {
    return { type: "popup:request", ok: false, error: err?.message || String(err) };
  }
  try {
    const req = await popupClient.evm.requests.get(msg.requestId);
    return { type: "popup:request", ok: true, request: req };
  } catch (err: any) {
    return { type: "popup:request", ok: false, error: err?.message || String(err) };
  }
}

/**
 * Switch the active signer for dApp requests.
 *
 * The EIP1193Provider holds the source of truth for "active account" — we
 * delegate to it (so the accountsChanged event fires naturally to every
 * connected tab) and mirror the choice into chrome.storage so it survives
 * the next service-worker cold start.
 */
async function handlePopupSwitchAccount(msg: PopupSwitchAccount) {
  await ensureInit();
  if (!provider) {
    return { type: "popup:accountSwitched", ok: false, error: initError || "Provider not initialized" };
  }
  try {
    await provider.switchAccount(msg.address);
  } catch (err: any) {
    return { type: "popup:accountSwitched", ok: false, error: err?.message || String(err) };
  }
  cachedConfig.activeSignerAddress = msg.address;
  await chrome.storage.local.set({ [configKey()]: cachedConfig });
  return { type: "popup:accountSwitched", ok: true, address: provider.selectedAddress };
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

    if (message.type === "popup:switchAccount") {
      handlePopupSwitchAccount(message).then(sendResponse);
      return true;
    }

    if (message.type === "popup:getActivity") {
      handlePopupGetActivity(message).then(sendResponse);
      return true;
    }

    if (message.type === "popup:getRequest") {
      handlePopupGetRequest(message).then(sendResponse);
      return true;
    }

    return false;
  }
);

// Lazy init: only create the provider when a dApp actually requests it.
// Config is loaded on-demand from chrome.storage.local.
