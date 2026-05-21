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
  type ProviderStorage,
} from "remote-signer-client";
import { bytesToHex, decryptKeystore } from "./keystore";
import { createLogger, describeError } from "./logger";

// One logger per major lifecycle area so SW-console grep ("bg.dispatch")
// can isolate the dApp hot path from background work like provider init,
// permission acquisition, or pending-approval window plumbing.
const log = createLogger("bg");
const dispatchLog = createLogger("bg.dispatch");
const permissionLog = createLogger("bg.permission");
const refreshLog = createLogger("bg.refresh");
const initLog = createLogger("bg.init");
const approvalLog = createLogger("bg.approval");
const connectLog = createLogger("bg.connect");

// Adapter that exposes chrome.storage.local through the SDK's
// ProviderStorage interface. Lets the SDK own the load/persist lifecycle
// for {chainId, activeAddress} — keeps a single source of truth and
// removes the need for state-mirroring listeners in this file.
const chromeStorageAdapter: ProviderStorage = {
  getItem(key: string): Promise<string | null> {
    return new Promise((resolve) => {
      chrome.storage.local.get(key, (r) => resolve(typeof r[key] === "string" ? r[key] : null));
    });
  },
  setItem(key: string, value: string): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: value }, () => resolve());
    });
  },
  removeItem(key: string): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.local.remove(key, () => resolve());
    });
  },
};

function providerStorageKey(apiKeyId: string): string {
  // Per-API-key namespace so multiple agents on the same browser don't
  // clobber each other's chain/account state.
  return `remote-signer:provider:${apiKeyId || "default"}`;
}

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
  /**
   * When true (default) dApps that call eth_requestAccounts /
   * wallet_requestPermissions get the active signer + popup's selected
   * chain back immediately — no Connect popup. Power-users who prefer
   * an explicit per-site prompt flip this off in Settings.
   */
  autoApproveConnections?: boolean;
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

// Decrypts an EnhancedKeyFile keystore JSON. Popup needs this when the
// operator pastes the admin keystore instead of the agent's plaintext
// PEM — popup itself can't bundle @noble/hashes (it's not esbuild'd),
// so the background service worker, which IS bundled, exposes a
// decrypt-on-demand entrypoint. Result is the 32-byte seed hex, which
// the popup then persists in chrome.storage exactly like it does for
// plaintext PEM imports — no encrypted state lives in extension storage.
interface PopupDecryptKeystore {
  type: "popup:decryptKeystore";
  json: string;
  password: string;
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
  | PopupGetRequest
  | PopupDecryptKeystore;

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
  autoApproveConnections: true,
};

const EXTENSION_VERSION =
  (typeof chrome !== "undefined" && chrome.runtime?.getManifest?.()?.version) || "dev";
const CLIENT_VERSION_STRING = `RemoteSigner/v${EXTENSION_VERSION}/javascript`;

// ── Chain registry ───────────────────────────────────────────────────────
//
// EIP-1193 read RPC methods (eth_call, eth_getBalance, …) and the forwarded
// methods we add below (eth_sendRawTransaction, eth_feeHistory, …) need an
// Chain metadata catalogue — name + native currency for popup
// rendering only. Read/broadcast RPC traffic now goes through the
// daemon's `/api/v1/evm/rpc/{chainId}` proxy (see
// `EvmRPCProxyService` in the SDK), so the extension no longer
// ships any chain RPC URLs. The daemon's `rpc_gateway` setting is
// the single source of upstream-endpoint configuration.

interface ChainEntry {
  chainId: number;
  chainName?: string;
  nativeCurrency?: { name: string; symbol: string; decimals: number };
  blockExplorerUrls?: string[];
}

const DEFAULT_CHAINS: ChainEntry[] = [
  { chainId: 1, chainName: "Ethereum", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 10, chainName: "Optimism", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 56, chainName: "BNB Smart Chain", nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 } },
  { chainId: 137, chainName: "Polygon", nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 } },
  { chainId: 8453, chainName: "Base", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 42161, chainName: "Arbitrum One", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  { chainId: 11155111, chainName: "Sepolia", nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 } },
];

const chainRegistry: Map<number, ChainEntry> = new Map(
  DEFAULT_CHAINS.map((c) => [c.chainId, c])
);

// ── Per-origin chain memory ──────────────────────────────────────────────
//
// remote-signer is a multi-chain gateway, not a traditional single-chain
// wallet. There is no reason the extension should impose a global
// "selectedChain" on every dApp — Polymarket lives on Polygon while
// Uniswap may be on Mainnet at the same moment. Each origin gets its own
// chain memory, persisted across SW restarts. The popup's chain chip
// remains as the default for *new* origins; existing origins remember
// whatever they (or the user, via popup-driven switch) last chose.
//
// Storage shape: { "https://polymarket.com": 137, ... }
// Stored under a dedicated key so it survives independently of the
// connection-related config.
const CHAIN_BY_ORIGIN_KEY = "remote-signer:chainByOrigin";
let chainByOrigin: Record<string, number> = {};

// Read fresh from storage every time — same rationale as
// ensurePermittedOriginsLoaded: a once-and-cache approach raced with
// out-of-band writes (e.g. injectStorageConfig from the popup page).
async function ensureChainByOriginLoaded(): Promise<void> {
  await new Promise<void>((resolve) =>
    chrome.storage.local.get(CHAIN_BY_ORIGIN_KEY, (r) => {
      const raw = r[CHAIN_BY_ORIGIN_KEY];
      const rebuilt: Record<string, number> = {};
      if (raw && typeof raw === "object") {
        for (const [k, v] of Object.entries(raw)) {
          if (typeof v === "number" && v > 0) rebuilt[k] = v;
        }
      }
      chainByOrigin = rebuilt;
      resolve();
    })
  );
}

async function persistChainByOrigin(): Promise<void> {
  try {
    await chrome.storage.local.set({ [CHAIN_BY_ORIGIN_KEY]: chainByOrigin });
  } catch {
    /* best-effort */
  }
}

function normalizeOrigin(senderUrl: string | undefined): string | null {
  if (!senderUrl) return null;
  try {
    const u = new URL(senderUrl);
    // Match what dApps see as window.origin: scheme + host + (port).
    return u.origin;
  } catch {
    return null;
  }
}

function getChainForOrigin(origin: string | null): number {
  if (origin && chainByOrigin[origin]) return chainByOrigin[origin];
  return cachedConfig.selectedChain || 1;
}

async function setChainForOrigin(origin: string, chainId: number): Promise<void> {
  if (chainByOrigin[origin] === chainId) return;
  chainByOrigin[origin] = chainId;
  await persistChainByOrigin();
}

// ── Per-origin permissions (EIP-2255) ────────────────────────────────────
//
// MetaMask 12+ ties two decisions together at first-connect time: WHICH
// signer accounts an origin can see, and WHICH chain it should observe.
// Without this gate our extension blindly returned the active signer on
// eth_accounts to every page — so dApps never had a reason to call
// eth_requestAccounts, never went through a permission prompt, and
// never got the chance to pick a chain. End result on Polymarket: SIWE
// gets built with our default chain (1) and Polymarket's auth API 401s.
//
// We persist permissions per origin under "remote-signer:permittedOrigins".
// `accounts` are address strings (lowercased) that the origin can read;
// `chainId` is the chain it should observe; `grantedAt` is the ms epoch
// so wallet_getPermissions can return a stable `date`. The Connect popup
// (popup/connect.html) writes new entries here; wallet_revokePermissions
// removes them; eth_accounts and eth_chainId read from them.
const PERMITTED_ORIGINS_KEY = "remote-signer:permittedOrigins";

interface OriginPermission {
  accounts: string[];
  chainId: number;
  grantedAt: number;
}

let permittedOrigins: Record<string, OriginPermission> = {};

// Always read from chrome.storage — the once-and-cache approach raced
// with same-session writers (popup's injectStorageConfig in tests,
// content-script seed paths) because storage.onChanged dispatches
// asynchronously. With a tens-of-entries map the cost is negligible
// and the freshness guarantee removes a whole class of subtle bugs.
async function ensurePermittedOriginsLoaded(): Promise<void> {
  await new Promise<void>((resolve) =>
    chrome.storage.local.get(PERMITTED_ORIGINS_KEY, (r) => {
      const raw = r[PERMITTED_ORIGINS_KEY];
      const rebuilt: Record<string, OriginPermission> = {};
      if (raw && typeof raw === "object") {
        for (const [k, v] of Object.entries(raw)) {
          const p = v as any;
          if (
            p &&
            Array.isArray(p.accounts) &&
            typeof p.chainId === "number" &&
            typeof p.grantedAt === "number"
          ) {
            rebuilt[k] = {
              accounts: p.accounts.map((a: any) => String(a).toLowerCase()),
              chainId: p.chainId,
              grantedAt: p.grantedAt,
            };
          }
        }
      }
      permittedOrigins = rebuilt;
      resolve();
    })
  );
}

async function persistPermittedOrigins(): Promise<void> {
  try {
    await chrome.storage.local.set({ [PERMITTED_ORIGINS_KEY]: permittedOrigins });
  } catch {
    /* best-effort */
  }
}


function getPermissionForOrigin(origin: string | null): OriginPermission | null {
  if (!origin) return null;
  return permittedOrigins[origin] ?? null;
}

async function setPermissionForOrigin(origin: string, perm: OriginPermission): Promise<void> {
  permittedOrigins[origin] = perm;
  await persistPermittedOrigins();
  // Per-origin chain mirrors the connect-time chain choice. Until the
  // dApp later calls wallet_switchEthereumChain, eth_chainId answers
  // from here.
  await setChainForOrigin(origin, perm.chainId);
}

async function revokePermissionForOrigin(origin: string): Promise<void> {
  if (!permittedOrigins[origin]) return;
  delete permittedOrigins[origin];
  await persistPermittedOrigins();
  // Tell the dApp its account list is now empty so its connector
  // state machine resets. Don't touch chainByOrigin — the origin can
  // re-connect on the same chain without retreading the dialog.
  broadcastEventToOrigin(origin, "accountsChanged", []);
}

// ── Connect-time prompt: openConnectWindow + pending request bookkeeping ──
//
// dApp calls eth_requestAccounts → background looks up the origin's
// permission record. If missing, we open a small floating window
// (popup/connect.html) and block the caller until the user clicks
// Connect or Cancel in that window. On Connect the popup IPCs back
// with the chain they picked; we persist + resolve. On Cancel (or
// window close, or timeout) we reject with EIP-1193 code 4001.

interface PendingConnect {
  origin: string;
  resolve: (perm: OriginPermission) => void;
  reject: (err: { code: number; message: string }) => void;
  windowId?: number;
  timeoutHandle: ReturnType<typeof setTimeout>;
}
const pendingConnects: Map<string, PendingConnect> = new Map();

function connectRequestId(): string {
  return "cnx-" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

async function openConnectWindow(
  origin: string,
  requestId: string,
  suggestedChainId: number
): Promise<void> {
  const params = new URLSearchParams({
    requestId,
    origin,
    suggestedChainId: String(suggestedChainId),
  });
  const url = chrome.runtime.getURL(`popup/connect.html?${params.toString()}`);
  try {
    const win = await chrome.windows.create({
      url,
      type: "popup",
      width: 380,
      height: 520,
      focused: true,
    });
    const pending = pendingConnects.get(requestId);
    if (pending && win.id != null) pending.windowId = win.id;
  } catch (err) {
    connectLog.error("failed to open Connect window", {
      requestId,
      origin,
      ...describeError(err),
    });
    const pending = pendingConnects.get(requestId);
    if (pending) {
      clearTimeout(pending.timeoutHandle);
      pendingConnects.delete(requestId);
      pending.reject({ code: -32603, message: "Failed to open Connect window" });
    }
  }
}

// Drop any pending connect tied to a window the user just closed, so
// the dApp side promise rejects instead of hanging forever.
chrome.windows?.onRemoved?.addListener?.((windowId) => {
  for (const [reqId, pending] of pendingConnects) {
    if (pending.windowId === windowId) {
      clearTimeout(pending.timeoutHandle);
      pendingConnects.delete(reqId);
      pending.reject({ code: 4001, message: "User closed Connect window" });
    }
  }
});

/**
 * Acquire a permission for `origin`. If `autoApproveConnections` is on
 * (the default), grant immediately with the active signer + popup's
 * selected chain — no Connect popup. Otherwise route through the
 * interactive Connect window so the user explicitly picks both.
 */
async function acquirePermission(origin: string): Promise<OriginPermission> {
  // Re-read cachedConfig from storage so out-of-band toggle changes
  // (popup settings save from another window) are seen immediately.
  // Without this, the SW uses whichever autoApprove value it had at
  // startup.
  await loadConfig();
  permissionLog.info("acquire", {
    origin,
    autoApprove: cachedConfig.autoApproveConnections !== false,
  });
  if (cachedConfig.autoApproveConnections !== false) {
    await ensureInit();
    // Always pull a fresh signer list from the daemon at connect time.
    // The user could have unlocked an HD wallet signer or added a new
    // keystore from the CLI / popup between provider init and now —
    // without this refresh, the SW would throw "No usable signers" until
    // someone reloads the extension. ensureInit guarantees provider!=null.
    await refreshSignersIgnoringErrors();
    let accounts: string[] = [];
    try {
      if (provider && provider.isConnected()) {
        accounts = (await provider.request({ method: "eth_accounts" })) as string[];
      } else {
        permissionLog.warn("provider not connected at acquire time", {
          providerExists: !!provider,
        });
      }
    } catch (err) {
      // eth_accounts failure is unusual — log so we don't swallow the
      // signal silently. Fall through with empty list so the existing
      // "No usable signers" error fires (which the dApp gets to see).
      permissionLog.warn("eth_accounts failed during acquire", describeError(err));
    }
    if (accounts.length === 0) {
      permissionLog.error("no usable signers", { origin });
      throw { code: -32603, message: "No usable signers — open Settings first" };
    }
    const perm: OriginPermission = {
      accounts: accounts.map((a) => a.toLowerCase()),
      chainId: getChainForOrigin(origin) || cachedConfig.selectedChain || 1,
      grantedAt: Date.now(),
    };
    await setPermissionForOrigin(origin, perm);
    permissionLog.info("granted", { origin, accountCount: perm.accounts.length });
    return perm;
  }
  return requestConnectFromUser(origin, getChainForOrigin(origin));
}

async function requestConnectFromUser(
  origin: string,
  suggestedChainId: number
): Promise<OriginPermission> {
  return new Promise<OriginPermission>((resolve, reject) => {
    const requestId = connectRequestId();
    const timeoutHandle = setTimeout(() => {
      if (pendingConnects.has(requestId)) {
        pendingConnects.delete(requestId);
        reject({ code: 4001, message: "Connect request timed out" });
      }
    }, 5 * 60 * 1000);
    pendingConnects.set(requestId, { origin, resolve, reject, timeoutHandle });
    void openConnectWindow(origin, requestId, suggestedChainId);
  });
}

async function handleConnectApprove(msg: {
  requestId: string;
  accounts: string[];
  chainId: number;
}): Promise<{ ok: boolean; error?: string }> {
  const pending = pendingConnects.get(msg.requestId);
  if (!pending) return { ok: false, error: "Unknown or expired request" };
  if (!Array.isArray(msg.accounts) || msg.accounts.length === 0) {
    return { ok: false, error: "Must grant at least one account" };
  }
  clearTimeout(pending.timeoutHandle);
  pendingConnects.delete(msg.requestId);
  const perm: OriginPermission = {
    accounts: msg.accounts.map((a) => a.toLowerCase()),
    chainId: msg.chainId,
    grantedAt: Date.now(),
  };
  await setPermissionForOrigin(pending.origin, perm);
  pending.resolve(perm);
  return { ok: true };
}

async function handleConnectReject(msg: { requestId: string }): Promise<{ ok: boolean }> {
  const pending = pendingConnects.get(msg.requestId);
  if (!pending) return { ok: false };
  clearTimeout(pending.timeoutHandle);
  pendingConnects.delete(msg.requestId);
  pending.reject({ code: 4001, message: "User rejected the connection request" });
  return { ok: true };
}

// Read-only IPC the Connect popup uses to render: the list of usable
// signers (so the user knows what they're about to grant access to),
// the popup-default chain (as a hint for the chain picker), and the
// origin/requestId echoed back for confirmation.
async function handleConnectGetContext(msg: { requestId: string }): Promise<{
  ok: boolean;
  origin?: string;
  suggestedChainId?: number;
  defaultChainId?: number;
  signers?: Array<{ address: string; locked?: boolean; enabled?: boolean }>;
  chains?: Array<{ chainId: number; chainName?: string }>;
  error?: string;
}> {
  const pending = pendingConnects.get(msg.requestId);
  if (!pending) return { ok: false, error: "Unknown or expired request" };
  await ensureInit();
  // Same live-refresh contract as the auto-approve path: a signer
  // unlocked from CLI between init and the Connect popup opening should
  // appear in the picker without an extension reload.
  await refreshSignersIgnoringErrors();
  let signers: Array<{ address: string; locked?: boolean; enabled?: boolean }> = [];
  try {
    if (provider && provider.isConnected()) {
      const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
      signers = accounts.map((address) => ({ address, locked: false, enabled: true }));
    }
  } catch {
    /* best-effort: caller may proceed without the rich list */
  }
  const chains = Array.from(chainRegistry.values()).map((c) => ({
    chainId: c.chainId,
    chainName: c.chainName,
  }));
  return {
    ok: true,
    origin: pending.origin,
    suggestedChainId: cachedConfig.selectedChain || 1,
    defaultChainId: cachedConfig.selectedChain || 1,
    signers,
    chains,
  };
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
    initLog.error("failed to register content script", describeError(e));
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
      initLog.error("CSP bypass injection failed", describeError(e));
    }
  }
});

// ── Provider Initialization ──────────────────────────────────────────────

async function initProvider(): Promise<void> {
  const cfg = await loadConfig();

  if (!cfg.apiKeyPrivateKey) {
    initError =
      "API key not configured. Open extension popup to configure.";
    initLog.warn(initError);
    return;
  }

  if (!cfg.apiKeyId) {
    initError =
      "API key ID not configured. Open extension popup to configure.";
    initLog.warn(initError);
    return;
  }

  initLog.info("initializing provider", {
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

  // When a sign request enters the manual-approval queue, the dApp's
  // call hangs while the SDK polls. Without surfacing anything to the
  // user, they often don't realise an admin action is needed — Polymarket
  // / wagmi / similar then time out client-side and the user sees a
  // generic "Request Cancelled". Pop up a small floating window with
  // the request summary + a button that jumps to the management page.
  client.evm.sign.onPendingApproval = (requestId, ctx) => {
    void openPendingApprovalWindow({
      requestId,
      signType: ctx.signRequest.sign_type,
      signerAddress: ctx.signRequest.signer_address,
      chainId: ctx.signRequest.chain_id,
      remoteSignerUrl: cfg.remoteSignerUrl,
    });
  };

  // Auto-fetch signers from backend. The SDK owns chainId + activeAddress
  // persistence via the `storage` adapter — on each create() it rehydrates
  // from chrome.storage.local, on each state-changing event it writes back.
  // No state-mirroring listeners live in this file any more.
  provider = await EIP1193Provider.create({
    signersSource: { type: "client", client, chainId: cfg.selectedChain },
    defaultChainId: cfg.selectedChain,
    // Read methods + signed-tx broadcast route through the daemon's
    // /api/v1/evm/rpc/{chainId} proxy via `client.evm.rpcProxy`. The
    // provider picks the client up from signersSource automatically,
    // so no rpcOverrides / rpcResolver config — the daemon's
    // rpc_gateway is the single source of upstream RPC configuration.
    storage: chromeStorageAdapter,
    storageKey: providerStorageKey(cfg.apiKeyId),
  });

  // Migration path for users upgrading from versions that stored the
  // active signer in `cachedConfig.activeSignerAddress` rather than the
  // SDK's own storage namespace. On first run after upgrade the SDK's
  // namespace is empty, so we replay the legacy value through
  // switchAccount() — which the SDK then persists into its own slot, so
  // subsequent reads come from the canonical source.
  if (
    cfg.activeSignerAddress &&
    provider.isConnected() &&
    provider.selectedAddress?.toLowerCase() !== cfg.activeSignerAddress.toLowerCase()
  ) {
    try {
      await provider.switchAccount(cfg.activeSignerAddress);
    } catch (err) {
      initLog.warn("stored active signer no longer usable", {
        activeSignerAddress: cfg.activeSignerAddress,
        ...describeError(err),
      });
      cfg.activeSignerAddress = undefined;
      await saveConfig(cfg);
    }
  }

  initLog.info("provider ready", {
    connected: provider.isConnected(),
    activeAccount: provider.selectedAddress,
    chainId: provider.chainId,
  });

  // Forward provider events to all tabs so dApps see them.
  //
  // `chainChanged` is intentionally NOT forwarded globally: chain state
  // is per-origin (see broadcastEventToOrigin in wallet_switchEthereumChain),
  // so a switch driven by one dApp must NOT ripple into other open dApp
  // tabs. The popup's chain-chip change still propagates because the
  // popup goes through its own dedicated message path.
  const events = ["accountsChanged", "connect", "disconnect"];
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
      initLog.error("provider init failed", describeError(err));
    });
  }
  return initPromise;
}

// In-flight de-dupe: concurrent dApp requests (Polymarket fires
// eth_chainId + eth_requestAccounts + eth_accounts back-to-back) should
// share one refresh round-trip, not stampede the daemon.
let pendingSignerRefresh: Promise<void> | null = null;

// Time-based cooldown: even after in-flight de-dupe, firing a
// /signers fetch on *every* dApp call is a 5x amplifier (Uniswap
// hammers ~20 reads / sec during a swap and we'd issue 20 refreshes
// in lockstep). 5s window covers the realistic case ("CLI just
// unlocked a signer") without burning the agent's rate-limit budget.
const SIGNER_REFRESH_COOLDOWN_MS = 5_000;
let lastSignerRefreshAt = 0;

// Pull a fresh signer list from the daemon and swap it into the
// provider, so dApp-visible accounts + signing routes always reflect
// current daemon truth. Best-effort — a transient daemon hiccup
// shouldn't break the dApp; the next request will retry.
async function refreshSignersIgnoringErrors(): Promise<void> {
  if (!provider) return;
  if (pendingSignerRefresh) return pendingSignerRefresh;
  const now = Date.now();
  if (now - lastSignerRefreshAt < SIGNER_REFRESH_COOLDOWN_MS) {
    return; // honored a refresh recently, skip
  }
  const t0 = now;
  pendingSignerRefresh = (async () => {
    try {
      await provider!.refreshSigners();
      lastSignerRefreshAt = Date.now();
      refreshLog.debug("refresh ok", { durMs: Date.now() - t0 });
    } catch (err) {
      refreshLog.warn("refresh failed", {
        durMs: Date.now() - t0,
        ...describeError(err),
      });
    } finally {
      pendingSignerRefresh = null;
    }
  })();
  return pendingSignerRefresh;
}

// ── Pending Approval Window ──────────────────────────────────────────────

// Track the currently-open pending-approval window so we don't spawn a
// new one for every concurrent sign request. The SW may suspend between
// requests, so we also check chrome.windows for liveness on each call.
let pendingApprovalWindowId: number | null = null;

interface PendingApprovalContext {
  requestId: string;
  signType: string;
  signerAddress: string;
  chainId: string;
  remoteSignerUrl: string;
}

async function openPendingApprovalWindow(ctx: PendingApprovalContext): Promise<void> {
  // Always bump the badge so even if the window is missed (window-creation
  // denied, popup blocker, etc.) the user has a visible cue.
  try {
    await chrome.action.setBadgeText({ text: "!" });
    await chrome.action.setBadgeBackgroundColor({ color: "#E48A2C" });
  } catch {
    /* badge is best-effort */
  }

  const params = new URLSearchParams({
    requestId: ctx.requestId,
    signType: ctx.signType,
    signerAddress: ctx.signerAddress,
    chainId: ctx.chainId,
    remoteSignerUrl: ctx.remoteSignerUrl,
  });
  const popupUrl = chrome.runtime.getURL(`popup/pending.html?${params.toString()}`);

  // If a previous pending window is still around, just focus it instead
  // of stacking yet another one. The pending UI itself shows the most
  // recent request and polls for completion of all live ones.
  if (pendingApprovalWindowId != null) {
    try {
      const win = await chrome.windows.get(pendingApprovalWindowId);
      if (win) {
        await chrome.windows.update(pendingApprovalWindowId, { focused: true });
        // Re-navigate the popup to the new request (the script reads URL params).
        const tabs = await chrome.tabs.query({ windowId: pendingApprovalWindowId });
        const tabId = tabs[0]?.id;
        if (tabId != null) await chrome.tabs.update(tabId, { url: popupUrl });
        return;
      }
    } catch {
      // Window no longer exists — fall through and create a fresh one.
      pendingApprovalWindowId = null;
    }
  }

  try {
    const win = await chrome.windows.create({
      url: popupUrl,
      type: "popup",
      width: 380,
      height: 520,
      focused: true,
    });
    pendingApprovalWindowId = win.id ?? null;
  } catch (err) {
    approvalLog.error("failed to open pending-approval window", describeError(err));
  }
}

async function clearPendingApprovalBadge(): Promise<void> {
  try {
    await chrome.action.setBadgeText({ text: "" });
  } catch {
    /* ignore */
  }
}

// Forget the window id when the user closes it so the next pending
// request creates a fresh window instead of trying to focus a dead one.
chrome.windows?.onRemoved?.addListener?.((windowId) => {
  if (windowId === pendingApprovalWindowId) {
    pendingApprovalWindowId = null;
  }
});

// ── Event Broadcasting ───────────────────────────────────────────────────

async function broadcastEventToOrigin(origin: string, event: string, data: unknown) {
  // Per-origin broadcast: only tabs whose page is on `origin` get the
  // event. Used for chainChanged after wallet_switchEthereumChain, so a
  // switch on polymarket.com doesn't ripple into an unrelated Uniswap
  // tab and trip ITS wagmi's chain check.
  try {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab.id == null || !tab.url) continue;
      try {
        if (new URL(tab.url).origin !== origin) continue;
      } catch {
        continue;
      }
      chrome.tabs
        .sendMessage(tab.id, { type: "web3-eip1193-event", event, data })
        .catch(() => {});
    }
  } catch {}
}

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
 * Forward a JSON-RPC call through the daemon's wallet RPC proxy.
 *
 * Covers the methods the SDK's switch doesn't enumerate
 * (eth_maxPriorityFeePerGas, eth_feeHistory, eth_getProof, …) and
 * eth_sendRawTransaction. The proxy enforces a method allowlist
 * server-side — sign methods are blocked there too, so a future
 * caller can't accidentally widen the surface from here.
 */
async function forwardToRpc(
  method: string,
  params: unknown
): Promise<{ result?: unknown; error?: RpcError }> {
  if (!client) {
    return {
      error: { code: -32603, message: "Provider not initialized — open Settings first" },
    };
  }
  const chainId = provider ? parseInt(provider.chainId, 16) : 1;
  try {
    const result = await client.evm.rpcProxy.call(
      chainId,
      method,
      Array.isArray(params) ? params : [],
    );
    return { result };
  } catch (err: any) {
    return { error: { code: -32603, message: err?.message || String(err) } };
  }
}

/**
 * Handle a wallet_addEthereumChain call (EIP-3085).
 *
 * Pre-refactor we stored the dApp-supplied rpcUrls and used them for
 * read/broadcast traffic. With the daemon proxy that's no longer
 * appropriate — the operator's daemon decides which upstream serves
 * each chain, not whichever URL the dApp suggested. We still record
 * the chain metadata (name + native currency) so the popup can show
 * a sensible label, but rpcUrls is ignored. If the daemon doesn't
 * have an upstream configured for the chain, the next eth_* call
 * returns the proxy's "no upstream for chain X" error — which is
 * the right place to surface that configuration gap.
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
  // If the chain is already in our registry, return null (per spec).
  if (chainRegistry.has(chainId)) return { result: null };
  chainRegistry.set(chainId, {
    chainId,
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
  msg: EIP1193Request,
  origin: string | null
): Promise<{ handled: false } | { handled: true; result?: unknown; error?: RpcError }> {
  const { method, params } = msg;

  switch (method) {
    // ── Chain identity (per-origin) ───────────────────────────────────────
    // Return the chain THIS origin last used, not a global state. dApps
    // like Polymarket (Polygon) and Uniswap (Mainnet) can run concurrently
    // without the extension forcing them onto a single chain.
    case "eth_chainId":
    case "net_version": {
      const chainId = getChainForOrigin(origin);
      return {
        handled: true,
        result: method === "net_version" ? String(chainId) : `0x${chainId.toString(16)}`,
      };
    }

    // ── Legacy / informational ─────────────────────────────────────────────
    case "web3_clientVersion":
      return { handled: true, result: CLIENT_VERSION_STRING };
    case "net_listening":
      return { handled: true, result: true };
    case "net_peerCount":
      return { handled: true, result: "0x0" };

    // ── Accounts / permissions (EIP-1102 / EIP-2255) ───────────────────────
    case "eth_accounts": {
      // EIP-1102: silent read of the *already-granted* account list. An
      // origin with no permission record gets []. dApps then call
      // eth_requestAccounts to trigger the Connect prompt.
      const perm = getPermissionForOrigin(origin);
      return { handled: true, result: perm ? perm.accounts : [] };
    }

    case "eth_requestAccounts": {
      const existing = getPermissionForOrigin(origin);
      if (existing) {
        return { handled: true, result: existing.accounts };
      }
      if (!origin) {
        // No origin — popup or extension-internal caller. Fall through
        // to the SDK provider's default (which honours the active signer).
        return { handled: false };
      }
      try {
        const perm = await acquirePermission(origin);
        broadcastEventToOrigin(origin, "accountsChanged", perm.accounts);
        broadcastEventToOrigin(origin, "chainChanged", `0x${perm.chainId.toString(16)}`);
        return { handled: true, result: perm.accounts };
      } catch (err: any) {
        return {
          handled: true,
          error: { code: err?.code ?? 4001, message: err?.message ?? "User rejected the request" },
        };
      }
    }

    case "wallet_requestPermissions": {
      // EIP-2255 shape: dApps usually pass [{ eth_accounts: {} }]. Treat
      // any incoming request as "give me eth_accounts" — we don't yet
      // support snap/endowment permissions. The Connect prompt is shared
      // with eth_requestAccounts (and auto-approved when the toggle is on).
      let perm = getPermissionForOrigin(origin);
      if (!perm) {
        if (!origin) return { handled: false };
        try {
          perm = await acquirePermission(origin);
        } catch (err: any) {
          return {
            handled: true,
            error: { code: err?.code ?? 4001, message: err?.message ?? "User rejected the request" },
          };
        }
      }
      broadcastEventToOrigin(origin || "", "accountsChanged", perm.accounts);
      return {
        handled: true,
        result: [
          {
            parentCapability: "eth_accounts",
            caveats: [{ type: "restrictReturnedAccounts", value: perm.accounts }],
            date: perm.grantedAt,
            id: `perm-${perm.grantedAt}`,
            invoker: origin || "unknown",
          },
        ],
      };
    }

    case "wallet_getPermissions": {
      const perm = getPermissionForOrigin(origin);
      if (!perm) return { handled: true, result: [] };
      return {
        handled: true,
        result: [
          {
            parentCapability: "eth_accounts",
            caveats: [{ type: "restrictReturnedAccounts", value: perm.accounts }],
            date: perm.grantedAt,
            id: `perm-${perm.grantedAt}`,
            invoker: origin,
          },
        ],
      };
    }

    case "wallet_revokePermissions": {
      if (origin) await revokePermissionForOrigin(origin);
      return { handled: true, result: null };
    }

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
      // Persist this dApp's chain choice. Only THIS origin's view changes;
      // other open dApps keep whatever chain they were on. Then notify the
      // origin's own tabs via a scoped chainChanged so wagmi/viem update
      // their connector cache without confusing concurrent dApps.
      if (origin) {
        await setChainForOrigin(origin, chainId);
        broadcastEventToOrigin(origin, "chainChanged", chainIdHex.toLowerCase());
      }
      // We intentionally do NOT delegate to the SDK's wallet_switchEthereumChain
      // here — that would mutate the SDK's single global chainId and leak
      // the switch to every other open dApp. Per-origin scoping is the
      // whole point of this refactor.
      return { handled: true, result: null };
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

async function handleEIP1193Request(msg: EIP1193Request, origin: string | null) {
  await ensureInit();
  await ensureChainByOriginLoaded();
  await ensurePermittedOriginsLoaded();

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

  // Best-effort live refresh so dApp-visible state (eth_accounts, signing
  // routes) reflects daemon truth without forcing extension reload after
  // CLI signer add/unlock. Errors are swallowed — if the daemon is briefly
  // unreachable, the cached list is still usable for already-granted
  // permissions; the real network error will surface on the actual call.
  await refreshSignersIgnoringErrors();

  // Entry trace — every dApp method that reaches the SW is logged with
  // enough context (method, origin, param count) to reconstruct the
  // sequence post-mortem without dumping potentially-huge param
  // payloads (typed-data blobs, signed-tx bytes).
  dispatchLog.info("dApp request", {
    method: msg.method,
    origin,
    paramsLen: Array.isArray(msg.params) ? msg.params.length : 0,
    id: msg.id,
  });

  // Pre-SDK dispatch for MetaMask-compatible methods the SDK doesn't cover.
  const extra = await tryHandleExtraMethod(msg, origin);
  if (extra.handled) {
    if (extra.error) {
      dispatchLog.warn("extra-dispatch error", {
        method: msg.method,
        id: msg.id,
        error: extra.error,
      });
      return { type: "web3-eip1193-response", id: msg.id, error: extra.error };
    }
    dispatchLog.debug("extra-dispatch result", { method: msg.method, id: msg.id });
    return { type: "web3-eip1193-response", id: msg.id, result: extra.result };
  }

  // Methods that carry their own chainId in the request (sendTransaction
  // tx.chainId, signTypedData_v4 domain.chainId) are honored by the
  // backend regardless of the SDK's global chain state — so multi-chain
  // signing already works at the gateway layer. personal_sign and
  // eth_sign are chain-agnostic at the cryptographic level. The
  // remaining "current chain" use is for the dApp's own eth_chainId
  // queries, which the per-origin pre-SDK dispatch already handles.
  try {
    const result = await provider.request({
      method: msg.method,
      params: msg.params,
    });
    dispatchLog.debug("sdk result", { method: msg.method, id: msg.id });
    return {
      type: "web3-eip1193-response",
      id: msg.id,
      result,
    };
  } catch (err: any) {
    dispatchLog.error("sdk error", {
      method: msg.method,
      id: msg.id,
      ...describeError(err),
    });
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

async function handleGetState(id: string, origin: string | null) {
  await ensureInit();
  await ensureChainByOriginLoaded();
  await ensurePermittedOriginsLoaded();

  // Accounts are gated by per-origin permissions (EIP-1102). A dApp page
  // loading fresh — before it has called eth_requestAccounts — should see
  // accounts=[] so its connector knows to ask for permission.
  const perm = getPermissionForOrigin(origin);
  const accounts = perm ? perm.accounts : [];
  const chainId = `0x${(getChainForOrigin(origin)).toString(16)}`;

  if (!provider) {
    return {
      type: "web3-state-response",
      id,
      accounts,
      chainId,
      isConnected: false,
    };
  }

  return {
    type: "web3-state-response",
    id,
    accounts,
    chainId,
    isConnected: provider.isConnected() && accounts.length > 0,
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
 * Decrypts an EnhancedKeyFile keystore JSON for the popup. Returns the
 * 32-byte Ed25519 seed as a lowercase hex string (no 0x prefix) — the
 * format the popup already understands for plaintext key imports. On
 * wrong password we surface the literal "wrong password" so the popup
 * UI can render a clean error without leaking which MAC byte mismatched.
 */
async function handlePopupDecryptKeystore(msg: PopupDecryptKeystore) {
  try {
    const seed = await decryptKeystore(msg.json, msg.password);
    return {
      type: "popup:keystoreDecrypted",
      ok: true,
      privateKeyHex: bytesToHex(seed),
    };
  } catch (err: any) {
    return {
      type: "popup:keystoreDecrypted",
      ok: false,
      error: err?.message || String(err),
    };
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
  await ensurePermittedOriginsLoaded();
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

  // Popup-driven account switch is a wallet-wide intent: "this is now my
  // active signer everywhere." Push the new active to the front of every
  // granted origin's account list, then re-broadcast accountsChanged so
  // connected dApps observe the switch. This matches MetaMask's behaviour
  // when the user picks an account from the global UI.
  const newActive = msg.address.toLowerCase();
  for (const [origin, perm] of Object.entries(permittedOrigins)) {
    const others = perm.accounts.filter((a) => a !== newActive);
    permittedOrigins[origin] = { ...perm, accounts: [newActive, ...others] };
    broadcastEventToOrigin(origin, "accountsChanged", permittedOrigins[origin].accounts);
  }
  await persistPermittedOrigins();

  return { type: "popup:accountSwitched", ok: true, address: provider.selectedAddress };
}

// ── Main Message Handler ─────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (message: IncomingMessage, sender, sendResponse) => {
    // ── EIP-1193 ──────────────────────────────────────────────────────
    if (message.type === "web3-eip1193-request") {
      // Tab-scoped sender → origin. The popup speaks via chrome.runtime
      // (no tab), so origin is null for those messages — per-origin
      // chain only applies to real dApp pages.
      const origin = normalizeOrigin(sender.tab?.url ?? sender.url);
      handleEIP1193Request(message, origin)
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
      const origin = normalizeOrigin(sender.tab?.url ?? sender.url);
      handleGetState(message.id, origin)
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

    if (message.type === "popup:decryptKeystore") {
      handlePopupDecryptKeystore(message).then(sendResponse);
      return true;
    }

    // ── Connect popup IPCs ────────────────────────────────────────────
    if ((message as any).type === "connect:getContext") {
      handleConnectGetContext(message as any).then(sendResponse);
      return true;
    }
    if ((message as any).type === "connect:approve") {
      handleConnectApprove(message as any).then(sendResponse);
      return true;
    }
    if ((message as any).type === "connect:reject") {
      handleConnectReject(message as any).then(sendResponse);
      return true;
    }

    return false;
  }
);

// Lazy init: only create the provider when a dApp actually requests it.
// Config is loaded on-demand from chrome.storage.local.
