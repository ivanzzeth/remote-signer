/**
 * Content script: bidirectional relay between MAIN world (inpage.js) and
 * background service worker (background.js).
 *
 * Runs at document_start in ISOLATED world.
 *
 * MAIN world ←→ content-script ←→ background.js
 * (postMessage)                (chrome.runtime)
 *
 * Logging mirrors extension/src/logger.ts so the dApp → SW relay shows
 * up in the *page* DevTools console with the same shape ("[ts] [level]
 * [content-script] msg {...}") the SW console uses. Level is read from
 * chrome.storage.local under "remote-signer:log-level" (default
 * "info") so a single toggle in the popup flips visibility everywhere.
 */

// ── Logger (mirrors extension/src/logger.ts) ─────────────────────────────
const LOG_LEVEL_RANK = { debug: 0, info: 1, warn: 2, error: 3 };
const LOG_STORAGE_KEY = "remote-signer:log-level";
let __logLevel = "info";

// Forward log level into the MAIN-world inpage script via postMessage —
// inpage can't read chrome.storage itself, so this is the only way it
// learns about a level toggle without an extension reload.
function broadcastLevelToInpage(level) {
  try {
    window.postMessage({ type: "remote-signer:log-level", level }, "*");
  } catch {
    /* page navigation / unloaded — ignore */
  }
}

try {
  chrome.storage?.local.get(LOG_STORAGE_KEY, (r) => {
    const v = r?.[LOG_STORAGE_KEY];
    if (typeof v === "string" && v in LOG_LEVEL_RANK) {
      __logLevel = v;
      broadcastLevelToInpage(v);
    }
  });
  chrome.storage?.onChanged?.addListener?.((changes, area) => {
    if (area !== "local") return;
    const v = changes[LOG_STORAGE_KEY]?.newValue;
    if (typeof v === "string" && v in LOG_LEVEL_RANK) {
      __logLevel = v;
      broadcastLevelToInpage(v);
    }
  });
} catch {
  /* non-extension context — keep default */
}

function logEmit(level, msg, fields) {
  if (LOG_LEVEL_RANK[level] < LOG_LEVEL_RANK[__logLevel]) return;
  const d = new Date();
  const pad = (n, w = 2) => n.toString().padStart(w, "0");
  const ts =
    pad(d.getHours()) +
    ":" +
    pad(d.getMinutes()) +
    ":" +
    pad(d.getSeconds()) +
    "." +
    pad(d.getMilliseconds(), 3);
  const prefix = `[${ts}] [${level}] [content-script] ${msg}`;
  const fn =
    level === "error" ? console.error
    : level === "warn" ? console.warn
    : console.log;
  if (fields && Object.keys(fields).length > 0) fn(prefix, fields);
  else fn(prefix);
}
const log = {
  debug: (m, f) => logEmit("debug", m, f),
  info: (m, f) => logEmit("info", m, f),
  warn: (m, f) => logEmit("warn", m, f),
  error: (m, f) => logEmit("error", m, f),
};

log.info("starting in ISOLATED world");

// Mark that content-script is loaded (readable from MAIN world via DOM)
document.documentElement.setAttribute("data-web3-agent-cs", "loaded");

// ── MAIN world → background (EIP-1193 requests + state queries) ─────────
window.addEventListener("message", (event) => {
  const data = event.data;
  if (!data || typeof data !== "object") return;

  // EIP-1193 request relay
  if (data.type === "web3-eip1193-request" && data.id) {
    log.info("→ background", { method: data.method, id: data.id });
    chrome.runtime.sendMessage(
      {
        type: "web3-eip1193-request",
        id: data.id,
        method: data.method,
        params: data.params,
      },
      (response) => {
        if (chrome.runtime.lastError) {
          log.error("runtime error", {
            method: data.method,
            id: data.id,
            message: chrome.runtime.lastError.message,
          });
          window.postMessage(
            {
              type: "web3-eip1193-response",
              id: data.id,
              error: {
                code: -32603,
                message: chrome.runtime.lastError.message || "Extension communication error",
              },
            },
            "*"
          );
          return;
        }
        if (response && response.error) {
          log.warn("← background error", {
            method: data.method,
            id: data.id,
            error: response.error,
          });
        } else {
          log.debug("← background ok", { method: data.method, id: data.id });
        }
        window.postMessage(response, "*");
      }
    );
    return;
  }

  // Account switch (from popup or headless call)
  if (data.type === "popup:switchAccount" && data.address) {
    chrome.runtime.sendMessage(
      { type: "popup:switchAccount", address: data.address },
      (response) => {
        if (chrome.runtime.lastError) {
          window.postMessage({ ...data, ok: false, error: chrome.runtime.lastError.message }, "*");
          return;
        }
        window.postMessage({ type: "popup:accountSwitched", id: data.id, ...response }, "*");
      }
    );
    return;
  }

  // State query relay
  if (data.type === "web3-get-state" && data.id) {
    chrome.runtime.sendMessage(
      { type: "web3-get-state", id: data.id },
      (response) => {
        if (chrome.runtime.lastError) {
          log.warn("state-query runtime error", {
            id: data.id,
            message: chrome.runtime.lastError.message,
          });
          window.postMessage(
            {
              type: "web3-state-response",
              id: data.id,
              accounts: [],
              chainId: "0x1",
              isConnected: false,
            },
            "*"
          );
          return;
        }
        window.postMessage(response, "*");
      }
    );
    return;
  }
});

// ── background → MAIN world (provider events) ──────────────────────────
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "web3-eip1193-event") {
    log.debug("provider event → MAIN", { event: message.event });
    window.postMessage(message, "*");
  }
});

log.info("EIP-1193 relay registered");

// ── Inject inpage.js into MAIN world ────────────────────────────────────
const inpageScript = document.createElement("script");
inpageScript.src = chrome.runtime.getURL("inpage.js");
inpageScript.onload = () => {
  inpageScript.remove();
  log.info("inpage.js injected");
  // Push the current level once inpage is alive — the addEventListener
  // bridge installed there is now ready to receive it, so the page
  // console starts off at the configured level instead of the inpage
  // default.
  broadcastLevelToInpage(__logLevel);
};
(document.head || document.documentElement).appendChild(inpageScript);
