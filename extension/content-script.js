/**
 * Content script: bidirectional relay between MAIN world (inpage.js) and
 * background service worker (background.js).
 *
 * Runs at document_start in ISOLATED world.
 *
 * MAIN world ←→ content-script ←→ background.js
 * (postMessage)                (chrome.runtime)
 */

console.log("[content-script] Starting in ISOLATED world");

// Mark that content-script is loaded (readable from MAIN world via DOM)
document.documentElement.setAttribute("data-web3-agent-cs", "loaded");

// ── MAIN world → background (EIP-1193 requests + state queries) ─────────
window.addEventListener("message", (event) => {
  const data = event.data;
  if (!data || typeof data !== "object") return;

  // EIP-1193 request relay
  if (data.type === "web3-eip1193-request" && data.id) {
    chrome.runtime.sendMessage(
      {
        type: "web3-eip1193-request",
        id: data.id,
        method: data.method,
        params: data.params,
      },
      (response) => {
        if (chrome.runtime.lastError) {
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
        window.postMessage(response, "*");
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
    window.postMessage(message, "*");
  }
});

console.log("[content-script] EIP-1193 relay registered");

// ── Inject inpage.js into MAIN world ────────────────────────────────────
const inpageScript = document.createElement("script");
inpageScript.src = chrome.runtime.getURL("inpage.js");
inpageScript.onload = () => {
  inpageScript.remove();
  console.log("[content-script] inpage.js injected");
};
(document.head || document.documentElement).appendChild(inpageScript);
