/**
 * Pending-approval window. Opened by chrome.windows.create() from the
 * service worker when a sign request lands in pending/authorizing.
 *
 * URL params (read directly from location.search):
 *   - requestId        the SignRequest ID the user needs to approve
 *   - signType         "personal" | "typed_data" | "transaction" | …
 *   - signerAddress    requester's signer (informational)
 *   - chainId          decimal chain id (informational)
 *   - remoteSignerUrl  base URL of the backend; the "Go to manual
 *                      approval" button opens this in a new tab
 */
(function () {
  "use strict";

  const params = new URLSearchParams(window.location.search);
  const requestId = params.get("requestId") || "";
  const signType = params.get("signType") || "";
  const signerAddress = params.get("signerAddress") || "";
  const chainId = params.get("chainId") || "";
  const remoteSignerUrl = (params.get("remoteSignerUrl") || "").replace(/\/$/, "");

  // ── DOM refs ───────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);
  const els = {
    statusPill: $("pendingStatus"),
    statusText: $("pendingStatusText"),
    detailSignType: $("detailSignType"),
    detailSigner: $("detailSigner"),
    detailChain: $("detailChain"),
    detailRequestId: $("detailRequestId"),
    openMgmtBtn: $("openMgmtBtn"),
    closeBtn: $("closeBtn"),
    error: $("pendingError"),
    messagePreviewBlock: $("messagePreviewBlock"),
    messagePreview: $("messagePreview"),
    messageChainWarning: $("messageChainWarning"),
    messageChainWarningText: $("messageChainWarningText"),
    copyMessageBtn: $("copyMessageBtn"),
  };

  // ── Render the request summary ─────────────────────────────────────────
  els.detailSignType.textContent = signType || "—";
  els.detailSigner.textContent = signerAddress
    ? signerAddress.slice(0, 6) + "…" + signerAddress.slice(-4)
    : "—";
  els.detailSigner.title = signerAddress;
  els.detailChain.textContent = chainId ? `Chain ${chainId}` : "—";
  els.detailRequestId.textContent = requestId || "—";
  els.detailRequestId.title = requestId;

  // ── Decoded message preview ────────────────────────────────────────────
  // hex0xToUtf8: dApps using viem/wagmi hex-encode their personal_sign
  // payload (the canonical SIWE shape on the wire). Decode for display so
  // operators read the actual text — without this they can't tell what
  // they're approving (the user-reported Polymarket Chain-ID-mismatch bug
  // was invisible before this preview).
  function hex0xToUtf8(maybeHex) {
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
      return null; // not valid UTF-8 (e.g. random bytes)
    }
  }

  // Pull the SIWE "Chain ID:" line from a decoded message body. Used to
  // surface the most common dApp bug we've seen — the message text says
  // chain X while the request was issued on chain Y (Polymarket 401).
  function extractSiweChainId(messageText) {
    if (typeof messageText !== "string") return null;
    const m = messageText.match(/^\s*Chain ID:\s*(\d+)\s*$/m);
    return m ? parseInt(m[1], 10) : null;
  }

  function renderMessageFromRequest(req) {
    if (!req || !req.payload) return;
    let body = null;
    let copyable = "";
    if (signType === "personal" || signType === "eip191" || signType === "raw_message") {
      const hex = req.payload.message ?? req.payload.raw_message;
      const decoded = hex0xToUtf8(hex);
      body = decoded ?? (typeof hex === "string" ? hex : JSON.stringify(req.payload, null, 2));
      copyable = body;
      const messageChainId = extractSiweChainId(decoded);
      if (messageChainId != null && chainId && messageChainId !== parseInt(chainId, 10)) {
        // Loud warning: this is exactly the Polymarket "Request Cancelled"
        // failure mode the user hit — the dApp baked the wrong chain into
        // the SIWE text so its backend will reject the signature even though
        // the signature itself is valid.
        els.messageChainWarning.classList.remove("hidden");
        els.messageChainWarningText.textContent =
          `SIWE message says Chain ID ${messageChainId} but the request was issued on chain ${chainId}. ` +
          `The dApp's backend will likely reject the signature — switch the wallet to chain ${messageChainId} (in the popup) and have the dApp re-issue.`;
      }
    } else if (signType === "typed_data" && req.payload.typed_data) {
      body = JSON.stringify(req.payload.typed_data, null, 2);
      copyable = body;
    } else if (signType === "transaction" && req.payload.transaction) {
      body = JSON.stringify(req.payload.transaction, null, 2);
      copyable = body;
    } else {
      body = JSON.stringify(req.payload, null, 2);
      copyable = body;
    }
    if (body) {
      els.messagePreview.textContent = body;
      els.messagePreviewBlock.classList.remove("hidden");
      els.copyMessageBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(copyable);
          els.copyMessageBtn.textContent = "Copied";
          setTimeout(() => (els.copyMessageBtn.textContent = "Copy"), 1500);
        } catch {
          /* clipboard may be denied in popup contexts; ignore */
        }
      };
    }
  }

  // ── Open Management ────────────────────────────────────────────────────
  // The admin UI lives at the backend root. The user lands there, finds
  // their request in the pending-approval queue, and clicks approve.
  els.openMgmtBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "popup:openManagement" }, () => {
      // The "Open Management" path opens a new tab via the SW; closing
      // this window after the click keeps the UX tidy.
      setTimeout(() => window.close(), 100);
    });
  });

  els.closeBtn.addEventListener("click", () => {
    window.close();
  });

  // ── Poll the request status ────────────────────────────────────────────
  // Watch the request itself so the window auto-closes once the operator
  // approves (or rejects) — the user doesn't have to remember to dismiss
  // it after they handle things in the admin UI.
  let stopped = false;
  function setStatus(text, cls) {
    els.statusText.textContent = text;
    els.statusPill.className = "pending-status";
    if (cls) els.statusPill.classList.add(cls);
  }

  let renderedMessage = false;
  function pollOnce() {
    if (stopped || !requestId) return;
    chrome.runtime.sendMessage(
      { type: "popup:getRequest", requestId },
      (resp) => {
        if (stopped) return;
        if (!resp || !resp.ok || !resp.request) {
          // Background may have lost the apiKey; show a soft error but
          // keep polling — the user might be configuring it right now.
          els.error.textContent = resp?.error || "Failed to fetch request";
          els.error.classList.remove("hidden");
          scheduleNextPoll();
          return;
        }
        els.error.classList.add("hidden");
        // Render the decoded message exactly once — the payload doesn't
        // change across the request's lifetime, and re-rendering every 2s
        // would clobber the user's scroll position in the preview pane.
        if (!renderedMessage) {
          renderMessageFromRequest(resp.request);
          renderedMessage = true;
        }
        const status = resp.request.status;
        switch (status) {
          case "pending":
          case "authorizing":
            setStatus("Waiting for manual approval", null);
            scheduleNextPoll();
            return;
          case "signing":
            setStatus("Signing…", null);
            scheduleNextPoll();
            return;
          case "completed":
            setStatus("Approved — signature delivered", "is-done");
            stopped = true;
            setTimeout(() => window.close(), 1500);
            return;
          case "rejected":
          case "failed":
            setStatus(
              status === "rejected"
                ? "Rejected by operator"
                : `Failed: ${resp.request.error_message || "unknown error"}`,
              "is-error"
            );
            stopped = true;
            return;
          default:
            setStatus(`Status: ${status}`, null);
            scheduleNextPoll();
        }
      }
    );
  }

  function scheduleNextPoll() {
    if (stopped) return;
    setTimeout(pollOnce, 2000);
  }

  // Kick the first poll immediately so the window doesn't sit on
  // "Waiting" if the request was approved between the SW emitting
  // onPendingApproval and the window finishing render.
  pollOnce();

  // Stop polling on close.
  window.addEventListener("beforeunload", () => {
    stopped = true;
  });
})();
