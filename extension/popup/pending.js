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
