import { SignError } from "remote-signer-client";
import { adminSDKClient, expect, test } from "./fixtures";

// Full approval round-trip:
//   1. Admin SDK creates a keystore signer.
//   2. Admin issues an async personal_sign — daemon parks it as `pending`
//      (security.manual_approval_enabled is true in the test config so
//      unmatched requests don't 403).
//   3. UI navigates to /requests, finds the row, clicks Approve.
//   4. Verify via SDK that status flipped to `completed`.
//
// Seeded via the SDK because creating a real keystore signer is heavier
// than what a UI-form-driven spec should bear; the focus here is the
// approval flow itself.

test("approve a pending request via the UI completes it", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();

  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-approve-pw" },
  });

  // The SDK throws SignError when executeAsync returns a non-completed
  // status — including the "pending" we want. Catch and pull the
  // request_id off the error so the spec can drive the approval flow.
  let requestId = "";
  try {
    const r = await c.evm.sign.executeAsync({
      chain_id: "1",
      signer_address: signer.address,
      sign_type: "personal",
      payload: { message: "0x48656c6c6f" }, // "Hello"
    });
    requestId = r.request_id;
  } catch (e) {
    if (!(e instanceof SignError)) throw e;
    expect(["pending", "authorizing"]).toContain(e.status);
    requestId = e.requestID;
  }
  expect(requestId).toBeTruthy();

  await authedPage.click("text=Requests");
  // List defaults to "all" so pending + authorizing both show without
  // changing filters. Rows show the shortened signer address (head=10,
  // tail=6) — match on the head fragment which is unique enough across
  // a single test run, and use the inline Approve button rather than
  // navigating to the detail page.
  const shortPrefix = signer.address.slice(0, 10);
  const row = authedPage.locator("tr", {
    has: authedPage.locator(`text=${shortPrefix}`),
  });
  await expect(row).toBeVisible({ timeout: 10_000 });
  await row.getByRole("button", { name: "Approve" }).click();

  // The row's status badge flips off pending/authorizing once approval
  // lands. Cross-check via the SDK that the request is no longer waiting
  // for a human — completed or actively signing are both fine.
  await expect
    .poll(async () => (await c.evm.requests.get(requestId)).status, {
      timeout: 10_000,
    })
    .not.toMatch(/^(pending|authorizing)$/);

  const finalState = await c.evm.requests.get(requestId);
  expect(["completed", "signing"]).toContain(finalState.status);
});
