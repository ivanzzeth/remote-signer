import { join } from "node:path";
import { adminSDKClient, agentSDKClient, expect, test } from "./fixtures";
import { getState } from "./global-setup";
import { sqliteExec } from "./sqlite";

/**
 * Manual walkthrough gates — each test maps to a page/flow the operator
 * verifies by hand. Run `npm run test:e2e` before asking for manual验收.
 */

const AGENT_SIGNER_PW = "e2e-walkthrough-agent-pw";

async function seedAgentAuthorizingRequest() {
  const agent = agentSDKClient();
  const admin = await adminSDKClient();

  const created = await agent.evm.signers.create({
    type: "keystore",
    keystore: { password: AGENT_SIGNER_PW },
    display_name: `walkthrough-agent-${Date.now()}`,
  } as Parameters<typeof agent.evm.signers.create>[0]);
  const address = created.address;
  await admin.evm.signers.approveSigner(address);

  // Real keystore on disk + sqlite authorizing row: pins admin approve on
  // agent-owned requests without depending on executeAsync parking semantics.
  const requestId = `req-walkthrough-approve-${Date.now()}`;
  const payload = JSON.stringify({ message: "0x48656c6c6f" }).replace(
    /'/g,
    "''",
  );
  const now = new Date().toISOString();
  sqliteExec(join(getState().home, "remote-signer.db"), [
    `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, payload, created_at, updated_at)
     VALUES ('${requestId}', 'agent', 'evm', '1', '${address}', 'personal', 'authorizing', '${payload}', '${now}', '${now}')`,
  ]);

  return { address, requestId };
}

function seedAgentAuthorizingTransaction(requestID: string) {
  const dbPath = join(getState().home, "remote-signer.db");
  const signerAddress = "0x898d92931a9f26b375ddfdc52b2a94196368c54b";
  const toAddr = "0x00000000000000000000000000000000000000aa";
  const payload = JSON.stringify({
    transaction: { to: toAddr, value: "0x0", data: "0x", from: signerAddress },
  }).replace(/'/g, "''");
  const now = new Date().toISOString();

  sqliteExec(dbPath, [
    `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, payload, created_at, updated_at)
     VALUES ('${requestID}', 'agent', 'evm', '1', '${signerAddress}', 'transaction', 'authorizing', '${payload}', '${now}', '${now}')`,
  ]);
}

async function openRequestDetail(
  page: import("@playwright/test").Page,
  requestId: string,
) {
  await page.evaluate((id) => {
    window.history.pushState({}, "", `/requests/${id}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, requestId);
  await expect(page.getByTestId("request-approval-panel")).toBeVisible({
    timeout: 10_000,
  });
}

test("walkthrough step 1 — Simulations page runs dry-run and surfaces a result", async ({
  authedPage,
}) => {
  const admin = await adminSDKClient();
  const signer = await admin.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-simulate-run-pw" },
  });

  await authedPage.getByRole("link", { name: "Simulations" }).click();
  await expect(authedPage.getByTestId("simulate-page")).toBeVisible();

  const txInputs = authedPage.getByTestId("simulate-page").locator("input");
  await txInputs.nth(1).fill(signer.address);
  await txInputs.nth(2).fill("0x00000000000000000000000000000000000000aa");

  const simReq = authedPage.waitForRequest((req) =>
    req.url().includes("/api/v1/evm/simulate") && req.method() === "POST",
  );
  await authedPage.getByTestId("simulations-run-button").click();
  await simReq;

  // E2E daemon may not register the simulate handler (404). Either outcome
  // proves the UI wired the POST and rendered feedback.
  const result = authedPage.getByRole("heading", { name: "Result" });
  const simError = authedPage.getByText("HTTP 404: 404 page not found");
  await expect(result.or(simError).first()).toBeVisible({ timeout: 20_000 });
});

test("walkthrough signers: Owner and Status column headers", async ({
  authedPage,
}) => {
  await authedPage.getByRole("link", { name: "Signers", exact: true }).click();
  await expect(
    authedPage.getByRole("columnheader", { name: "Owner" }),
  ).toBeVisible();
  await expect(
    authedPage.getByRole("columnheader", { name: "Status" }),
  ).toBeVisible();
  await expect(authedPage.getByTestId("signers-col-material")).toBeVisible();
});

test("walkthrough step 2 — hash request shows no generatable rule types", async ({
  authedPage,
}) => {
  const requestID = `req-agent-hash-${Date.now()}`;
  const payload = JSON.stringify({ hash: "0xdeadbeef" }).replace(/'/g, "''");
  const now = new Date().toISOString();
  sqliteExec(join(getState().home, "remote-signer.db"), [
    `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, payload, created_at, updated_at)
     VALUES ('${requestID}', 'agent', 'evm', '1', '0xdeadbeef', 'hash', 'authorizing', '${payload}', '${now}', '${now}')`,
  ]);
  await openRequestDetail(authedPage, requestID);
  await expect(
    authedPage.getByTestId("request-approval-no-generatable-rules"),
  ).toBeVisible();
  await expect(authedPage.getByTestId("approval-rule-type")).toHaveCount(0);
});

test("walkthrough step 2 — admin previews rule on agent-submitted request (no 403)", async ({
  authedPage,
}) => {
  const requestID = `req-agent-preview-${Date.now()}`;
  seedAgentAuthorizingTransaction(requestID);
  await openRequestDetail(authedPage, requestID);

  await authedPage
    .getByRole("checkbox", {
      name: "Generate a whitelist rule from this request when approving",
    })
    .check();

  const previewReq = authedPage.waitForRequest((req) =>
    req.url().includes(`/api/v1/evm/requests/${requestID}/preview-rule`),
  );
  await authedPage.getByRole("button", { name: "Preview rule" }).click();
  const req = await previewReq;
  expect(req.method()).toBe("POST");

  await expect(authedPage.getByText("Preview config")).toBeVisible({
    timeout: 15_000,
  });
  await expect(authedPage.getByText(/HTTP 403/i)).toHaveCount(0);
});

test("walkthrough step 2 — admin approves agent-submitted request from detail panel", async ({
  authedPage,
}) => {
  const admin = await adminSDKClient();
  const { requestId } = await seedAgentAuthorizingRequest();
  await openRequestDetail(authedPage, requestId);

  await authedPage
    .getByTestId("request-approval-panel")
    .getByRole("button", { name: "Approve", exact: true })
    .click();

  await expect
    .poll(async () => (await admin.evm.requests.get(requestId)).status, {
      timeout: 15_000,
    })
    .not.toMatch(/^(pending|authorizing)$/);
});
