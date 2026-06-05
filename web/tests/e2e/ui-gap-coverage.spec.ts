import { join } from "node:path";
import { adminSDKClient, acceptConfirm, expect, test } from "./fixtures";
import { getState } from "./global-setup";
import { sqliteExec } from "./sqlite";

/**
 * E2E coverage for the UI-gap work: new pages/panels, filters, RBAC nav,
 * and dashboard signals added in the web UI refresh.
 */

test("Dashboard shows sign request queue + full security block", async ({
  authedPage,
}) => {
  await expect(
    authedPage.getByTestId("dashboard-request-queue"),
  ).toBeVisible();
  await expect(authedPage.getByText("Pending")).toBeVisible();
  await expect(authedPage.getByText("Authorizing")).toBeVisible();

  await expect(authedPage.getByText("Auto-lock")).toBeVisible();
  await expect(authedPage.getByText("Sign timeout")).toBeVisible();
  await expect(authedPage.getByText("Audit retention")).toBeVisible();
  await expect(authedPage.getByText("Content-Type check")).toBeVisible();
});

test("Dashboard shows signers pending approval queue for admin", async ({
  authedPage,
}) => {
  await expect(
    authedPage.getByTestId("dashboard-signer-approval-queue"),
  ).toBeVisible();
  await expect(
    authedPage.getByRole("link", { name: "review signers →" }),
  ).toHaveAttribute("href", "/signers?ownership_status=pending_approval");
});

test("Simulate page loads from nav with engine status", async ({
  authedPage,
}) => {
  await authedPage.getByRole("link", { name: "Simulate" }).click();
  await expect(authedPage.getByTestId("simulate-page")).toBeVisible();
  await expect(
    authedPage.getByRole("heading", { name: "Simulate" }),
  ).toBeVisible();
  await expect(
    authedPage.getByRole("heading", { name: "Transaction" }),
  ).toBeVisible();
  await expect(
    authedPage.getByRole("button", { name: "Simulate", exact: true }),
  ).toBeVisible();
});

test("Settings shows admin security panel (IP ACL + guard resume)", async ({
  authedPage,
}) => {
  await authedPage.getByRole("link", { name: "Settings" }).click();
  await expect(
    authedPage.getByRole("heading", { name: "Settings" }),
  ).toBeVisible();
  await expect(authedPage.getByTestId("admin-security-panel")).toBeVisible();
  await expect(authedPage.getByText("IP whitelist (read-only)")).toBeVisible();
  // E2E daemon enables approval_guard; production may show "not configured" instead.
  const resume = authedPage.getByTestId("guard-resume");
  const notConfigured = authedPage.getByTestId("guard-not-configured");
  await expect(resume.or(notConfigured)).toBeVisible();
});

test("Templates registry refresh button completes sync", async ({
  authedPage,
}) => {
  await authedPage.getByRole("link", { name: "Templates" }).click();
  await expect(
    authedPage.getByRole("heading", { name: "Templates" }),
  ).toBeVisible();

  const refreshReq = authedPage.waitForRequest((req) =>
    req.url().includes("/api/v1/registry/refresh"),
  );
  await authedPage.getByTestId("registry-refresh").click();
  await acceptConfirm(authedPage);
  await refreshReq;
  await expect(authedPage.getByTestId("toast")).toContainText(
    "Registry sync complete",
    { timeout: 10_000 },
  );
});

test("Audit chain_type filter reissues query", async ({ authedPage }) => {
  await authedPage.getByRole("link", { name: "Audit log" }).click();
  await expect(authedPage.getByTestId("audit-filter-bar")).toBeVisible();

  const filtered = authedPage.waitForRequest(
    (req) =>
      req.url().includes("/api/v1/audit") &&
      req.url().includes("chain_type=evm"),
  );
  await authedPage.getByTestId("audit-filter-chain-type").fill("evm");
  await filtered;
});

test("Transactions sign_request_id filter reissues query", async ({
  authedPage,
}) => {
  await authedPage.getByRole("link", { name: "Transactions" }).click();
  await expect(
    authedPage.getByTestId("transactions-filter-bar"),
  ).toBeVisible();

  const reqId = "00000000-0000-4000-8000-000000000001";
  const filtered = authedPage.waitForRequest(
    (req) =>
      req.url().includes("/api/v1/evm/transactions") &&
      req.url().includes(`sign_request_id=${reqId}`),
  );
  await authedPage.getByTestId("transactions-filter-sign-request").fill(reqId);
  await filtered;
});

test("ApiKeys list shows rate limit column", async ({ authedPage }) => {
  await authedPage.getByRole("link", { name: "API Keys" }).click();
  await expect(
    authedPage.getByRole("columnheader", { name: "Rate limit" }),
  ).toBeVisible();
});

test("Signers list shows material status column", async ({ authedPage }) => {
  const admin = await adminSDKClient();
  await admin.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-material-col-pw" },
  });

  await authedPage.getByRole("link", { name: "Signers", exact: true }).click();
  await expect(
    authedPage.getByRole("heading", { name: "Signers" }),
  ).toBeVisible();
  await expect(authedPage.getByTestId("signers-col-material")).toBeVisible({
    timeout: 10_000,
  });
});

test("Rules chain_type filter reissues list query", async ({ authedPage }) => {
  await authedPage.getByRole("link", { name: "Rules" }).click();
  await expect(authedPage.getByTestId("rules-filter-bar")).toBeVisible();

  const filtered = authedPage.waitForRequest(
    (req) =>
      req.url().includes("/api/v1/evm/rules") &&
      req.url().includes("chain_type=evm"),
  );
  await authedPage.getByTestId("rules-filter-chain-type").fill("evm");
  await filtered;
});

test("Rules deep link expands rule row from rule_id query", async ({
  authedPage,
}) => {
  const c = await adminSDKClient();
  let rule;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      rule = await c.evm.rules.create({
        name: `e2e-deep-link-${Date.now()}-${attempt}`,
        type: "evm_address_list",
        mode: "whitelist",
        chain_type: "evm",
        chain_id: "1",
        config: { addresses: ["0x0000000000000000000000000000000000000001"] },
      });
      break;
    } catch {
      if (attempt === 4) throw new Error("failed to create rule for deep link test");
    }
  }
  if (!rule) throw new Error("missing rule fixture");

  await authedPage.getByRole("link", { name: "Rules" }).click();
  await expect(authedPage.getByRole("heading", { name: "Rules" })).toBeVisible();

  await authedPage.evaluate((id) => {
    const url = new URL(window.location.href);
    url.searchParams.set("rule_id", id);
    window.history.pushState(
      {},
      "",
      `${url.pathname}?${url.searchParams.toString()}`,
    );
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, rule.id);

  await expect(authedPage.getByText(rule.name)).toBeVisible({
    timeout: 10_000,
  });
});

test("Request detail shows approval panel with preview rule on agent-owned request", async ({
  authedPage,
}) => {
  const home = getState().home;
  const dbPath = join(home, "remote-signer.db");
  const requestID = `req-approval-preview-${Date.now()}`;
  const toAddr = "0x00000000000000000000000000000000000000aa";
  const payload = JSON.stringify({
    transaction: { to: toAddr, value: "0x0", data: "0x" },
  }).replace(/'/g, "''");
  const now = new Date().toISOString();

  // api_key_id=agent regression: admin must preview/approve without 403
  sqliteExec(dbPath, [
    `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, payload, created_at, updated_at)
     VALUES ('${requestID}', 'agent', 'evm', '1', '0xdeadbeef', 'transaction', 'authorizing', '${payload}', '${now}', '${now}')`,
  ]);

  await authedPage.evaluate((id) => {
    window.history.pushState({}, "", `/requests/${id}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, requestID);

  await expect(authedPage.getByTestId("request-approval-panel")).toBeVisible({
    timeout: 10_000,
  });
  await authedPage
    .getByRole("checkbox", {
      name: "Generate a whitelist rule from this request when approving",
    })
    .check();
  await expect(authedPage.getByTestId("approval-rule-type")).toHaveValue(
    "evm_address_list",
  );

  await authedPage.getByRole("button", { name: "Preview rule" }).click();
  await expect(authedPage.getByText("Preview config")).toBeVisible({
    timeout: 15_000,
  });
});
