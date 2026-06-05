import { adminSDKClient, agentSDKClient, expect, test } from "./fixtures";

const PASSWORD = "e2e-pending-signer-pw-7x";

test("Admin sees global pending signer queue without API key filter", async ({
  authedPage,
}) => {
  const agent = agentSDKClient();
  const admin = await adminSDKClient();

  const created = await agent.evm.signers.create({
    type: "keystore",
    keystore: { password: PASSWORD },
    display_name: "pending-queue-e2e",
  } as any);
  const address = (created as any).address as string;

  // Leave Dashboard so remount refetches pending signer count.
  await authedPage.getByRole("link", { name: "Settings" }).click();
  await authedPage.getByRole("link", { name: "Dashboard" }).click();
  await expect(
    authedPage.getByTestId("dashboard-signer-approval-queue"),
  ).toBeVisible();
  await expect
    .poll(
      async () =>
        authedPage.getByTestId("dashboard-signer-approval-queue").innerText(),
      { timeout: 10_000 },
    )
    .toMatch(/[1-9]/);

  await authedPage.getByRole("link", { name: "Signers", exact: true }).click();
  await expect(authedPage.getByTestId("signers-pending-banner")).toBeVisible();
  await authedPage.getByTestId("signers-pending-banner-cta").click();

  await expect(authedPage.getByTestId("signers-pending-view-hint")).toBeVisible();
  await expect(
    authedPage.getByRole("columnheader", { name: "Owner" }),
  ).toBeVisible();
  await expect(
    authedPage.getByRole("columnheader", { name: "Status" }),
  ).toBeVisible();
  await expect(authedPage.locator("tr", { hasText: address })).toBeVisible({
    timeout: 5_000,
  });
  const row = authedPage.locator("tr", { hasText: address });
  await expect(row.getByTestId("signer-owner")).toHaveText("agent");
  await expect(row.getByText("pending_approval")).toBeVisible();
  await expect(
    authedPage.locator("tr", { hasText: address }).getByRole("button", {
      name: "Approve",
    }),
  ).toBeVisible();

  await admin.evm.signers.approveSigner(address);
  await authedPage.getByRole("button", { name: "Refresh" }).click();
  await expect(authedPage.getByText("No signers pending approval.")).toBeVisible({
    timeout: 10_000,
  });

  try {
    await agent.evm.signers.deleteSigner(address);
  } catch {
    // Best-effort cleanup — agent-owned signers cannot be deleted by admin.
  }
});
