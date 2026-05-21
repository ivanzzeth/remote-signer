import { adminSDKClient, expect, test } from "./fixtures";

const PASSWORD = "e2e-grant-pw-1f8d";

// The AccessPanel's Grant input switched from free-text to a select
// populated from /api/v1/api-keys/names. Default selection is the
// "agent" bootstrap key — the most common grantee in practice — but
// the operator can pick any other key. This spec pins both the
// default-selection contract and the round-trip from grant to row.
test("Grant access dropdown defaults to agent and grants successfully", async ({
  authedPage,
}) => {
  const sdk = await adminSDKClient();

  // 1. Create a keystore signer owned by admin; AccessPanel reads
  //    /signers/{address}/access against this row.
  const created = await sdk.evm.signers.create({
    type: "keystore",
    keystore: { password: PASSWORD },
    display_name: "grant-dropdown-target",
  } as any);
  const address: string = (created as any).address;

  // 2. Navigate to Signers, expand the row to render the AccessPanel.
  //    The actions cell stops propagation, so click the address cell
  //    (first <td>) to ensure the row-level toggle fires.
  await authedPage.click("text=Signers");
  const row = authedPage.locator("tr", { hasText: address }).first();
  await expect(row).toBeVisible({ timeout: 5_000 });
  await row.locator("td").first().click();
  // Sanity gate — AccessPanel renders the "Access grants" header
  // unconditionally, so its visibility tells us the row really
  // expanded (vs. a row.click that hit a stopPropagation child).
  await expect(authedPage.getByText("Access grants", { exact: false }))
    .toBeVisible({ timeout: 5_000 });

  // 3. The dropdown is visible, populated, and defaults to "agent".
  const grantSelect = authedPage.locator("[data-testid=grant-apikey]");
  await expect(grantSelect).toBeVisible({ timeout: 5_000 });
  await expect
    .poll(async () => grantSelect.inputValue(), { timeout: 5_000 })
    .toBe("agent");

  // 4. Submit Grant — listed row picks up the new grantee. The
  //    daemon round-trip proves the dropdown's value made it through
  //    the wire intact.
  await authedPage
    .locator("button", { hasText: "Grant" })
    .first()
    .click();
  await expect(authedPage.locator("tr", { hasText: "agent" }).first())
    .toBeVisible({ timeout: 5_000 });

  // 5. Once granted, "agent" disappears from the dropdown (we filter
  //    already-granted ids out so the operator can't double-grant).
  await expect
    .poll(
      async () =>
        await grantSelect.evaluate((el) =>
          Array.from((el as HTMLSelectElement).options).map((o) => o.value),
        ),
      { timeout: 3_000 },
    )
    .not.toContain("agent");

  // Cleanup: revoke then delete so the next spec sees a clean slate.
  await sdk.evm.signers.revokeAccess(address, "agent");
  await sdk.evm.signers.deleteSigner(address);
});
