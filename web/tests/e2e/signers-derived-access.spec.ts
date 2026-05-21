import { adminSDKClient, expect, test } from "./fixtures";

const HD_PASSWORD = "e2e-hd-grant-9q4f";

// Regression guard for the "click derived address → AccessPanel says
// 'not the owner of signer'" bug. Pre-fix SignerAccessService.IsOwner
// only consulted the direct ownership row, so every derived HD address
// 403'd the GET /access call that the panel opens with. Post-fix the
// service resolves derived → parent, the GET returns an empty list,
// and the Grant form is interactive.
//
// Daemon-side fixture setup goes through the SDK (an HD wallet primary
// + a deterministic derivation index 1 child) — the address strings
// surface in full there, while the HD Wallets UI shortens them and
// would make matching brittle. The web UI is exercised on the surface
// that actually carries the bug: clicking the derived row on Signers
// and asking the AccessPanel to load.
test("derived HD address opens a functional access panel for the owner", async ({
  authedPage,
}) => {
  const client = await adminSDKClient();

  // 1. Set up a fresh HD wallet via the SDK so we own the parent.
  const created = await client.evm.hdWallets.create({
    password: HD_PASSWORD,
  } as any);
  const primaryAddr: string = (created as any).primary_address;
  expect(primaryAddr).toMatch(/^0x[0-9a-fA-F]{40}$/);

  // 2. Derive index 1 — the daemon's create path returns index 0; we
  //    explicitly mint 1 so there's an address whose ownership row
  //    doesn't exist (only the parent does).
  const derived = await client.evm.hdWallets.deriveAddress(primaryAddr, {
    index: 1,
  });
  expect(derived.derived?.length ?? 0).toBeGreaterThan(0);
  const derivedAddr: string = derived.derived[0].address;
  expect(derivedAddr.toLowerCase()).not.toBe(primaryAddr.toLowerCase());

  // 3. Drive the Signers UI — the daemon's signer list surfaces
  //    derived addresses with hd_parent_address pointing at the
  //    wallet primary, so the row is reachable.
  await authedPage.click("text=Signers");
  const derivedRow = authedPage
    .locator("tr", { hasText: derivedAddr })
    .first();
  await expect(derivedRow).toBeVisible({ timeout: 5_000 });

  // 4. Click to expand the AccessPanel. Pre-fix the panel dispatched
  //    GET /signers/{derived}/access and rendered "not the owner of
  //    signer …" inside an ErrorBanner. Post-fix the parent-resolved
  //    IsOwner returns true and the list endpoint returns an empty
  //    array.
  await derivedRow.click();
  await expect(authedPage.getByText(/not the owner of signer/i)).toHaveCount(0);

  // 5. The Grant form must render and be interactive. We assert the
  //    select by its data-testid rather than the visible label so the
  //    selector survives the input → select migration done in the
  //    Grant-access dropdown commit.
  const grantSelect = authedPage.locator("[data-testid=grant-apikey]");
  await expect(grantSelect).toBeVisible();
  await expect(grantSelect).toBeEnabled();
});
