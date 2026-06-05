import { SignError } from "remote-signer-client";
import { acceptConfirm, adminSDKClient, expect, test } from "./fixtures";

test("bulk reject selected pending requests", async ({ authedPage }) => {
  const c = await adminSDKClient();

  const signer = await c.evm.signers.create({
    type: "keystore",
    keystore: { password: "e2e-bulk-reject-pw" },
  });

  const requestIds: string[] = [];
  for (let i = 0; i < 2; i++) {
    try {
      const r = await c.evm.sign.executeAsync({
        chain_id: "1",
        signer_address: signer.address,
        sign_type: "personal",
        payload: { message: `0x${(65 + i).toString(16)}` },
      });
      requestIds.push(r.request_id);
    } catch (e) {
      if (!(e instanceof SignError)) throw e;
      requestIds.push(e.requestID);
    }
  }
  expect(requestIds).toHaveLength(2);

  await authedPage.getByRole("link", { name: "Requests", exact: true }).click();
  await expect(
    authedPage.getByRole("heading", { name: "Sign requests" }),
  ).toBeVisible();

  await authedPage.getByPlaceholder("0x…").fill(signer.address);

  await expect
    .poll(async () => {
      const rows = authedPage.locator("tbody tr").filter({
        has: authedPage.locator(`text=${signer.address.slice(0, 10)}`),
      });
      return rows.count();
    }, { timeout: 10_000 })
    .toBe(2);

  await authedPage.getByTestId("requests-select-all").check();
  await expect(authedPage.getByTestId("requests-bulk-toolbar")).toBeVisible();

  await authedPage.getByRole("button", { name: "Reject selected" }).click();
  await acceptConfirm(authedPage);

  await expect
    .poll(async () => (await c.evm.requests.get(requestIds[0]!)).status, {
      timeout: 10_000,
    })
    .toBe("rejected");

  const second = await c.evm.requests.get(requestIds[1]!);
  expect(second.status).toBe("rejected");
});
