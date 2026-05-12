import { SETTINGS_GROUPS } from "remote-signer-client";
import { expect, test } from "./fixtures";

test("Settings page renders a card per group", async ({ authedPage }) => {
  await authedPage.click("text=Settings");
  await expect(
    authedPage.getByRole("heading", { name: "Settings" }),
  ).toBeVisible();

  // Each group title is rendered exactly once as the card header. We
  // assert all 9 are reachable rather than poking at the snapshot data
  // (shape varies and isn't load-bearing for the read-only viewer).
  for (const g of SETTINGS_GROUPS) {
    await expect(authedPage.getByRole("heading", { name: g })).toBeVisible();
  }

  // None of the groups should still be loading after the fan-out resolves.
  // (The page never falls back to a "loading" state across the suite —
  //  Promise.allSettled is awaited inside the effect.)
  await expect(authedPage.locator("text=Loading…")).toHaveCount(0);
});
