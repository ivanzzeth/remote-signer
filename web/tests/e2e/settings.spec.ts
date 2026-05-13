import { SETTINGS_GROUPS } from "remote-signer-client";
import { expect, test } from "./fixtures";

test("Settings page exposes a nav entry per group", async ({ authedPage }) => {
  await authedPage.click("text=Settings");
  await expect(
    authedPage.getByRole("heading", { name: "Settings" }),
  ).toBeVisible();

  // Left-rail nav has one button per group. We assert all 9 are
  // reachable rather than poking at the snapshot shape, which varies
  // per group and isn't load-bearing for the page contract.
  for (const g of SETTINGS_GROUPS) {
    await expect(
      authedPage.getByRole("button", { name: g }),
    ).toBeVisible();
  }
});

test("clicking a group nav button swaps the right pane", async ({
  authedPage,
}) => {
  await authedPage.click("text=Settings");

  // The page defaults to the first group ("security"). Switch to
  // "notify" and assert the card heading flips.
  await authedPage.getByRole("button", { name: "notify" }).click();
  await expect(
    authedPage.getByRole("heading", { name: "notify" }),
  ).toBeVisible();
});
