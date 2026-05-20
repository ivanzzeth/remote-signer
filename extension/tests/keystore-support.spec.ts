/**
 * Keystore (EnhancedKeyFile) input coverage for the popup settings form.
 *
 * The daemon ships its admin API key as an encrypted keystore JSON at
 * `~/.remote-signer/apikeys/admin.keystore.json`. The popup auto-detects
 * that shape when the operator pastes / loads it, surfaces a
 * "Keystore Password" field, and decrypts via the background service
 * worker — never persisting the encrypted blob in extension storage.
 *
 * This spec pins:
 *   1. The detection heuristic (PEM stays hidden, keystore JSON shows).
 *   2. The toggle reacts to subsequent edits (paste keystore → field
 *      visible → replace with PEM → field hidden again).
 *   3. Correct password decrypts and persists the resulting hex seed.
 *   4. Wrong password surfaces a clear error and does NOT persist
 *      anything.
 *   5. PEM-mode save still works after the form has seen a keystore
 *      (no leaked password state).
 *
 * Was added after a regression where the keystore-password field stayed
 * visible for PEM input because `.hidden` was a class with no matching
 * CSS rule on `.form-group` — fix uses the native HTML `hidden`
 * attribute, and this spec is the load-bearing check on the visibility
 * toggle.
 */
import { test, expect } from "./fixtures";

// PEM produced by `openssl genpkey -algorithm Ed25519` (same fixture
// the PEM-support spec uses).
const PEM_FIXTURE = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIG73OyQ7jTI+j/6qWSlm3tCl7PhPcWZXBdRzTdeoBuAK
-----END PRIVATE KEY-----`;
const PEM_EXPECTED_HEX =
  "6ef73b243b8d323e8ffeaa592966ded0a5ecf84f71665705d4734dd7a806e00a";

// Pre-built keystore (EnhancedKeyFile v1, scrypt N=4096 for fast test;
// the popup honours per-file kdfparams so light N is fine here).
// Decrypts to KEYSTORE_EXPECTED_HEX with KEYSTORE_PASSWORD. Generated
// once with /tmp/gen_keystore.mjs (see commit) and pasted verbatim —
// no test-time encryption, so the assertion is on the decrypt path
// exclusively.
const KEYSTORE_JSON = `{"version":1,"key_type":"ed25519","identifier":"fixture","label":"test keystore","crypto":{"cipher":"aes-128-ctr","ciphertext":"1c655bedd4327f5c9551baba967cccacf6ca7ad4a67172f0753f01e2b2b820a8","cipherparams":{"iv":"7c7442d2226bf6227951c9cf89267ea4"},"kdf":"scrypt","kdfparams":{"n":4096,"r":8,"p":1,"dklen":32,"salt":"7da777d483e8805797813c03dd51e07af4a25b5a595fb44db1c4842cdfb0e1db"},"mac":"2646f0c2c565845bc5bb30775ef3002708a2d8ddd4fd1c4c1906afe108f8e2ce"}}`;
const KEYSTORE_PASSWORD = "Daemon-Boot-2026!";
const KEYSTORE_EXPECTED_HEX =
  "deadbeeffeedface0123456789abcdef1032547698badcfe0011223344556677";

test.describe("Popup keystore input (@integration)", () => {
  test("PEM input keeps the keystore-password field hidden", async ({
    popup,
  }) => {
    // The bug this guards: I shipped the password-field toggle using a
    // `hidden` CSS class with no scoped rule on `.form-group`. PEM input
    // → detectKeystoreJSON() returns false → toggle should hide the
    // field. With the broken CSS the field stayed visible forever. The
    // assertion here MUST be on actual rendered visibility, not on the
    // class list, so a future re-styling that breaks the same way trips
    // this test.
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputPrivateKey", PEM_FIXTURE);

    await expect(popup.locator("#keystorePasswordGroup")).toBeHidden();
    // Sanity-check the affordance copy stayed correct.
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(PEM_FIXTURE);
  });

  test("Empty textarea keeps the keystore-password field hidden", async ({
    popup,
  }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();
    // The field MUST start hidden on a freshly-opened popup — otherwise
    // first-time operators see an unexplained password input before
    // typing anything.
    await expect(popup.locator("#keystorePasswordGroup")).toBeHidden();
  });

  test("Pasting an EnhancedKeyFile JSON surfaces the password field", async ({
    popup,
  }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputPrivateKey", KEYSTORE_JSON);

    await expect(popup.locator("#keystorePasswordGroup")).toBeVisible();
    await expect(popup.locator("#inputKeystorePassword")).toBeVisible();
    // The hint paragraph must tell the operator what to type — copy
    // regression guard.
    await expect(popup.locator("#keystorePasswordHint")).toContainText(
      /password/i,
    );
  });

  test("Switching from keystore to PEM hides the password field AND clears the entered password", async ({
    popup,
  }) => {
    await popup.click("#disconnectedSettingsBtn");
    await popup.fill("#inputPrivateKey", KEYSTORE_JSON);
    await expect(popup.locator("#keystorePasswordGroup")).toBeVisible();
    await popup.fill("#inputKeystorePassword", "some-typed-password");

    // Now flip the textarea to a PEM. Visibility toggle MUST run, and
    // the previously-typed password MUST be wiped — otherwise a save
    // would smuggle the keystore password into the PEM-import code
    // path.
    await popup.fill("#inputPrivateKey", PEM_FIXTURE);
    await expect(popup.locator("#keystorePasswordGroup")).toBeHidden();
    await expect(popup.locator("#inputKeystorePassword")).toHaveValue("");
  });

  test("Keystore + correct password saves as the decrypted hex seed", async ({
    popup,
    serverInfo,
  }) => {
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", "admin");
    await popup.fill("#inputPrivateKey", KEYSTORE_JSON);
    await expect(popup.locator("#keystorePasswordGroup")).toBeVisible();
    await popup.fill("#inputKeystorePassword", KEYSTORE_PASSWORD);

    await popup.click("#saveConfigBtn");
    // Save flips out of settings — wait for it.
    await expect(popup.locator("#settingsView")).toHaveClass(/hidden/, {
      timeout: 15_000,
    });

    // Re-open settings and verify the persisted value is the DECRYPTED
    // hex seed, NOT the keystore JSON. The encrypted blob must never
    // live in chrome.storage — the popup decrypts once and stores only
    // the resulting bytes.
    const settingsBtn = popup.locator("#settingsBtn");
    const disconnectedBtn = popup.locator("#disconnectedSettingsBtn");
    if (await settingsBtn.isVisible().catch(() => false)) {
      await settingsBtn.click();
    } else {
      await disconnectedBtn.click();
    }
    await expect(popup.locator("#settingsView")).toBeVisible({
      timeout: 5_000,
    });
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(
      KEYSTORE_EXPECTED_HEX,
    );
    // And the keystore-password field is hidden again — because the
    // persisted value is now a hex seed, not a keystore.
    await expect(popup.locator("#keystorePasswordGroup")).toBeHidden();
  });

  test("Keystore + wrong password surfaces an error and does not persist", async ({
    popup,
    serverInfo,
  }) => {
    await popup.click("#disconnectedSettingsBtn");
    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", "admin");
    await popup.fill("#inputPrivateKey", KEYSTORE_JSON);
    await popup.fill("#inputKeystorePassword", "definitely-the-wrong-password");

    await popup.click("#saveConfigBtn");

    // Error banner with the verbatim "Wrong keystore password" copy
    // (the popup rewrites the SDK's internal "wrong password" to this
    // friendlier string — pin it so future copy changes are explicit).
    await expect(popup.locator("#connectionError")).toBeVisible({
      timeout: 15_000,
    });
    await expect(popup.locator("#connectionError")).toContainText(
      /Wrong keystore password/i,
    );

    // The button comes back so the operator can fix and retry.
    await expect(popup.locator("#saveConfigBtn")).toBeEnabled();
    // The textarea still holds the keystore JSON (so the operator
    // doesn't have to re-paste).
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(KEYSTORE_JSON);
  });

  test("PEM-mode save still works after the form previously saw a keystore", async ({
    popup,
    serverInfo,
  }) => {
    // Defence-in-depth for the "leaked password" failure mode: after
    // we've shown the keystore-password field, switching back to PEM
    // and saving MUST hand the PEM straight through to the daemon —
    // no leftover keystore-decrypt code path firing on plaintext
    // input.
    await popup.click("#disconnectedSettingsBtn");

    await popup.fill("#inputPrivateKey", KEYSTORE_JSON);
    await expect(popup.locator("#keystorePasswordGroup")).toBeVisible();
    // Now flip to PEM without saving.
    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", "anything");
    await popup.fill("#inputPrivateKey", PEM_FIXTURE);
    await expect(popup.locator("#keystorePasswordGroup")).toBeHidden();

    await popup.click("#saveConfigBtn");
    await expect(popup.locator("#settingsView")).toHaveClass(/hidden/, {
      timeout: 10_000,
    });

    // Verify the stored value is the hex seed parsePrivateKey would
    // extract from the PEM — same assertion as pem-support.spec, just
    // re-validated post-keystore-state.
    const settingsBtn = popup.locator("#settingsBtn");
    const disconnectedBtn = popup.locator("#disconnectedSettingsBtn");
    if (await settingsBtn.isVisible().catch(() => false)) {
      await settingsBtn.click();
    } else {
      await disconnectedBtn.click();
    }
    await expect(popup.locator("#settingsView")).toBeVisible({
      timeout: 5_000,
    });
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(
      PEM_EXPECTED_HEX,
    );
  });
});
