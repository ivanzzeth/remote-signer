/**
 * Settings-form defaults and the "Load from file…" helper.
 *
 * The extension targets a `remote-signer` instance that ships a default
 * `agent` API key under `~/.remote-signer/apikeys/agent.key.priv`. The
 * popup's onboarding pre-fills the `API Key ID` field with "agent" and
 * lets the user load the private key from disk with a single click,
 * so first-run never requires typing the role name or pasting hex.
 */
import { test, expect } from "./fixtures";

test.describe("Settings defaults & key-file loader (@integration)", () => {
  test("fresh popup pre-fills 'agent' in the API Key ID field", async ({ context, extensionId }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");

    // Disconnected view is the entry state for an unconfigured extension.
    await expect(popup.locator("#disconnectedView")).toBeVisible();
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await expect(popup.locator("#inputKeyId")).toHaveValue("agent");
    await expect(popup.locator("#inputPrivateKey")).toHaveValue("");

    await popup.close();
  });

  test("'Load from file…' button fills the textarea with the file contents", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    // Use a real key (the seeded admin one) so a subsequent Save would
    // succeed; here we only assert the load path itself.
    const keyText = serverInfo.admin_api_key_hex;
    await popup.setInputFiles("#keyFileInput", {
      name: "agent.key.priv",
      mimeType: "text/plain",
      buffer: Buffer.from(keyText + "\n", "utf-8"),
    });

    await expect(popup.locator("#inputPrivateKey")).toHaveValue(keyText);
    // Loading the file un-masks the textarea so the user can verify what
    // landed; the toggle button label flips to "Hide".
    await expect(popup.locator("#togglePwBtn")).toHaveText("Hide");

    await popup.close();
  });

  /**
   * File System Access API path: stub showOpenFilePicker before the
   * popup loads so a single button click triggers our pick→read→fill
   * flow without spawning a native file dialog (which Playwright can't
   * dismiss in this context). Asserts the textarea is populated AND the
   * button relabels to "Reload <filename>" so users see persistence
   * happened.
   */
  test("showOpenFilePicker path: button relabels to 'Reload <filename>' after pick", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    const keyText = serverInfo.admin_api_key_hex;
    // Inject the stub before any popup script runs.
    await popup.addInitScript(({ keyText }) => {
      // Minimal FileSystemFileHandle shape — name + queryPermission +
      // requestPermission + getFile is all popup.js touches.
      const stubHandle = {
        name: "agent.key.priv",
        kind: "file",
        async queryPermission() { return "granted"; },
        async requestPermission() { return "granted"; },
        async getFile() {
          return new File([keyText], "agent.key.priv", { type: "text/plain" });
        },
      };
      // Track invocations so the test can assert the picker fired (or
      // didn't, on the reload path).
      (window as any).__pickerCalls = 0;
      (window as any).showOpenFilePicker = async () => {
        (window as any).__pickerCalls += 1;
        return [stubHandle];
      };
    }, { keyText });

    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    await popup.click("#loadKeyFileBtn");
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(keyText);
    await expect(popup.locator("#loadKeyFileBtn")).toHaveText(/Reload agent\.key\.priv/);
    await expect(popup.locator("#togglePwBtn")).toHaveText("Hide");

    const pickerCalls = await popup.evaluate(() => (window as any).__pickerCalls);
    expect(pickerCalls).toBe(1);

    await popup.close();
  });

  /**
   * Handle reuse path: after the first pick the in-session handle is
   * cached, so a subsequent click reloads the same file with NO further
   * picker invocation. This is what users experience when they re-open
   * the settings view to refresh their key — the whole point of avoiding
   * the "navigate to ~/.remote-signer/apikeys/ every time" friction.
   *
   * NOTE on cross-popup persistence: real FileSystemFileHandle instances
   * are structured-clone-safe and survive a popup reload via IndexedDB;
   * plain-object stubs aren't, so we exercise the same code path within a
   * single popup session here.
   */
  test("handle reuse: second click reads the same file without re-opening the picker", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    const keyText = serverInfo.admin_api_key_hex;
    await popup.addInitScript(({ keyText }) => {
      const stubHandle = {
        name: "agent.key.priv",
        kind: "file",
        async queryPermission() { return "granted"; },
        async requestPermission() { return "granted"; },
        async getFile() {
          return new File([keyText], "agent.key.priv", { type: "text/plain" });
        },
      };
      (window as any).__pickerCalls = 0;
      (window as any).showOpenFilePicker = async () => {
        (window as any).__pickerCalls += 1;
        return [stubHandle];
      };
    }, { keyText });

    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await popup.click("#disconnectedSettingsBtn");

    // First click: picker fires, handle gets cached.
    await popup.click("#loadKeyFileBtn");
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(keyText);
    await expect(popup.locator("#loadKeyFileBtn")).toHaveText(/Reload agent\.key\.priv/);
    expect(await popup.evaluate(() => (window as any).__pickerCalls)).toBe(1);

    // Clear the textarea so we can prove the second click refills it from
    // the cached handle — not from a residual DOM value.
    await popup.fill("#inputPrivateKey", "");

    // Second click: must use the cached handle, NOT spawn the picker.
    await popup.click("#loadKeyFileBtn");
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(keyText);
    expect(await popup.evaluate(() => (window as any).__pickerCalls)).toBe(1);

    // Shift-click escape hatch: force a fresh pick.
    await popup.locator("#loadKeyFileBtn").click({ modifiers: ["Shift"] });
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(keyText);
    expect(await popup.evaluate(() => (window as any).__pickerCalls)).toBe(2);

    await popup.close();
  });

  test("drag-and-drop onto the textarea loads the dropped file", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    const keyText = serverInfo.admin_api_key_hex;

    // Construct a real File, drop it via DataTransfer. Playwright doesn't
    // expose a one-liner for file-drag, so we synthesise the events ourselves.
    await popup.evaluate(async ({ keyText }) => {
      const file = new File([keyText], "agent.key.priv", { type: "text/plain" });
      const dt = new DataTransfer();
      dt.items.add(file);
      const ta = document.getElementById("inputPrivateKey")!;
      ta.dispatchEvent(new DragEvent("dragover", { bubbles: true, cancelable: true, dataTransfer: dt }));
      ta.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
      // Give the async file.text() time to resolve.
      await new Promise((r) => setTimeout(r, 100));
    }, { keyText });

    await expect(popup.locator("#inputPrivateKey")).toHaveValue(keyText);
    await expect(popup.locator("#loadKeyFileBtn")).toHaveText(/Reload agent\.key\.priv/);

    await popup.close();
  });

  test("loaded key + default ID + URL Save reaches the connected view", async ({ context, extensionId, serverInfo }) => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await popup.waitForSelector("#app");
    await popup.click("#disconnectedSettingsBtn");
    await expect(popup.locator("#settingsView")).toBeVisible();

    // Default ID stays as "agent" — we only need to supply URL + load the key
    // file. This is the intended single-keystroke-free onboarding flow.
    await popup.fill("#inputUrl", serverInfo.base_url);
    await popup.fill("#inputKeyId", serverInfo.admin_api_key_id);
    await popup.setInputFiles("#keyFileInput", {
      name: "agent.key.priv",
      mimeType: "text/plain",
      buffer: Buffer.from(serverInfo.admin_api_key_hex, "utf-8"),
    });
    await expect(popup.locator("#inputPrivateKey")).toHaveValue(serverInfo.admin_api_key_hex);

    await popup.click("#saveConfigBtn");
    await expect(popup.locator("#connectedView")).toBeVisible({ timeout: 15_000 });
    await expect(popup.locator("#statusText")).toHaveText("Connected");

    await popup.close();
  });
});
