/**
 * Extension build script — esbuild bundles background.ts into background.js.
 *
 * inpage.js and content-script.js are sourced from web3-agent-browser
 * and copied directly (no build step needed for those two files).
 *
 * background.ts bundles remote-signer-client and EIP1193Provider.
 */
import * as esbuild from "esbuild";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

await esbuild.build({
  entryPoints: [path.join(__dirname, "src/background.ts")],
  bundle: true,
  format: "iife",
  target: "chrome125",
  outfile: path.join(__dirname, "background.js"),
  minify: false,
  sourcemap: false,
  banner: {
    // Proxy/CLI mode support: web3-agent-browser (and other headless
    // launchers) inject runtime config via importScripts("bg-config.js"),
    // which sets self.__WEB3_AGENT_BROWSER_CONFIG__. When this file
    // exists the extension reads its config from there and skips
    // chrome.storage, enabling zero-click headless operation.
    // Swallowed silently so interactive popup users never notice.
    js: 'try { importScripts("bg-config.js"); } catch(e) {}',
  },
  define: {
    "process.env.NODE_ENV": '"production"',
    global: "self",
  },
  platform: "browser",
});

console.log("[build] extension/background.js built successfully");
