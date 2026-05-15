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
  define: {
    "process.env.NODE_ENV": '"production"',
    global: "self",
  },
  platform: "browser",
});

console.log("[build] extension/background.js built successfully");
