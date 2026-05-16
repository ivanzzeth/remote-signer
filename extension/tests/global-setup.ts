import { type FullConfig } from "@playwright/test";
import { fileURLToPath } from "url";
import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import * as fs from "fs";
import * as http from "http";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface E2EServerInfo {
  base_url: string;
  dapp_url: string;
  admin_api_key_id: string;
  admin_api_key_hex: string;
  non_admin_api_key_id: string;
  non_admin_api_key_hex: string;
  signer_address: string;
}

declare global {
  var __e2eServerProcess: ChildProcess | undefined;
  var __e2eServerInfo: E2EServerInfo | undefined;
  var __dappServer: http.Server | undefined;
}

async function globalSetup(_config: FullConfig) {
  const projectRoot = path.resolve(__dirname, "..", "..");
  const bin = path.join(projectRoot, ".e2e-test-server");

  // Build the launcher
  await new Promise<void>((resolve, reject) => {
    const build = spawn("go", ["build", "-tags=e2e", "-o", bin, "./cmd/e2e-test-server"], {
      cwd: projectRoot,
      stdio: "inherit",
    });
    build.on("close", (code) => {
      code === 0 ? resolve() : reject(new Error(`go build failed with code ${code}`));
    });
  });

  console.log("[global-setup] Starting e2e-test-server...");

  const proc = spawn(bin, [], {
    cwd: projectRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });

  // Collect stderr for failures
  let stderr = "";
  proc.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });

  // Read server info from stdout (first JSON line)
  const info = await new Promise<E2EServerInfo>((resolve, reject) => {
    let stdout = "";
    const timeout = setTimeout(() => reject(new Error("server startup timed out")), 30_000);

    proc.stdout?.on("data", (d: Buffer) => {
      stdout += d.toString();
      const lines = stdout.split("\n");
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line.trim());
          if (parsed.base_url) {
            clearTimeout(timeout);
            resolve(parsed as E2EServerInfo);
            return;
          }
        } catch { /* keep reading */ }
      }
      if (stderr) {
        try {
          const errParsed = JSON.parse(stderr);
          if (errParsed.error) {
            clearTimeout(timeout);
            reject(new Error(errParsed.error));
            return;
          }
        } catch { /* keep reading */ }
      }
    });

    proc.on("close", (code) => {
      clearTimeout(timeout);
      reject(new Error(`server exited with code ${code}. stderr: ${stderr}`));
    });
  });

  globalThis.__e2eServerProcess = proc;
  globalThis.__e2eServerInfo = info;

  // Write server info for test fixture consumption
  const outDir = path.join(__dirname, ".e2e-state");
  fs.mkdirSync(outDir, { recursive: true });

  // Also write dApp test page that needs the server URL
  const dappHtml = generateDappPage(info);
  fs.writeFileSync(path.join(outDir, "dapp-test-page.html"), dappHtml);

  // Copy dApp pages into .e2e-state so they can be served via HTTP
  const dappDir = path.join(__dirname, "dapp");
  if (fs.existsSync(dappDir)) {
    for (const file of fs.readdirSync(dappDir)) {
      fs.copyFileSync(path.join(dappDir, file), path.join(outDir, file));
    }
  }

  // Start a static HTTP file server to serve dApp pages (file:// doesn't work with MV3 content scripts)
  const dappServer = http.createServer((req, res) => {
    const urlPath = req.url === "/" ? "dapp-test-page.html" : req.url!;
    let filePath = path.join(outDir, urlPath);
    // Resolve symlinks and prevent directory traversal
    filePath = path.resolve(filePath);
    if (!filePath.startsWith(path.resolve(outDir))) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end("Not found");
        return;
      }
      const ext = path.extname(filePath);
      const mimeTypes: Record<string, string> = {
        ".html": "text/html",
        ".js": "application/javascript",
        ".css": "text/css",
        ".json": "application/json",
      };
      res.writeHead(200, { "Content-Type": mimeTypes[ext] || "text/html" });
      res.end(data);
    });
  });

  const dappPort = await new Promise<number>((resolve) => {
    const server = dappServer.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve(typeof addr === "object" && addr ? addr.port : 0);
    });
  });

  globalThis.__dappServer = dappServer;
  globalThis.__e2eServerInfo!.dapp_url = `http://127.0.0.1:${dappPort}`;

  // Re-write server.json with dapp_url now included
  const fullInfo = { ...info, dapp_url: globalThis.__e2eServerInfo!.dapp_url };
  fs.writeFileSync(path.join(outDir, "server.json"), JSON.stringify(fullInfo, null, 2));

  console.log(`[global-setup] DApp file server ready at http://127.0.0.1:${dappPort}`);

  console.log(`[global-setup] Test server ready at ${info.base_url}`);
}

function generateDappPage(info: E2EServerInfo): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Remote Signer E2E Test dApp</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
    .panel { border: 1px solid #ccc; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    .panel h3 { margin-top: 0; }
    pre { background: #f0f0f0; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }
    button { padding: 0.5rem 1rem; margin: 0.25rem; cursor: pointer; border-radius: 4px; border: 1px solid #999; background: #fff; }
    button:hover { background: #e8e8e8; }
    .status { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: 600; }
    .status.ok { background: #d4edda; color: #155724; }
    .status.err { background: #f8d7da; color: #721c24; }
    .status.pending { background: #fff3cd; color: #856404; }
    #results { white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <h1>Remote Signer E2E Test dApp</h1>
  <p>This page tests the EIP-1193 provider injected by the Remote Signer extension.</p>

  <div class="panel">
    <h3>Provider State</h3>
    <p>Available: <span id="providerStatus" class="status pending">checking...</span></p>
    <p>Chain ID: <span id="chainId">-</span></p>
    <p>Accounts: <pre id="accounts">-</pre></p>
    <p>Connected: <span id="connected">-</span></p>
  </div>

  <div class="panel">
    <h3>EIP-1193 Actions</h3>
    <button id="btnRequestAccounts">eth_requestAccounts</button>
    <button id="btnAccounts">eth_accounts</button>
    <button id="btnChainId">eth_chainId</button>
    <button id="btnPersonalSign">personal_sign</button>
    <button id="btnSendTransaction">eth_sendTransaction</button>
    <button id="btnSwitchChain">wallet_switchEthereumChain</button>
    <div id="results"></div>
  </div>

  <div class="panel">
    <h3>Event Log</h3>
    <pre id="eventLog">-</pre>
  </div>

  <script>
    // Server info injected by global setup
    window.__E2E_SERVER_INFO = ${JSON.stringify(info)};
    const eventLog = [];
    function logEvent(name, data) {
      const entry = new Date().toISOString() + " " + name + " " + JSON.stringify(data);
      eventLog.unshift(entry);
      document.getElementById("eventLog").textContent = eventLog.slice(0, 50).join("\\n");
    }

    // Poll for provider availability
    let checkCount = 0;
    const checkInterval = setInterval(() => {
      checkCount++;
      const provider = window.ethereum;
      const statusEl = document.getElementById("providerStatus");
      if (provider) {
        clearInterval(checkInterval);
        statusEl.textContent = "available";
        statusEl.className = "status ok";
        document.getElementById("chainId").textContent = provider.chainId || "-";
        document.getElementById("accounts").textContent = JSON.stringify(provider.selectedAddress ? [provider.selectedAddress] : []);
        document.getElementById("connected").textContent = String(provider.isConnected?.() ?? false);

        provider.on("accountsChanged", (accounts) => logEvent("accountsChanged", accounts));
        provider.on("chainChanged", (chainId) => logEvent("chainChanged", chainId));
        provider.on("connect", (info) => logEvent("connect", info));
        provider.on("disconnect", (error) => logEvent("disconnect", error));
      } else if (checkCount > 100) {
        clearInterval(checkInterval);
        statusEl.textContent = "unavailable (timeout)";
        statusEl.className = "status err";
      }
    }, 100);

    async function call(method, ...params) {
      try {
        const result = await window.ethereum.request({ method, params });
        return { ok: true, result };
      } catch (err) {
        return { ok: false, error: { code: err.code, message: err.message } };
      }
    }

    function showResult(result) {
      document.getElementById("results").innerHTML = "<pre>" + JSON.stringify(result, null, 2).replace(/</g, "&lt;") + "</pre>";
    }

    document.getElementById("btnRequestAccounts").onclick = async () => {
      const r = await call("eth_requestAccounts");
      showResult(r);
      if (r.ok) document.getElementById("accounts").textContent = JSON.stringify(r.result);
    };
    document.getElementById("btnAccounts").onclick = async () => showResult(await call("eth_accounts"));
    document.getElementById("btnChainId").onclick = async () => showResult(await call("eth_chainId"));
    document.getElementById("btnPersonalSign").onclick = async () => {
      const accounts = await call("eth_accounts");
      if (!accounts.ok || !accounts.result.length) { showResult({ ok: false, error: "no accounts" }); return; }
      showResult(await call("personal_sign", "0x48656c6c6f", accounts.result[0]));
    };
    document.getElementById("btnSendTransaction").onclick = async () => {
      const accounts = await call("eth_accounts");
      if (!accounts.ok || !accounts.result.length) { showResult({ ok: false, error: "no accounts" }); return; }
      showResult(await call("eth_sendTransaction", {
        from: accounts.result[0],
        to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        value: "0x0",
      }));
    };
    document.getElementById("btnSwitchChain").onclick = async () => {
      showResult(await call("wallet_switchEthereumChain", { chainId: "0x89" }));
    };
  </script>
</body>
</html>`;
}

export default globalSetup;
