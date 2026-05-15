import { spawn, ChildProcess } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

declare global {
  // eslint-disable-next-line no-var
  var __e2eServerProcess: ChildProcess | undefined;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..", "..");

function serverReadyPromise(): Promise<string> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Test server did not start within 60s"));
    }, 60_000);

    const maxConnectAttempts = 50;
    let connectAttempts = 0;

    const connectInterval = setInterval(async () => {
      connectAttempts++;
      try {
        const resp = await fetch("http://127.0.0.1:18549/health");
        if (resp.ok) {
          const text = await resp.text();
          clearInterval(connectInterval);
          clearTimeout(timeout);
          resolve(text);
        }
      } catch {
        if (connectAttempts >= maxConnectAttempts) {
          clearInterval(connectInterval);
          clearTimeout(timeout);
          reject(new Error("Test server health check failed"));
        }
      }
    }, 200);
  });
}

async function globalSetup() {
  const serverConfigPath = path.join(__dirname, ".server-config.json");

  // Try to build the Go binary
  const goBin = path.join(repoRoot, "e2e-test-server");
  console.log("[globalSetup] Building e2e-test-server...");
  await new Promise<void>((resolve, reject) => {
    const build = spawn("go", ["build", "-o", goBin, "./cmd/e2e-test-server"], {
      cwd: repoRoot,
      stdio: "inherit",
    });
    build.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`go build failed with code ${code}`));
    });
  });

  console.log("[globalSetup] Starting e2e test server on port 18549...");
  const server = spawn(goBin, [], {
    cwd: repoRoot,
    env: { ...process.env, E2E_API_PORT: "18549" },
    stdio: ["ignore", "pipe", "inherit"],
  });

  let configLine = "";
  server.stdout?.on("data", (chunk: Buffer) => {
    configLine += chunk.toString();
    // Parse each line - the server outputs JSON on a single line
    const lines = configLine.split("\n");
    for (const line of lines) {
      try {
        const cfg = JSON.parse(line);
        if (cfg.baseURL) {
          fs.writeFileSync(serverConfigPath, JSON.stringify(cfg, null, 2));
        }
      } catch {
        // Not JSON yet, keep accumulating
      }
    }
  });

  // Store for teardown
  (globalThis as any).__e2eServerProcess = server;

  await serverReadyPromise();
  console.log("[globalSetup] Test server is ready");

  // Verify config file was written
  if (!fs.existsSync(serverConfigPath)) {
    throw new Error("Server config file was not written");
  }
}

export default globalSetup;
