import { ChildProcess } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

declare global {
  // eslint-disable-next-line no-var
  var __e2eServerProcess: ChildProcess | undefined;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function globalTeardown() {
  const server = (globalThis as any).__e2eServerProcess as ChildProcess | undefined;
  if (server) {
    console.log("[globalTeardown] Stopping test server...");
    server.kill("SIGTERM");

    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        console.log("[globalTeardown] Force killing server...");
        server.kill("SIGKILL");
        resolve();
      }, 5_000);

      server.on("close", () => {
        clearTimeout(timeout);
        resolve();
      });
    });

    console.log("[globalTeardown] Test server stopped");
  }

  // Clean up config file
  const configPath = path.join(__dirname, ".server-config.json");
  try {
    fs.unlinkSync(configPath);
  } catch {
    // File may not exist
  }
}

export default globalTeardown;
