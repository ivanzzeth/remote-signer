import { type FullConfig } from "@playwright/test";

async function globalTeardown(_config: FullConfig) {
  // Stop the dApp file server
  const dappServer = globalThis.__dappFileServer;
  if (dappServer) {
    await new Promise<void>((resolve) => dappServer.close(() => resolve()));
  }

  const proc = globalThis.__e2eServerProcess;
  if (proc?.pid) {
    console.log("[global-teardown] Stopping e2e-test-server...");
    proc.kill("SIGTERM");

    // Wait up to 5 seconds for graceful shutdown
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        proc.kill("SIGKILL");
        resolve();
      }, 5_000);
      proc.on("close", () => {
        clearTimeout(timeout);
        resolve();
      });
    });
    console.log("[global-teardown] Server stopped");
  }
}

export default globalTeardown;
