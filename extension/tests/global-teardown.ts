import { type FullConfig } from "@playwright/test";

async function globalTeardown(_config: FullConfig) {
  // Stop dApp HTTP file server
  const dappServer = globalThis.__dappServer;
  if (dappServer) {
    console.log("[global-teardown] Stopping dApp file server...");
    await new Promise<void>((resolve) => dappServer.close(() => resolve()));
    console.log("[global-teardown] DApp file server stopped");
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

  const anvil = globalThis.__anvilProcess;
  if (anvil?.pid) {
    console.log("[global-teardown] Stopping anvil...");
    anvil.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        anvil.kill("SIGKILL");
        resolve();
      }, 5_000);
      anvil.on("close", () => {
        clearTimeout(timeout);
        resolve();
      });
    });
    console.log("[global-teardown] Anvil stopped");
  }
}

export default globalTeardown;
