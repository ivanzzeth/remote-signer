// Electron main process. The shell's job is intentionally narrow: find or
// spawn a remote-signer daemon, wait until /health responds, then open a
// BrowserWindow pointed at the daemon's HTTP root. The React UI is the
// same code served to a browser — no IPC or preload bridge needed because
// the renderer talks to the daemon over HTTP like every other client.
//
// Lifecycle:
//   1. app.whenReady → startDaemon (skip if one already responds)
//   2.                → createWindow
//   3. window-all-closed → kill the daemon (only if we spawned it)
//   4. before-quit → safety kill in case window-all-closed already
//      fired but a child is still around (eg. multi-window scenarios)

import { app, BrowserWindow, dialog, shell, Menu, MenuItemConstructorOptions } from "electron";
import { ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DAEMON_PORT = 8548;
const DAEMON_URL = `http://127.0.0.1:${DAEMON_PORT}`;
const READY_TIMEOUT_MS = 15_000;
const HEALTH_POLL_MS = 250;

// Tracks whether THIS process owns the daemon subprocess. When we attached
// to an already-running daemon, we leave it alone on quit so the operator
// can keep using the CLI.
let ownedDaemon: ChildProcess | null = null;

async function main(): Promise<void> {
  await app.whenReady();

  // Disable the GPU sandbox on macOS arm64 dev machines where Electron
  // sometimes warns; harmless to leave default in production.
  if (process.platform === "darwin") {
    app.dock?.show();
  }

  installMenu();

  try {
    await startOrAttachDaemon();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    await dialog.showMessageBox({
      type: "error",
      title: "remote-signer failed to start",
      message: "Could not start the daemon",
      detail: msg,
      buttons: ["Quit"],
    });
    app.exit(1);
    return;
  }

  await createWindow();

  app.on("activate", async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createWindow();
    }
  });
}

async function startOrAttachDaemon(): Promise<void> {
  if (await isDaemonAlive(500)) {
    // Operator already has a daemon running (CLI session, brew service,
    // etc.). Just point the window at it.
    return;
  }

  const binary = findDaemonBinary();
  if (!binary) {
    throw new Error(
      "Could not locate the remote-signer binary. " +
        "Set REMOTE_SIGNER_BIN to its absolute path, or run `make build` " +
        "and re-launch.",
    );
  }

  ownedDaemon = spawn(binary, [], {
    env: {
      ...process.env,
      REMOTE_SIGNER_HOME:
        process.env.REMOTE_SIGNER_HOME ?? join(homedir(), ".remote-signer"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  ownedDaemon.stdout?.on("data", (b: Buffer) =>
    process.stdout.write(`[daemon] ${b}`),
  );
  ownedDaemon.stderr?.on("data", (b: Buffer) =>
    process.stderr.write(`[daemon] ${b}`),
  );
  ownedDaemon.on("exit", (code, signal) => {
    console.log(`[daemon] exited (code=${code}, signal=${signal})`);
    ownedDaemon = null;
  });

  await waitForDaemon(READY_TIMEOUT_MS);
}

async function waitForDaemon(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isDaemonAlive(500)) return;
    if (ownedDaemon === null) {
      throw new Error(
        "daemon exited before becoming ready — check the launcher console for [daemon] log lines",
      );
    }
    await sleep(HEALTH_POLL_MS);
  }
  throw new Error(`daemon did not respond on ${DAEMON_URL}/health within ${timeoutMs}ms`);
}

async function isDaemonAlive(timeoutMs: number): Promise<boolean> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(`${DAEMON_URL}/health`, { signal: ctrl.signal });
    return r.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

// findDaemonBinary returns the first existing path among:
//   1. $REMOTE_SIGNER_BIN (manual override; dev workflow)
//   2. <resourcesPath>/bin/remote-signer (electron-builder extraResource)
//   3. <repo-root>/remote-signer (this is the file emitted by `make build`)
//   4. <repo-root>/dist/remote-signer (CI's local artefact dir)
// Returns null if none exist.
function findDaemonBinary(): string | null {
  const ext = process.platform === "win32" ? ".exe" : "";

  const envOverride = process.env.REMOTE_SIGNER_BIN;
  if (envOverride && existsSync(envOverride)) {
    return envOverride;
  }

  const packaged = join(process.resourcesPath, "bin", `remote-signer${ext}`);
  if (existsSync(packaged)) {
    return packaged;
  }

  // Walk up from `electron/dist/main.js` to repo root and look for the
  // freshly-built binary. Works for `npm start` runs inside the source tree.
  const devCandidates = [
    join(__dirname, "..", "..", `remote-signer${ext}`),
    join(__dirname, "..", "..", "dist", `remote-signer${ext}`),
    join(__dirname, "..", "..", "..", `remote-signer${ext}`),
  ];
  for (const p of devCandidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

async function createWindow(): Promise<void> {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: "Remote Signer",
    backgroundColor: "#f8fafc",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  // Open external links in the default browser, not in the Electron window.
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  await win.loadURL(DAEMON_URL);
}

function installMenu(): void {
  // A minimal native menu — keeps cmd+Q, cmd+R, devtools and Edit
  // shortcuts working. Electron's auto-generated menu also works but is
  // noisy ("Window → Bring All to Front" etc.).
  const isMac = process.platform === "darwin";
  const template: MenuItemConstructorOptions[] = [
    ...(isMac
      ? ([
          {
            label: app.name,
            submenu: [
              { role: "about" },
              { type: "separator" },
              { role: "hide" },
              { role: "hideOthers" },
              { role: "unhide" },
              { type: "separator" },
              { role: "quit" },
            ],
          },
        ] satisfies MenuItemConstructorOptions[])
      : []),
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
      ],
    },
    {
      label: "View",
      submenu: [
        { role: "reload" },
        { role: "forceReload" },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.on("window-all-closed", () => {
  killOwnedDaemon();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  killOwnedDaemon();
});

function killOwnedDaemon(): void {
  if (!ownedDaemon) return;
  try {
    ownedDaemon.kill("SIGTERM");
  } catch {
    // Process may have already exited; nothing actionable.
  }
  ownedDaemon = null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error("electron main: fatal", msg);
  app.exit(1);
});
