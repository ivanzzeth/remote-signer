import { spawn, type ChildProcessByStdio } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

// __dirname isn't defined in the ESM context tsx uses; reconstruct from
// import.meta. The web/ workspace is "type": "module".
const __dirname = dirname(fileURLToPath(import.meta.url));

// Path emitted by globalSetup and consumed by tests + globalTeardown.
const STATE_ENV = "E2E_STATE";
const PORT = Number(process.env.E2E_PORT ?? 18548);

export interface E2EState {
  home: string;
  pid: number;
  binary: string;
}

declare global {
  // eslint-disable-next-line no-var
  var __E2E_DAEMON__: ChildProcessByStdio<null, Readable, Readable> | undefined;
}

async function waitForHealth(url: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`daemon never became healthy on ${url}`);
}

export default async function globalSetup(): Promise<void> {
  // Resolve the binary relative to web/ — Playwright runs from web/ as cwd
  // when invoked via `npm run test:e2e`. The Go build target writes to repo
  // root, which is ../ from here.
  const binary = resolve(__dirname, "../../../remote-signer");

  // Isolated home so the test daemon never touches the developer's actual
  // ~/.remote-signer (own SQLite, own admin key, own audit log).
  const home = mkdtempSync(join(tmpdir(), "remote-signer-e2e-"));

  // Pre-write config.yaml so the daemon binds to PORT instead of 8548.
  // Other knobs we'd otherwise auto-generate (logger pretty=false to keep
  // test output readable, chains/keystore_dir relative to $HOME) get filled
  // in by the daemon's bootstrap path on first launch.
  const cfg = `
server:
  host: 127.0.0.1
  port: ${PORT}
  read_timeout: 30s
  write_timeout: 30s
  tls:
    enabled: false

database:
  dsn: "file:${home}/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000"

logger:
  level: warn
  pretty: false

chains:
  evm:
    enabled: true
    keystore_dir: "${home}/keystores"
    hd_wallet_dir: "${home}/hd-wallets"
`;
  writeFileSync(join(home, "config.yaml"), cfg.trimStart());

  const proc = spawn(binary, ["server", "start"], {
    env: { ...process.env, REMOTE_SIGNER_HOME: home },
    stdio: ["ignore", "pipe", "pipe"],
  });

  // Stream daemon output through to Playwright's stdout when E2E_DEBUG is
  // set — otherwise stay quiet. Stderr always flows on test failures, kept
  // in the trace zip.
  if (process.env.E2E_DEBUG) {
    proc.stdout.on("data", (b) => process.stdout.write(`[daemon] ${b}`));
    proc.stderr.on("data", (b) => process.stderr.write(`[daemon] ${b}`));
  } else {
    proc.stdout.on("data", () => undefined);
    proc.stderr.on("data", () => undefined);
  }

  globalThis.__E2E_DAEMON__ = proc;

  await waitForHealth(`http://127.0.0.1:${PORT}/health`);

  const state: E2EState = { home, pid: proc.pid!, binary };
  process.env[STATE_ENV] = JSON.stringify(state);
}

export function getState(): E2EState {
  const raw = process.env[STATE_ENV];
  if (!raw) throw new Error("E2E_STATE not set — globalSetup didn't run?");
  return JSON.parse(raw) as E2EState;
}
