import { execFileSync } from "node:child_process";

function sleepMs(ms: number): void {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    /* spin until WAL lock clears */
  }
}

/** Direct SQLite writes for seeding e2e state. Retries on WAL lock contention. */
export function sqliteExec(dbPath: string, stmts: string[]): void {
  if (stmts.length === 0) return;

  const script = [
    ".timeout 60000",
    "BEGIN IMMEDIATE;",
    ...stmts.map((s) => (s.trimEnd().endsWith(";") ? s : `${s};`)),
    "COMMIT;",
  ].join("\n");

  let lastErr: unknown;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      // ⛔ stderr must be "pipe", not "inherit". With "inherit" the sqlite3
      // error text goes straight to the terminal and never reaches `err`, so
      // String(err) is only "Command failed: sqlite3 <path>" — which matches
      // none of the lock patterns below. The retry loop then re-threw on the
      // first attempt and the whole retry was dead code, while the failure
      // message named the helper rather than the lock.
      execFileSync("sqlite3", [dbPath], {
        input: script,
        stdio: ["pipe", "ignore", "pipe"],
      });
      return;
    } catch (err) {
      lastErr = err;
      const e = err as { stderr?: Buffer | string; message?: string };
      const msg = `${e.message ?? ""} ${e.stderr?.toString() ?? ""}`;
      if (
        !msg.includes("database is locked") &&
        !msg.includes("locked (5)") &&
        !msg.includes("SQLITE_BUSY")
      ) {
        // ⚠️ Re-thrown with the actual sqlite3 output attached. Without it the
        // test reports "Command failed: sqlite3 /tmp/…" and nothing else.
        throw new Error(`sqlite3 failed: ${msg.trim()}`);
      }
      sleepMs(500 + attempt * 200);
    }
  }
  throw lastErr;
}
