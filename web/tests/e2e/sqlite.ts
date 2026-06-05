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
      execFileSync("sqlite3", [dbPath], {
        input: script,
        stdio: ["pipe", "ignore", "inherit"],
      });
      return;
    } catch (err) {
      lastErr = err;
      const msg = String(err);
      if (
        !msg.includes("database is locked") &&
        !msg.includes("locked (5)") &&
        !msg.includes("SQLITE_BUSY")
      ) {
        throw err;
      }
      sleepMs(500 + attempt * 200);
    }
  }
  throw lastErr;
}
