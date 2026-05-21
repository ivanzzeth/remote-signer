/**
 * Structured logger for the Remote Signer extension.
 *
 * Goal: every chokepoint in the dApp → content-script → background →
 * daemon flow logs a one-line, parse-able event with a consistent
 * shape, so a bug report that says "approval failed" lands in the SW
 * console with enough context to identify the failing layer without a
 * second user round-trip.
 *
 * Format:
 *
 *     [HH:MM:SS.mmm] [<level>] [<source>] <msg> {field: value, ...}
 *
 * `source` is the producer (bg / content-script / inpage). The fields
 * object is the structured payload — keep keys stable so a future
 * filter ("show me every dApp call that failed with code 4100") can
 * grep on names rather than substrings.
 *
 * Level is set via chrome.storage.local under the key
 * `remote-signer:log-level` — debug / info / warn / error. Default
 * "info" keeps prod consoles quiet but still captures errors and
 * every dApp method dispatched. Operators investigating an
 * intermittent issue flip it to "debug" without rebuilding.
 *
 * This module is the single owner of console.log/warn/error in the
 * extension. Direct console calls outside helper UX hooks should be
 * rewritten to go through here so the level filter applies uniformly.
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const STORAGE_KEY = "remote-signer:log-level";

// Module-level cache so the hot path (one log call per dApp request)
// doesn't hit chrome.storage. Refreshed at boot + whenever
// storage.onChanged fires for the key.
let currentLevel: LogLevel = "info";

function loadLevel(): void {
  try {
    chrome.storage?.local.get(STORAGE_KEY, (r) => {
      const v = r?.[STORAGE_KEY];
      if (typeof v === "string" && v in LEVEL_RANK) {
        currentLevel = v as LogLevel;
      }
    });
  } catch {
    // chrome.storage isn't available in unit tests / non-extension
    // contexts; keep the default in that case.
  }
}

try {
  chrome.storage?.onChanged?.addListener?.((changes, area) => {
    if (area !== "local") return;
    const change = changes[STORAGE_KEY];
    if (!change) return;
    const v = change.newValue;
    if (typeof v === "string" && v in LEVEL_RANK) {
      currentLevel = v as LogLevel;
    }
  });
} catch {
  /* same — non-extension contexts */
}

loadLevel();

function fmtTimestamp(): string {
  // HH:MM:SS.mmm — short enough to skim, precise enough to
  // correlate with daemon logs that print to the millisecond.
  const d = new Date();
  const pad = (n: number, w = 2) => n.toString().padStart(w, "0");
  return (
    pad(d.getHours()) +
    ":" +
    pad(d.getMinutes()) +
    ":" +
    pad(d.getSeconds()) +
    "." +
    pad(d.getMilliseconds(), 3)
  );
}

function emit(
  level: LogLevel,
  source: string,
  msg: string,
  fields?: Record<string, unknown>,
): void {
  if (LEVEL_RANK[level] < LEVEL_RANK[currentLevel]) return;
  const prefix = `[${fmtTimestamp()}] [${level}] [${source}] ${msg}`;
  const fn =
    level === "error" ? console.error
    : level === "warn" ? console.warn
    : console.log;
  if (fields && Object.keys(fields).length > 0) {
    fn(prefix, fields);
  } else {
    fn(prefix);
  }
}

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

/**
 * Build a logger pinned to a `source` label. Use one per module
 * (e.g. `const log = createLogger("bg.permission")` for the
 * permission-acquisition path) so the source field stays specific
 * enough to grep without restating it at every call site.
 */
export function createLogger(source: string): Logger {
  return {
    debug: (msg, fields) => emit("debug", source, msg, fields),
    info: (msg, fields) => emit("info", source, msg, fields),
    warn: (msg, fields) => emit("warn", source, msg, fields),
    error: (msg, fields) => emit("error", source, msg, fields),
  };
}

/**
 * Programmatic level setter — used by the popup's diagnostic toggle.
 * Writes through to chrome.storage so the change survives SW restarts
 * and is picked up by content-script / inpage on the next page load.
 */
export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
  try {
    chrome.storage?.local.set({ [STORAGE_KEY]: level });
  } catch {
    /* same as loadLevel */
  }
}

export function getLogLevel(): LogLevel {
  return currentLevel;
}

/**
 * Best-effort normaliser for error objects — collapses Error,
 * ProviderRpcError, plain rejection values, and string throws into
 * a uniform shape so the structured-fields object is predictable.
 */
export function describeError(err: unknown): Record<string, unknown> {
  if (err == null) return { error: null };
  if (err instanceof Error) {
    const out: Record<string, unknown> = {
      message: err.message,
      name: err.name,
    };
    const code = (err as { code?: unknown }).code;
    if (code !== undefined) out.code = code;
    const data = (err as { data?: unknown }).data;
    if (data !== undefined) out.data = data;
    if (err.stack) out.stack = err.stack.split("\n").slice(0, 3).join("\n");
    return out;
  }
  if (typeof err === "object") return { ...(err as Record<string, unknown>) };
  return { message: String(err) };
}
