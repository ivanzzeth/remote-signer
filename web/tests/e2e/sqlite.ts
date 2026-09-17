import { execFileSync } from "node:child_process";

// 等锁时让出 CPU,而不是抢着它空转。
//
// ⛔ 这里原本是 `while (Date.now() < end) {}` —— 一个忙等自旋,实测**占满一整个核**
// (800ms 等待消耗 800.8ms CPU;换成下面这个是 0.1ms,差 8000 倍)。
//
// ⚠️ 为什么它在本地永远不出事、只在 CI 上要命:本机 16 核,自旋占 6%,daemon 毫无压力;
// CI 的 ubuntu-latest 只有 **2 核**,自旋占掉 50%,剩下一个核还要同时跑 daemon、
// Chromium 和 node —— 于是 daemon 更慢、锁更久不放、这边更久等不到,是个正反馈。
// 2026-09-16 那次 CI:同一份代码,本地 4.7 分钟 141 全过,CI 跑了 5 小时 25 分红 11 个。
//
// ⭐ Atomics.wait 是同步阻塞且不占 CPU,正是这里要的语义(sqliteExec 必须同步,
// 因为调用方是 Playwright 的同步 seeding 代码)。
function sleepMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// 等锁预算:单次 5 秒 × 4 次 + 退避 ≈ 最坏 22 秒。
//
// ⛔ 这几个数字必须一起看,单独调任何一个都会让上限失控:
//
// 1. **它必须小于 Playwright 的单测超时(默认 30 秒)**。sqliteExec 是同步阻塞,
//    它卡死 Node 事件循环,Playwright 的超时计时器**根本没机会触发** —— 所以
//    「反正 Playwright 会兜底」是错的,上限只能由这里自己保证。2026-09-16 那次
//    有十个用例各跑满 31.8 分钟没被杀掉,就是这个原因。
//
// 2. **5000 与 daemon 侧对齐**(global-setup.ts 的 `_busy_timeout=5000`)。
//    两边各等各的没有意义:daemon 自己都不会持锁超过 5 秒,除非有长事务 ——
//    而那种情况等 5 秒和等 60 秒结果一样。
//
// 3. ⚠️ 旧值是 `.timeout 60000` × 30 次 = **31.8 分钟**,而它在 CI 上是**跑满了
//    仍然失败**的。所以砍到 22 秒不会把本来能过的改红:1800 秒都没拿到的锁,
//    多等 1778 秒也拿不到,只是把失败推迟 —— 代价是一次红要烧 5 小时 CI。
const LOCK_TIMEOUT_MS = 5000;
const MAX_ATTEMPTS = 4;

/**
 * Direct SQLite writes for seeding e2e state. Retries on WAL lock contention.
 *
 * ⚠️ 这个 helper 的存在本身是个妥协:它绕开 daemon,用外部 sqlite3 去写 daemon
 * 正持有的 WAL 库,两边抢同一把写锁。真正的修法是让 seeding 走 API,但有些状态
 * (直接塞一行 `authorizing` 的 sign_request)API 造不出来。⛔ 改那个要动 4 个
 * spec,是单独的一件事,不要夹在这里顺手做。
 */
export function sqliteExec(dbPath: string, stmts: string[]): void {
  if (stmts.length === 0) return;

  const script = [
    `.timeout ${LOCK_TIMEOUT_MS}`,
    "BEGIN IMMEDIATE;",
    ...stmts.map((s) => (s.trimEnd().endsWith(";") ? s : `${s};`)),
    "COMMIT;",
  ].join("\n");

  let lastErr: unknown;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    try {
      // ⛔ stderr must be "pipe", not "inherit". With "inherit" the sqlite3
      // error text goes straight to the terminal and never reaches `err`, so
      // String(err) is only "Command failed: sqlite3 <path>" — which matches
      // none of the lock patterns below. The retry loop then re-threw on the
      // first attempt and the whole retry was dead code, while the failure
      // message named the helper rather than the lock.
      //
      // ⭐ 那个修复(6b4f20b)是对的,别动它 —— 但要知道它的副作用:在它之前这段
      // 重试是**死代码,一次都没跑过**;修好错误传递之后,`.timeout 60000 × 30`
      // 和那个忙等自旋才第一次真正执行,31.8 分钟的代价也才第一次兑现。
      // 一段被写下、被相信、却从未运行的配置,是在它被唤醒的那天才开始收费的。
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
      // 指数退避:250 / 500 / 1000 ms,合计 1.75 秒。
      sleepMs(250 * 2 ** attempt);
    }
  }
  // ⚠️ 带上「等了多久」,否则读日志的人无从判断该调预算还是该查长事务。
  const waited = (MAX_ATTEMPTS * LOCK_TIMEOUT_MS) / 1000;
  throw new Error(
    `sqlite3: WAL lock not released after ${MAX_ATTEMPTS} attempts (~${waited}s of lock waits): ${String(lastErr)}`,
  );
}
