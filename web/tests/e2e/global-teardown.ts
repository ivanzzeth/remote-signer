export default async function globalTeardown(): Promise<void> {
  const proc = globalThis.__E2E_DAEMON__;
  if (!proc || proc.killed) return;
  proc.kill("SIGTERM");
  // Give it a beat to flush, then force.
  await new Promise((r) => setTimeout(r, 500));
  if (!proc.killed) proc.kill("SIGKILL");
}
