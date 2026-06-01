import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "./fixtures";
import { getState } from "./global-setup";

// The web/tests/e2e harness daemon doesn't ship a configured
// simulator (no anvil-backed eth_simulateV1, no upstream gateway
// guaranteed reachable), so the simulation pipeline never produces
// a row on its own. We seed the row directly via the daemon's
// SQLite file — that's not the same as a production live-simulation
// test, but it pins the bit that's actually interesting here: the
// frontend polls, the panel renders, the auto-refresh stops on
// terminal state. The simulation engine itself has unit + backend
// integration coverage on its own.

test.describe("SimulationPreview on RequestDetail", () => {
  test("renders simulation row + decoded fields once seeded", async ({
    authedPage,
  }) => {
    // 1. Seed a sign request that the UI will open. We use the
    //    raw HTTP request through the SDK transport instead of
    //    going via sign.execute (which would try to actually sign);
    //    a manual insert keeps the test independent of any signer
    //    configuration.
    const home = getState().home;
    const dbPath = join(home, "remote-signer.db");
    const requestID = `req-sim-preview-${Date.now()}`;

    // SignRequest row. Columns must match types.SignRequest's Gorm
    // schema. Keeping the column list short on purpose — anything
    // not asserted on stays at its column default.
    const now = new Date().toISOString();
    sqliteExec(dbPath, [
      `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, created_at, updated_at)
       VALUES ('${requestID}', 'admin', 'evm', '56', '0xdeadbeef', 'transaction', 'authorizing', '${now}', '${now}')`,
    ]);

    // RequestSimulation row — matches the table created by
    // types.RequestSimulation's auto-migrate. JSON columns get
    // valid JSON literals so reading-side decoders don't choke.
    sqliteExec(dbPath, [
      `INSERT INTO request_simulations
         (sign_request_id, chain_id, decision, reason, success, gas_used, revert_reason,
          balance_changes, events, contracts, decoded_calldata, raw_result,
          simulated_at, updated_at)
       VALUES ('${requestID}', '56', 'allow', '', 1, 287453, '',
         '[{"token":"native","standard":"native","amount":"-1000000","direction":"outflow"}]',
         '[{"address":"0xabc","event":"Transfer","standard":"erc20","args":{"from":"0x1","to":"0x2","amount":"1"}}]',
         '["0xabc","0xdef"]',
         '{}', '{}',
         '${now}', '${now}')`,
    ]);

    // 2. Navigate to the request detail page; the panel polls
    //    /api/v1/evm/requests/{id}/simulation on mount.
    // SPA-internal navigation — using page.goto would do a hard
    // reload and lose the decrypted in-memory keystore the fixture
    // just set up, bouncing us to /login.
    await authedPage.evaluate((id) => {
      window.history.pushState({}, "", `/requests/${id}`);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, requestID);

    // 3. The Simulation preview heading + decision badge land within
    //    a couple seconds of mount (first poll fires immediately,
    //    daemon roundtrip is single-digit ms in test).
    await expect(authedPage.getByText("Simulation preview")).toBeVisible({
      timeout: 5_000,
    });
    await expect(authedPage.getByText("would auto-approve")).toBeVisible();
    // Gas + balance change + contracts touched all surface from the
    // seeded row.
    await expect(authedPage.getByText("287,453")).toBeVisible();
    await expect(authedPage.getByText(/Balance changes/i)).toBeVisible();
    await expect(authedPage.getByText(/Contracts touched/i)).toBeVisible();
    await expect(authedPage.getByText("0xabc")).toBeVisible();

    // 4. Sanity: the auto-refresh indicator names a fresh fetch.
    await expect(authedPage.getByText(/auto-refresh/i)).toBeVisible();
  });

  test("renders 'evaluating' loading state when no simulation row exists", async ({
    authedPage,
  }) => {
    // The handler returns 404 with "not yet available" message
    // when the simulation hasn't run yet. The panel must render a
    // spinner instead of treating it as a hard error — pre-fix the
    // SDK would have surfaced it as an APIError.
    const home = getState().home;
    const dbPath = join(home, "remote-signer.db");
    const requestID = `req-sim-evaluating-${Date.now()}`;
    const now = new Date().toISOString();
    sqliteExec(dbPath, [
      `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, created_at, updated_at)
       VALUES ('${requestID}', 'admin', 'evm', '56', '0xdeadbeef', 'transaction', 'authorizing', '${now}', '${now}')`,
    ]);

    // SPA-internal navigation — using page.goto would do a hard
    // reload and lose the decrypted in-memory keystore the fixture
    // just set up, bouncing us to /login.
    await authedPage.evaluate((id) => {
      window.history.pushState({}, "", `/requests/${id}`);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, requestID);
    await expect(authedPage.getByText("Simulation preview")).toBeVisible({
      timeout: 5_000,
    });
    // Pin to the exact spinner copy. A loose /Evaluating/i regex
    // would also match the seeded request id ("req-sim-evaluating-…")
    // and pass even if the spinner never rendered.
    await expect(
      authedPage.getByText("Evaluating… first simulation takes a few seconds."),
    ).toBeVisible();
  });

  test("hides preview for non-transaction sign types", async ({
    authedPage,
  }) => {
    // typed_data / personal_sign requests don't go through the
    // simulation pipeline (no calldata to simulate). The panel
    // must NOT render for them — otherwise operators see an
    // "evaluating" spinner that never resolves.
    const home = getState().home;
    const dbPath = join(home, "remote-signer.db");
    const requestID = `req-sim-typed-${Date.now()}`;
    const now = new Date().toISOString();
    sqliteExec(dbPath, [
      `INSERT INTO sign_requests (id, api_key_id, chain_type, chain_id, signer_address, sign_type, status, created_at, updated_at)
       VALUES ('${requestID}', 'admin', 'evm', '56', '0xdeadbeef', 'typed_data', 'authorizing', '${now}', '${now}')`,
    ]);

    // SPA-internal navigation — using page.goto would do a hard
    // reload and lose the decrypted in-memory keystore the fixture
    // just set up, bouncing us to /login.
    await authedPage.evaluate((id) => {
      window.history.pushState({}, "", `/requests/${id}`);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, requestID);
    // The Request card mounts; the Simulation preview does NOT.
    await expect(authedPage.getByText("Request ID")).toBeVisible({
      timeout: 5_000,
    });
    await expect(authedPage.getByText("Simulation preview")).toHaveCount(0);
  });
});

// sqliteExec shells out to the system sqlite3 CLI to run a sequence
// of SQL statements. macOS + Linux runners both ship sqlite3; the
// daemon's WAL mode means concurrent writes from this process don't
// block the daemon's own queries.
function sqliteExec(dbPath: string, stmts: string[]): void {
  for (const stmt of stmts) {
    // `.timeout` makes the CLI wait for the daemon's WAL write lock instead of
    // failing instantly with "database is locked" — the daemon runs concurrently
    // and may hold the lock when these direct writes fire.
    execFileSync("sqlite3", ["-cmd", ".timeout 10000", dbPath, stmt], {
      stdio: ["ignore", "ignore", "inherit"],
    });
  }
}
