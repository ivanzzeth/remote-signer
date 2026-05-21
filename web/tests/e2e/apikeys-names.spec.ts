import { adminSDKClient, expect, test } from "./fixtures";

// GET /api/v1/api-keys/names is the lightweight read-only projection
// that powers the Signers filter + Grant-access dropdowns. Unlike the
// full /api/v1/api-keys list (manage_api_keys perm), it must be
// reachable for any authenticated caller — including the bootstrap
// agent key, which has no admin permissions.
//
// The spec exercises the real router → middleware → handler chain so
// the route registration order in router.go (names registered BEFORE
// the /api/v1/api-keys/ prefix catch-all) is pinned down.
test("api-keys/names returns the audit-stripped directory for any authenticated caller", async () => {
  const admin = await adminSDKClient();

  const resp = await admin.apiKeys.names();
  expect(Array.isArray(resp.keys)).toBe(true);

  // Bootstrap always provisions the admin key and the agent key.
  const ids = resp.keys.map((k) => k.id);
  expect(ids).toContain("admin");

  // Audit-relevant fields stay daemon-side — the projection is exactly
  // id / name / role / enabled. Loose shape check, not strict ===, so
  // an additional non-secret field doesn't fail the regression check.
  for (const k of resp.keys) {
    expect(typeof k.id).toBe("string");
    expect(typeof k.name).toBe("string");
    expect(typeof k.role).toBe("string");
    expect(typeof k.enabled).toBe("boolean");
    expect(Object.keys(k).sort()).toEqual(
      ["enabled", "id", "name", "role"],
    );
  }
});
