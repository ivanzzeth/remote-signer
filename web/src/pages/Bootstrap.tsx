import { type FormEvent, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { persistKeystore, setCredentials } from "../lib/auth";
import { decryptKeystore, validatePassword } from "../lib/keystore";

/**
 * Bootstrap is the first-run setup form. It's shown when the daemon
 * reports `needs_bootstrap=true` on GET /api/v1/bootstrap/status —
 * meaning no admin api_keys row exists yet and no
 * REMOTE_SIGNER_KEYSTORE_PASSWORD was supplied at startup. The form:
 *
 *   1. Collects a new admin keystore password (with confirmation).
 *   2. Posts it to POST /api/v1/bootstrap/admin. The daemon creates the
 *      encrypted keystore on its own disk and returns the JSON content.
 *   3. Persists the returned keystore into localStorage (same shape the
 *      regular Login flow stores) and unlocks the session in one shot,
 *      so the operator lands directly on the dashboard.
 *
 * Why this exists: docker/launchd/systemd deployments don't have a TTY
 * for the daemon's old "Enter password" prompt and shouldn't be forced
 * to ship a password as an environment variable. This route closes that
 * gap by moving the password handoff into the browser — TLS-encrypted
 * (or localhost) and limited to a single fire of an unauth POST that
 * the daemon refuses (410 Gone) the second time around.
 *
 * Security caveats surfaced to the operator inline:
 *
 *   - The password protects the encrypted keystore on the daemon's
 *     disk. There is no recovery: lose it and the admin role goes with
 *     it. The same password is then used to wrap the local copy stored
 *     in localStorage so the dashboard can re-unlock it later.
 *   - The form will not submit until the password meets the same
 *     strength check the regular keystore-creation flow applies
 *     (validatePassword in lib/keystore).
 */
export function Bootstrap() {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const passwordError = useMemo(
    () => (password ? validatePassword(password) : null),
    [password],
  );
  const confirmError = useMemo(() => {
    if (!confirm) return null;
    if (confirm !== password) return "passwords do not match";
    return null;
  }, [confirm, password]);

  const canSubmit =
    !submitting &&
    password.length > 0 &&
    confirm.length > 0 &&
    !passwordError &&
    !confirmError;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setError(null);
    setSubmitting(true);
    try {
      const resp = await fetch("/api/v1/bootstrap/admin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (resp.status === 410) {
        // Someone else completed bootstrap between our status check
        // and this submit. Reload to drop into the login page.
        setError(
          "admin already configured. Reloading to the login page…",
        );
        setTimeout(() => window.location.reload(), 2000);
        return;
      }
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(
          `bootstrap failed (HTTP ${resp.status}): ${text || "no body"}`,
        );
      }
      const data: {
        status: string;
        keystore_path: string;
        public_key_hex: string;
        keystore_json?: string;
      } = await resp.json();

      if (!data.keystore_json) {
        // Backend couldn't return the keystore content (read-back
        // failure). Fall back to telling the operator where the file
        // landed so they can paste it manually on the login page.
        setError(
          `Bootstrap succeeded, but the keystore content wasn't returned. ` +
            `Copy ${data.keystore_path} off the daemon and use the login page.`,
        );
        setSubmitting(false);
        return;
      }

      // Unlock the just-issued keystore client-side with the same
      // password the operator just typed. Mirrors the Login flow's
      // "paste keystore JSON + password" path.
      const { seed } = await decryptKeystore(data.keystore_json, password);
      await setCredentials("admin", seed);
      persistKeystore("admin", data.keystore_json);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-ink-50 px-4 py-12">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md space-y-6 rounded-lg border border-ink-200 bg-white p-8 shadow-sm"
      >
        <header className="space-y-2">
          <h1 className="text-xl font-semibold text-ink-900">
            First-run setup
          </h1>
          <p className="text-sm text-ink-600">
            Pick a password for the admin keystore. The daemon will encrypt
            its API signing key with this password and store it under
            <code className="mx-1 rounded bg-ink-100 px-1 py-0.5 text-xs">
              ~/.remote-signer/apikeys/admin.keystore.json
            </code>
            . You'll need it every time you re-open this page.
          </p>
          <p className="text-xs text-amber-700">
            There's no recovery if you lose this password. The encrypted
            keystore is the only persistent copy of the admin key.
          </p>
        </header>

        <div className="space-y-2">
          <label
            htmlFor="bootstrap-password"
            className="block text-sm font-medium text-ink-800"
          >
            New admin password
          </label>
          <input
            id="bootstrap-password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-md border border-ink-300 px-3 py-2 text-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            disabled={submitting}
            required
          />
          {passwordError && (
            <p className="text-xs text-red-600">{passwordError}</p>
          )}
        </div>

        <div className="space-y-2">
          <label
            htmlFor="bootstrap-confirm"
            className="block text-sm font-medium text-ink-800"
          >
            Confirm password
          </label>
          <input
            id="bootstrap-confirm"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="w-full rounded-md border border-ink-300 px-3 py-2 text-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            disabled={submitting}
            required
          />
          {confirmError && (
            <p className="text-xs text-red-600">{confirmError}</p>
          )}
        </div>

        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-800">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full rounded-md bg-accent-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-accent-700 disabled:cursor-not-allowed disabled:bg-ink-300"
        >
          {submitting ? "Creating admin keystore…" : "Create admin & continue"}
        </button>
      </form>
    </div>
  );
}
