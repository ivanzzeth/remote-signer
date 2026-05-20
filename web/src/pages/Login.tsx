import { type FormEvent, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { parsePrivateKey } from "remote-signer-client";
import {
  clearStoredKeystore,
  getStoredKeystoreID,
  getStoredKeystoreJSON,
  hasStoredKeystore,
  persistKeystore,
  setCredentials,
} from "../lib/auth";
import {
  decryptKeystore,
  encryptSeed,
  validatePassword,
} from "../lib/keystore";

// detectKeystoreJSON returns true when the operator's pasted/uploaded key
// material looks like an encrypted keystore (post-cleanup the daemon ships
// these to the operator instead of plaintext PEM). The detection is
// shape-based, not parse-strict — we only need to decide which input mode
// the form is in; the actual decrypt happens on submit and surfaces a
// proper error if the file is malformed.
function detectKeystoreJSON(input: string): boolean {
  const trimmed = input.trim();
  if (!trimmed.startsWith("{")) return false;
  try {
    const parsed = JSON.parse(trimmed);
    return (
      typeof parsed === "object" &&
      parsed !== null &&
      "crypto" in parsed &&
      "version" in parsed
    );
  } catch {
    return false;
  }
}

/**
 * Credential screen. Two modes, switched on whether a previous session
 * left a password-encrypted keystore in localStorage:
 *
 *   - Returning user (keystore present):   "Enter password" → Unlock.
 *   - First time (no keystore):            paste private key + set
 *                                          strong password → encrypted and
 *                                          stored locally.
 *
 * The "keystore" mechanism is intentionally invisible in the copy — to the
 * operator it's just "we encrypted your key on this device with your
 * password". The encrypted blob never leaves the browser; the daemon
 * sees the same Ed25519 seed it did before.
 */
export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const intendedPath =
    (location.state as { from?: string } | null)?.from ?? "/";

  // Mode is set once on mount — refreshing after a reset returns to first-
  // time mode, refreshing after persist returns to unlock mode.
  const [mode, setMode] = useState<"unlock" | "onboard">(() =>
    hasStoredKeystore() ? "unlock" : "onboard",
  );

  if (mode === "unlock") {
    return (
      <UnlockForm
        intendedPath={intendedPath}
        navigate={navigate}
        onReset={() => {
          clearStoredKeystore();
          setMode("onboard");
        }}
      />
    );
  }
  return <OnboardForm intendedPath={intendedPath} navigate={navigate} />;
}

// ──────────────────────────────────────────────────────────────────────
// Returning-user unlock
// ──────────────────────────────────────────────────────────────────────

function UnlockForm({
  intendedPath,
  navigate,
  onReset,
}: {
  intendedPath: string;
  navigate: ReturnType<typeof useNavigate>;
  onReset: () => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const apiKeyID = getStoredKeystoreID() ?? "admin";

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const json = getStoredKeystoreJSON();
      if (!json) {
        // localStorage was wiped between mount and submit (other tab reset?)
        throw new Error("Encrypted key is gone — please import it again.");
      }
      const { seed } = await decryptKeystore(json, password);
      await setCredentials(apiKeyID, seed);
      navigate(intendedPath, { replace: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // decryptKeystore throws the literal "wrong password" on MAC mismatch;
      // surface a friendlier line without leaking which check failed.
      if (msg === "wrong password") {
        setError("Wrong password. Try again.");
      } else {
        setError(msg);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-ink-50">
      <div className="w-full max-w-md rounded-lg border border-ink-200 bg-white p-6 shadow-sm">
        <h1 className="text-lg font-semibold text-ink-900">Unlock</h1>
        <p className="mt-1 text-sm text-ink-500">
          Enter the password you set for{" "}
          <code className="font-mono text-xs">{apiKeyID}</code> on this
          device. The key is encrypted locally and never sent to the
          server.
        </p>

        <form onSubmit={onSubmit} className="mt-5 space-y-4">
          <div>
            <label
              htmlFor="unlock-password"
              className="mb-1 block text-xs font-medium text-ink-700"
            >
              Password
            </label>
            <input
              id="unlock-password"
              data-testid="unlock-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoFocus
              autoComplete="current-password"
              className="block w-full rounded-md border border-ink-300 px-3 py-1.5 text-sm shadow-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            />
          </div>

          {error && (
            <div
              data-testid="unlock-error"
              className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            data-testid="unlock-submit"
            disabled={submitting || password.length === 0}
            className="w-full rounded-md bg-accent-500 px-3 py-2 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            {submitting ? "Unlocking…" : "Unlock"}
          </button>

          <button
            type="button"
            data-testid="reset-keystore"
            onClick={() => {
              if (
                confirm(
                  "Forget the encrypted key on this device? You'll need to import the private key and set a new password again.",
                )
              ) {
                onReset();
              }
            }}
            className="block w-full text-center text-xs text-ink-500 hover:text-ink-700"
          >
            Forgot password — import a different key
          </button>
        </form>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// First-time onboarding
// ──────────────────────────────────────────────────────────────────────

function OnboardForm({
  intendedPath,
  navigate,
}: {
  intendedPath: string;
  navigate: ReturnType<typeof useNavigate>;
}) {
  const [apiKeyID, setApiKeyID] = useState("admin");
  const [keyInput, setKeyInput] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Auto-detect input shape. When the operator pastes/uploads an
  // encrypted keystore JSON we switch to a single-password flow
  // (the password they type IS the keystore's password, and we store
  // the JSON as-is in localStorage). For PEM/hex we keep the
  // set-new-password + confirm flow with the strong-policy gate.
  //
  // Recomputing on every render is cheap (one trim + try/catch parse)
  // but useMemo keeps it tidy for large pasted blobs.
  const isKeystore = useMemo(() => detectKeystoreJSON(keyInput), [keyInput]);

  // Live password-strength feedback. We render it always (not just on
  // submit) so the operator sees what's missing while typing — saves a
  // round-trip with the error banner. For keystore inputs we DON'T
  // enforce strong-policy on the prompt: the operator can't change the
  // keystore's password from the web UI, so policing it here would
  // just block them. The CLI's `keystore reencrypt` is the place to
  // raise the bar on an existing keystore.
  const passwordError =
    password && !isKeystore ? validatePassword(password) : null;
  const passwordsMismatch =
    !isKeystore && confirmPassword.length > 0 && password !== confirmPassword;

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);

    if (!isKeystore) {
      const pwErr = validatePassword(password);
      if (pwErr) {
        setError(pwErr);
        return;
      }
      if (password !== confirmPassword) {
        setError("Passwords don't match.");
        return;
      }
    } else if (password.length === 0) {
      setError("Password is required to unlock the keystore.");
      return;
    }

    setSubmitting(true);
    try {
      if (isKeystore) {
        // Keystore path: verify the password works by decrypting once.
        // On success we KEEP the original JSON in localStorage rather
        // than re-encrypting — the on-disk format and the in-browser
        // format then stay byte-identical, which means the operator
        // could later export the localStorage value back to disk
        // without going through a re-encrypt round-trip.
        const { seed, identifier } = await decryptKeystore(
          keyInput.trim(),
          password,
        );
        const id = apiKeyID.trim() || identifier;
        await setCredentials(id, seed);
        persistKeystore(id, keyInput.trim());
        navigate(intendedPath, { replace: true });
      } else {
        const seed = parsePrivateKey(keyInput);
        const keystore = await encryptSeed(seed, password, apiKeyID.trim());
        // Verify the daemon accepts this credential BEFORE persisting —
        // catches "wrong api-key-id" / "key not registered" early so the
        // operator doesn't get stuck in the unlock screen.
        await setCredentials(apiKeyID.trim(), seed);
        persistKeystore(apiKeyID.trim(), JSON.stringify(keystore));
        navigate(intendedPath, { replace: true });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // decryptKeystore throws the literal "wrong password" on MAC
      // mismatch; rewrap so the operator doesn't see internal jargon.
      if (msg === "wrong password") {
        setError("Wrong password for the keystore.");
      } else {
        setError(msg);
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      const text = await file.text();
      setKeyInput(text);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      e.target.value = "";
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-ink-50">
      <div className="w-full max-w-md rounded-lg border border-ink-200 bg-white p-6 shadow-sm">
        <h1 className="text-lg font-semibold text-ink-900">Import API key</h1>
        <p className="mt-1 text-sm text-ink-500">
          Paste an encrypted keystore (.json), an Ed25519 private key
          (hex), or a PKCS#8 PEM file. The key is encrypted locally with
          your password so the next visit only needs the password.
        </p>

        <form onSubmit={onSubmit} className="mt-5 space-y-4">
          <div>
            <label
              htmlFor="api-key-id"
              className="mb-1 block text-xs font-medium text-ink-700"
            >
              API key ID
            </label>
            <input
              id="api-key-id"
              data-testid="onboard-api-key-id"
              type="text"
              value={apiKeyID}
              onChange={(e) => setApiKeyID(e.target.value)}
              required
              autoComplete="off"
              className="block w-full rounded-md border border-ink-300 px-3 py-1.5 text-sm shadow-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            />
          </div>

          <div>
            <label
              htmlFor="key-input"
              className="mb-1 flex items-center justify-between text-xs font-medium text-ink-700"
            >
              <span>
                {isKeystore
                  ? "Encrypted keystore (detected)"
                  : "Private key (hex or PEM)"}
              </span>
              <label className="cursor-pointer text-accent-600 hover:text-accent-500">
                <input
                  type="file"
                  className="hidden"
                  // Intentionally no `accept` filter. macOS pickers grey
                  // out files whose system-assigned MIME doesn't match a
                  // single hint — `.priv` has no built-in MIME on macOS,
                  // and any listed `accept=` value left the file un-
                  // selectable in practice. The Load-file affordance is
                  // carried by the button label; bad input is caught
                  // downstream by the parser with a clear error.
                  onChange={onFileChange}
                />
                Load file…
              </label>
            </label>
            <textarea
              id="key-input"
              data-testid="onboard-key-input"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              required
              rows={5}
              spellCheck={false}
              autoComplete="off"
              placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----&#10;&#10;or paste the contents of an encrypted keystore .json"
              className="block w-full rounded-md border border-ink-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            />
            {isKeystore && (
              <p
                data-testid="onboard-keystore-detected"
                className="mt-1 text-xs text-ink-500"
              >
                Encrypted keystore detected — enter the password it was
                created with.
              </p>
            )}
          </div>

          <div>
            <label
              htmlFor="onboard-password"
              className="mb-1 block text-xs font-medium text-ink-700"
            >
              {isKeystore ? "Keystore password" : "New password"}
            </label>
            <input
              id="onboard-password"
              data-testid="onboard-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete={isKeystore ? "current-password" : "new-password"}
              className="block w-full rounded-md border border-ink-300 px-3 py-1.5 text-sm shadow-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            />
            {!isKeystore && (
              <p
                data-testid="onboard-password-help"
                className={`mt-1 text-xs ${
                  passwordError ? "text-red-600" : "text-ink-500"
                }`}
              >
                {passwordError ??
                  "At least 10 characters with lowercase, uppercase, digit, and special character."}
              </p>
            )}
          </div>

          {!isKeystore && (
            <div>
              <label
                htmlFor="onboard-password-confirm"
                className="mb-1 block text-xs font-medium text-ink-700"
              >
                Confirm password
              </label>
              <input
                id="onboard-password-confirm"
                data-testid="onboard-password-confirm"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                autoComplete="new-password"
                className="block w-full rounded-md border border-ink-300 px-3 py-1.5 text-sm shadow-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
              />
              {passwordsMismatch && (
                <p className="mt-1 text-xs text-red-600">
                  Passwords don't match.
                </p>
              )}
            </div>
          )}

          {error && (
            <div
              data-testid="onboard-error"
              className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            data-testid="onboard-submit"
            disabled={
              submitting ||
              !keyInput.trim() ||
              !password ||
              (!isKeystore &&
                (passwordError !== null ||
                  passwordsMismatch ||
                  !confirmPassword))
            }
            className="w-full rounded-md bg-accent-500 px-3 py-2 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            {submitting
              ? isKeystore
                ? "Unlocking…"
                : "Encrypting…"
              : isKeystore
                ? "Unlock & remember this device"
                : "Sign in & remember this device"}
          </button>
        </form>
      </div>
    </div>
  );
}
