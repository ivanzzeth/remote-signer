import { type FormEvent, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { setCredentials } from "../lib/auth";
import { parsePrivateKey } from "../lib/crypto";

/**
 * Credential import screen. The threat model documented in
 * docs/architecture: this page accepts the unwrapped private key bytes;
 * static encryption is handled out-of-band by `remote-signer keystore`.
 * The bytes never leave the browser tab — refresh discards them.
 */
export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const intendedPath =
    (location.state as { from?: string } | null)?.from ?? "/";

  const [apiKeyID, setApiKeyID] = useState("admin");
  const [keyInput, setKeyInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const seed = parsePrivateKey(keyInput);
      await setCredentials(apiKeyID.trim(), seed);
      navigate(intendedPath, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
        <h1 className="text-lg font-semibold text-ink-900">
          Import API key
        </h1>
        <p className="mt-1 text-sm text-ink-500">
          Paste an Ed25519 private key (hex) or a PKCS#8 PEM file —{" "}
          <code className="font-mono text-xs">admin.key.priv</code> works.
          The key is held in memory for this tab only.
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
              <span>Private key (hex or PEM)</span>
              <label className="cursor-pointer text-accent-600 hover:text-accent-500">
                <input
                  type="file"
                  className="hidden"
                  accept=".priv,.pem,.txt,application/x-pem-file"
                  onChange={onFileChange}
                />
                Load file…
              </label>
            </label>
            <textarea
              id="key-input"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              required
              rows={6}
              spellCheck={false}
              autoComplete="off"
              placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"
              className="block w-full rounded-md border border-ink-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            />
          </div>

          {error && (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !keyInput.trim()}
            className="w-full rounded-md bg-accent-500 px-3 py-2 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            {submitting ? "Verifying…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
