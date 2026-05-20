import { type ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  clearCredentials,
  clearStoredKeystore,
  getCredentials,
  hasStoredKeystore,
} from "../lib/auth";

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const creds = getCredentials();
  const navigate = useNavigate();
  const stored = hasStoredKeystore();

  function onSignOut() {
    // Clears the in-memory seed but keeps the encrypted keystore so the
    // next visit only needs the password. The /login route detects the
    // stored keystore and goes straight to the Unlock screen.
    clearCredentials();
    navigate("/login", { replace: true });
  }

  function onForgetKey() {
    if (
      !confirm(
        "Forget the encrypted key on this device? You'll need to import the private key and set a new password again.",
      )
    ) {
      return;
    }
    clearStoredKeystore();
    clearCredentials();
    navigate("/login", { replace: true });
  }

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col gap-1 border-r border-ink-200 bg-white px-3 py-5">
        <div className="mb-4 px-3">
          <div className="text-sm font-semibold text-ink-900">
            remote-signer
          </div>
          <div className="font-mono text-xs text-ink-500">
            {creds ? creds.apiKeyID : "—"}
          </div>
        </div>

        <NavItem to="/dashboard">Dashboard</NavItem>
        <NavItem to="/signers">Signers</NavItem>
        <NavItem to="/hd-wallets">HD Wallets</NavItem>
        <NavItem to="/wallets">Wallets</NavItem>
        <NavItem to="/requests">Requests</NavItem>
        <NavItem to="/rules">Rules</NavItem>
        <NavItem to="/templates">Templates</NavItem>
        <NavItem to="/presets">Presets</NavItem>
        <NavItem to="/budgets">Budgets</NavItem>
        <NavItem to="/api-keys">API Keys</NavItem>
        <NavItem to="/audit">Audit log</NavItem>
        <NavItem to="/settings">Settings</NavItem>

        <div className="mt-auto space-y-2 border-t border-ink-200 px-3 pt-3">
          {creds && (
            <button
              type="button"
              data-testid="sign-out"
              onClick={onSignOut}
              className="block text-xs text-ink-500 hover:text-ink-900"
            >
              Sign out
            </button>
          )}
          {stored && (
            <button
              type="button"
              data-testid="forget-key"
              onClick={onForgetKey}
              className="block text-xs text-red-600 hover:text-red-800"
            >
              Forget encrypted key
            </button>
          )}
        </div>
      </aside>
      <main className="flex-1 overflow-auto bg-ink-50">
        <div className="mx-auto max-w-5xl p-8">{children}</div>
      </main>
    </div>
  );
}

function NavItem({ to, children }: { to: string; children: ReactNode }) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        [
          "rounded-md px-3 py-1.5 text-sm transition",
          isActive
            ? "bg-accent-500 text-white"
            : "text-ink-700 hover:bg-ink-100",
        ].join(" ")
      }
    >
      {children}
    </NavLink>
  );
}
