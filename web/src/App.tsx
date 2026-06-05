import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/Layout";
import { getCredentials, subscribeAuth } from "./lib/auth";
import { ApiKeys } from "./pages/ApiKeys";
import { Audit } from "./pages/Audit";
import { Bootstrap } from "./pages/Bootstrap";
import { BudgetDetail } from "./pages/BudgetDetail";
import { Budgets } from "./pages/Budgets";
import { Dashboard } from "./pages/Dashboard";
import { HDWallets } from "./pages/HDWallets";
import { Login } from "./pages/Login";
import { PresetDetail } from "./pages/PresetDetail";
import { Presets } from "./pages/Presets";
import { RequestDetail } from "./pages/RequestDetail";
import { Requests } from "./pages/Requests";
import { Rules } from "./pages/Rules";
import { Settings } from "./pages/Settings";
import { Signers } from "./pages/Signers";
import { Simulate } from "./pages/Simulate";
import { TemplateDetail } from "./pages/TemplateDetail";
import { Templates } from "./pages/Templates";
import { TransactionDetail } from "./pages/TransactionDetail";
import { Transactions } from "./pages/Transactions";
import { Wallets } from "./pages/Wallets";

/**
 * Top-level shell. The router takes one of three shapes:
 *
 * - Unauthenticated → /login (and any other path redirects there)
 * - Authenticated   → Layout-wrapped routes (dashboard, etc.)
 *
 * Auth state lives in module scope (lib/auth) and updates fire a subscriber
 * callback, which we wire into a React state update so the router re-renders
 * the moment credentials are imported or cleared.
 */
export function App() {
  const [authed, setAuthed] = useState(() => getCredentials() !== null);
  // needsBootstrap is one of three states:
  //   null     — still checking GET /api/v1/bootstrap/status
  //   true     — daemon has no admin api_keys row yet; force Bootstrap page
  //   false    — admin exists; normal auth flow
  // Network/parsing errors fall through to `false` so a transient failure
  // doesn't lock new users out of login — they'll see the login page and
  // their attempt will surface the real error (401, etc.).
  const [needsBootstrap, setNeedsBootstrap] = useState<boolean | null>(null);

  useEffect(() => {
    return subscribeAuth(() => setAuthed(getCredentials() !== null));
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/v1/bootstrap/status", { headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : Promise.reject(r.statusText)))
      .then((data: { needs_bootstrap?: boolean }) => {
        if (!cancelled) {
          setNeedsBootstrap(Boolean(data.needs_bootstrap));
        }
      })
      .catch(() => {
        if (!cancelled) setNeedsBootstrap(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Order matters: once the operator has a valid credential, the
  // bootstrap state is no longer relevant — a populated `authed` means
  // the daemon must have an admin row (otherwise the credentials would
  // have failed to load). Checking authed before needsBootstrap also
  // closes a render loop: the Bootstrap page calls setCredentials() on
  // success, which flips `authed` to true before the next bootstrap-
  // status refetch could even fire, so we go straight to the dashboard.
  if (!authed) {
    if (needsBootstrap === null) {
      // Brief blocking spinner while we figure out which mode we're
      // in. Without this the login form would flash, then yank over
      // to the bootstrap page once the fetch returns — confusing on
      // slow links.
      return (
        <div className="flex min-h-screen items-center justify-center bg-ink-50 text-sm text-ink-500">
          Loading…
        </div>
      );
    }

    if (needsBootstrap) {
      return (
        <Routes>
          <Route path="/bootstrap" element={<Bootstrap />} />
          <Route path="*" element={<Navigate to="/bootstrap" replace />} />
        </Routes>
      );
    }

    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<RedirectToLogin />} />
      </Routes>
    );
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/signers" element={<Signers />} />
        <Route path="/hd-wallets" element={<HDWallets />} />
        <Route path="/wallets" element={<Wallets />} />
        <Route path="/requests" element={<Requests />} />
        <Route path="/requests/:id" element={<RequestDetail />} />
        <Route path="/transactions" element={<Transactions />} />
        <Route path="/transactions/:id" element={<TransactionDetail />} />
        <Route path="/simulate" element={<Simulate />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/templates" element={<Templates />} />
        <Route path="/templates/:id" element={<TemplateDetail />} />
        <Route path="/presets" element={<Presets />} />
        <Route path="/presets/:id" element={<PresetDetail />} />
        <Route path="/budgets" element={<Budgets />} />
        <Route path="/budgets/:id" element={<BudgetDetail />} />
        <Route path="/api-keys" element={<ApiKeys />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

/** Preserves the user's intended destination so we can bounce them back
 *  after login. Stored in location state, not in localStorage, so a tab
 *  open is the only thing that survives across the login screen. */
function RedirectToLogin() {
  const location = useLocation();
  return <Navigate to="/login" replace state={{ from: location.pathname }} />;
}
