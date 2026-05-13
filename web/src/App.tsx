import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/Layout";
import { getCredentials, subscribeAuth } from "./lib/auth";
import { ApiKeys } from "./pages/ApiKeys";
import { Audit } from "./pages/Audit";
import { Dashboard } from "./pages/Dashboard";
import { HDWallets } from "./pages/HDWallets";
import { Login } from "./pages/Login";
import { Requests } from "./pages/Requests";
import { Rules } from "./pages/Rules";
import { Settings } from "./pages/Settings";
import { Signers } from "./pages/Signers";
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

  useEffect(() => {
    return subscribeAuth(() => setAuthed(getCredentials() !== null));
  }, []);

  if (!authed) {
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
        <Route path="/rules" element={<Rules />} />
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
