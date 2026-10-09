import { Routes, Route, Navigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import Shell from "./components/Shell";
import { SessionFilterProvider } from "./lib/sessionFilter";
import { api } from "./lib/api";
import { useAuthed } from "./lib/auth";
import type { SandboxInfo, SessionRow } from "./lib/types";
import LoginPage from "./pages/LoginPage";
import OverviewPage from "./pages/Overview";
import SessionsPage from "./pages/Sessions";
import SessionDetailPage from "./pages/SessionDetail";
import HostsPage from "./pages/Hosts";
import SandboxesPage from "./pages/Sandboxes";
import SandboxDetailPage from "./pages/SandboxDetail";
import SnapshotsPage from "./pages/Snapshots";
import SnapshotDetailPage from "./pages/SnapshotDetail";
import AlertsPage from "./pages/Alerts";
import EgressPage from "./pages/Egress";
import PolicyPage from "./pages/Policy";
import GetStartedPage from "./pages/GetStarted";
import ApiKeysPage from "./pages/ApiKeys";
import ApiKeyDetailPage from "./pages/ApiKeyDetail";
import ObservabilityPage from "./pages/Observability";

/** Default route: Get Started for a brand-new control plane (nothing has
 * ever run), Overview once something exists. Falls through to Overview on
 * error rather than blocking on a control plane that might be unreachable. */
function DefaultRoute() {
  const sandboxes = useQuery({ queryKey: ["sandboxes", "default-route"], queryFn: () => api.get<SandboxInfo[]>("/api/sandboxes") });
  const sessions = useQuery({ queryKey: ["sessions", "default-route"], queryFn: () => api.get<SessionRow[]>("/api/sessions?limit=1") });
  if (sandboxes.isLoading || sessions.isLoading) return null;
  const empty = (sandboxes.data ?? []).length === 0 && (sessions.data ?? []).length === 0;
  return <Navigate to={empty ? "/get-started" : "/overview"} replace />;
}

export default function App() {
  const authed = useAuthed();
  if (!authed) return <LoginPage />;

  return (
    <SessionFilterProvider>
      <Shell>
        <Routes>
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/sessions" element={<SessionsPage />} />
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
          <Route path="/keys" element={<ApiKeysPage />} />
          <Route path="/keys/:id" element={<ApiKeyDetailPage />} />
          <Route path="/hosts" element={<HostsPage />} />
          <Route path="/sandboxes" element={<SandboxesPage />} />
          <Route path="/sandboxes/:id" element={<SandboxDetailPage />} />
          <Route path="/snapshots" element={<SnapshotsPage />} />
          <Route path="/templates" element={<SnapshotsPage />} />
          <Route path="/snapshots/:name" element={<SnapshotDetailPage />} />
          <Route path="/templates/:name" element={<SnapshotDetailPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/egress" element={<EgressPage />} />
          <Route path="/policy" element={<PolicyPage />} />
          <Route path="/settings/observability" element={<ObservabilityPage />} />
          <Route path="/get-started" element={<GetStartedPage />} />
          <Route path="/" element={<DefaultRoute />} />
        </Routes>
      </Shell>
    </SessionFilterProvider>
  );
}
