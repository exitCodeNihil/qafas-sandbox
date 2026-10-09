/**
 * Application frame: 240px side nav, 56px top bar, scrolling content.
 *
 * The frame is plain CSS (app.css, `.sbx-shell`) rather than Astryx's
 * AppShell/SideNav — the console needs exact nav metrics (56px logo row,
 * 36px items, 11px group labels, hairline separators) that the generic
 * shell doesn't expose. Everything interactive inside it is still Astryx.
 */
import { useEffect, useState, type ElementType } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { HStack, VStack } from "@astryxdesign/core/Stack";
import { Text } from "@astryxdesign/core/Text";
import { IconButton } from "@astryxdesign/core/IconButton";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Selector } from "@astryxdesign/core/Selector";
import { Popover } from "@astryxdesign/core/Popover";
import { Button } from "@astryxdesign/core/Button";
import { CommandPalette, CommandPaletteInput, CommandPaletteEmpty } from "@astryxdesign/core/CommandPalette";
import { createStaticSource, type SearchableItem } from "@astryxdesign/core/Typeahead";

import { token, api } from "../lib/api";
import { useHealth } from "../lib/useHealth";
import { useMode } from "../mode";
import { useSessionFilter } from "../lib/sessionFilter";
import type { SessionRow, SandboxInfo, SnapshotInfo, ApiKey } from "../lib/types";
import { version as pkgVersion } from "../../package.json";
import { StatusDot } from "../ui";
import {
  IconDashboard,
  IconMoon,
  IconSun,
  IconAlertTriangle,
  IconSessions,
  IconDeployment,
  IconEdge,
  IconShield,
  IconSearch,
  IconRocket,
  IconSnapshot,
  IconSignal,
  IconKey,
  IconCube,
  IconObservability,
  IconLogout,
} from "./icons";

type NavEntry = { to: string; label: string; icon: ElementType };

const SECTIONS: { title: string; items: NavEntry[] }[] = [
  {
    title: "Compute",
    items: [
      { to: "/sandboxes", label: "Sandboxes", icon: IconCube },
      { to: "/snapshots", label: "Templates", icon: IconSnapshot },
    ],
  },
  {
    title: "Monitoring",
    items: [
      { to: "/overview", label: "Overview", icon: IconDashboard },
      { to: "/sessions", label: "Sessions", icon: IconSessions },
      { to: "/alerts", label: "Alerts", icon: IconAlertTriangle },
      { to: "/egress", label: "Egress", icon: IconEdge },
    ],
  },
  {
    title: "Platform",
    items: [
      { to: "/keys", label: "API Keys", icon: IconKey },
      { to: "/hosts", label: "Hosts", icon: IconDeployment },
      { to: "/policy", label: "Policy", icon: IconShield },
      { to: "/get-started", label: "Get Started", icon: IconRocket },
    ],
  },
  {
    title: "Settings",
    items: [{ to: "/settings/observability", label: "Observability", icon: IconObservability }],
  },
];

/** Route → breadcrumb (nav group › page label), for the top bar. */
function crumbsFor(pathname: string): { group: string; page: string; to: string } | null {
  for (const section of SECTIONS) {
    for (const item of section.items) {
      if (pathname === item.to || pathname.startsWith(item.to + "/")) {
        return { group: section.title, page: item.label, to: item.to };
      }
    }
  }
  return null;
}

/** Connection status — reachability + auth at a glance, token behind a click. */
function ConnectionStatus() {
  const qc = useQueryClient();
  const [adminToken, setTok] = useState(token.get() || "");
  const setAdminToken = (t: string) => {
    setTok(t);
    if (t) token.set(t);
    else token.clear();
    void qc.invalidateQueries();
  };

  const health = useHealth();
  // Auth check layered on top of reachability — only makes sense once /healthz
  // says the control plane is actually there.
  const authQuery = useQuery({
    queryKey: ["healthz", "auth"],
    queryFn: async () => {
      const t = token.get();
      const auth = await fetch("/api/stats", { headers: t ? { Authorization: `Bearer ${t}` } : {} });
      return auth.status === 401 ? ("unauthorized" as const) : ("ok" as const);
    },
    enabled: health.data?.reachable === true,
    refetchInterval: 15_000,
    retry: false,
  });
  const healthy = health.data?.reachable === true && authQuery.data === "ok";
  const statusLabel = health.isPending || (health.data?.reachable && authQuery.isPending)
    ? "Connecting"
    : !health.data?.reachable
      ? "Offline"
      : authQuery.data === "unauthorized"
        ? "Set token"
        : "Connected";
  const tone = healthy ? "ready" : authQuery.data === "unauthorized" ? "warning" : "danger";

  return (
    <Popover
      label="Connection"
      width={280}
      content={
        <VStack gap={3}>
          <Text type="body" style={{ fontSize: 13 }}>
            {healthy
              ? "Control plane reachable."
              : authQuery.data === "unauthorized"
                ? "Reachable, admin token missing or wrong (SBX_ADMIN_TOKEN)."
                : "Control plane unreachable."}
          </Text>
          <TextInput
            label="Admin token"
            size="sm"
            value={adminToken}
            onChange={setAdminToken}
            placeholder="Paste admin token"
            type="password"
            width="100%"
          />
          <HStack hAlign="end">
            <Button label="Clear" size="sm" variant="secondary" onClick={() => setAdminToken("")} />
          </HStack>
        </VStack>
      }
    >
      <button type="button" className="sbx-conn">
        <StatusDot tone={tone} label={statusLabel} />
      </button>
    </Popover>
  );
}

type PaletteItem = SearchableItem<{ kind: string; to: string; group: string }>;

/** ⌘K: navigation pages plus a live search across sessions, sandboxes,
 * templates and keys by id/name/label. */
function CommandK({ isOpen, onOpenChange }: { isOpen: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate();

  const sessionsQ = useQuery({
    queryKey: ["sessions", "palette"],
    queryFn: () => api.get<SessionRow[]>("/api/sessions?limit=100"),
    enabled: isOpen,
    staleTime: 30_000,
  });
  const sandboxesQ = useQuery({
    queryKey: ["sandboxes", "palette"],
    queryFn: () => api.get<SandboxInfo[]>("/api/sandboxes"),
    enabled: isOpen,
    staleTime: 30_000,
  });
  const snapshotsQ = useQuery({
    queryKey: ["snapshots", "palette"],
    queryFn: () => api.get<SnapshotInfo[]>("/api/snapshots"),
    enabled: isOpen,
    staleTime: 30_000,
    retry: false,
  });
  const keysQ = useQuery({
    queryKey: ["keys", "palette"],
    queryFn: () => api.get<ApiKey[]>("/api/keys"),
    enabled: isOpen,
    staleTime: 30_000,
    retry: false,
  });

  const pageItems: PaletteItem[] = SECTIONS.flatMap((s) => s.items).map((i) => ({
    id: `page:${i.to}`,
    label: i.label,
    auxiliaryData: { kind: "Page", to: i.to, group: "Go to" },
  }));
  const sessionItems: PaletteItem[] = (sessionsQ.data ?? []).map((s) => ({
    id: `session:${s.pi_session}`,
    label: s.pi_session,
    auxiliaryData: { kind: "Session", to: `/sessions/${s.pi_session}`, group: "Sessions" },
  }));
  const sandboxItems: PaletteItem[] = (sandboxesQ.data ?? []).map((sb) => ({
    id: `sandbox:${sb.id}`,
    label: sb.name || sb.id,
    auxiliaryData: { kind: "Sandbox", to: `/sandboxes/${sb.id}`, group: "Sandboxes" },
  }));
  const snapshotItems: PaletteItem[] = (snapshotsQ.data ?? []).map((sn) => ({
    id: `snapshot:${sn.name}`,
    label: sn.name,
    auxiliaryData: { kind: "Template", to: `/snapshots`, group: "Templates" },
  }));
  const keyItems: PaletteItem[] = (keysQ.data ?? []).map((k) => ({
    id: `key:${k.id}`,
    label: k.name,
    auxiliaryData: { kind: "API key", to: `/keys/${k.id}`, group: "API Keys" },
  }));
  const items = [...pageItems, ...sessionItems, ...sandboxItems, ...snapshotItems, ...keyItems];

  const keywords = (item: PaletteItem) => {
    if (item.auxiliaryData?.kind === "Sandbox") {
      const sb = (sandboxesQ.data ?? []).find((s) => `sandbox:${s.id}` === item.id);
      return sb ? [sb.id, ...Object.entries(sb.labels ?? {}).map(([k, v]) => `${k}=${v}`)] : [];
    }
    if (item.auxiliaryData?.kind === "API key") {
      const k = (keysQ.data ?? []).find((k) => `key:${k.id}` === item.id);
      return k ? [k.prefix] : [];
    }
    return [];
  };
  const source = createStaticSource(items, { keywords });

  const go = (id: string) => {
    const item = items.find((i) => i.id === id);
    if (item) navigate(item.auxiliaryData!.to);
  };

  return (
    <CommandPalette
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      searchSource={source}
      label="Search"
      onValueChange={go}
      input={<CommandPaletteInput placeholder="Search sessions, sandboxes, templates, keys…" />}
      renderItem={(item) => (
        <span className="mono" style={{ fontSize: 13 }}>
          {item.label}
        </span>
      )}
      emptyBootstrapText={<CommandPaletteEmpty>Search sessions, sandboxes, templates, keys…</CommandPaletteEmpty>}
      emptySearchText={<CommandPaletteEmpty>No results</CommandPaletteEmpty>}
    />
  );
}

export default function Shell({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();
  const { mode, toggle } = useMode();
  const { session, setSession } = useSessionFilter();
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      const target = e.target as HTMLElement | null;
      const typing = target && ["INPUT", "TEXTAREA"].includes(target.tagName);
      if (e.key === "/" && !typing) {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const health = useHealth();

  const sessionsQuery = useQuery({
    queryKey: ["sessions", "nav"],
    queryFn: () => api.get<SessionRow[]>("/api/sessions?limit=50"),
    staleTime: 30_000,
  });
  const sessionOptions = (sessionsQuery.data ?? []).map((s) => ({ value: s.pi_session, label: s.pi_session }));

  const active = SECTIONS.flatMap((s) => s.items)
    .map((i) => i.to)
    .filter((to) => pathname === to || pathname.startsWith(to + "/"))
    .sort((a, b) => b.length - a.length)[0];
  const crumbs = crumbsFor(pathname);

  // On a sandbox's own detail page, name it in the breadcrumb instead of stopping at
  // "Sandboxes" — the one static crumbsFor() can't know a dynamic route's resource name.
  const sandboxDetailId = pathname.match(/^\/sandboxes\/([^/]+)$/)?.[1];
  // Same queryKey the detail page's own query uses (SandboxDetail.tsx), so this shares
  // its cache entry and network request instead of firing a second fetch alongside it.
  const sandboxCrumbQuery = useQuery({
    queryKey: ["sandbox", sandboxDetailId],
    queryFn: () => api.get<SandboxInfo>(`/api/sandboxes/${sandboxDetailId}`),
    enabled: !!sandboxDetailId,
    staleTime: 30_000,
  });
  const crumbDetailName = sandboxDetailId
    ? sandboxCrumbQuery.data?.name || sandboxCrumbQuery.data?.id || sandboxDetailId
    : null;

  return (
    <div className="sbx-shell">
      <nav className="sbx-nav" aria-label="Main">
        <Link to="/overview" className="sbx-nav-brand">
          <IconSignal width={20} height={20} />
          Qafas Sandbox
        </Link>

        <div className="sbx-nav-search">
          <button type="button" className="sbx-search-field" onClick={() => setPaletteOpen(true)}>
            <IconSearch width={14} height={14} />
            <span>Search</span>
            <kbd>⌘K</kbd>
          </button>
        </div>

        <div className="sbx-nav-scroll">
          {SECTIONS.map((section) => (
            <div className="sbx-nav-group" key={section.title}>
              <span className="sbx-nav-group-title">{section.title}</span>
              {section.items.map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    className="sbx-nav-item"
                    aria-current={item.to === active ? "page" : undefined}
                  >
                    <Icon width={16} height={16} />
                    {item.label}
                  </Link>
                );
              })}
            </div>
          ))}
        </div>

        <div className="sbx-nav-footer">
          <ConnectionStatus />
          <span className="sbx-version">v{health.data?.version ?? pkgVersion}</span>
        </div>
      </nav>

      <div className="sbx-main">
        <header className="sbx-topbar">
          <div className="sbx-crumbs">
            {crumbs ? (
              <>
                <span>{crumbs.group}</span>
                <span className="sbx-crumb-sep">›</span>
                {crumbDetailName ? (
                  <>
                    <span>{crumbs.page}</span>
                    <span className="sbx-crumb-sep">›</span>
                    <span className="sbx-crumb-current">{crumbDetailName}</span>
                  </>
                ) : (
                  <span className="sbx-crumb-current">{crumbs.page}</span>
                )}
              </>
            ) : (
              <span className="sbx-crumb-current">Qafas Sandbox</span>
            )}
          </div>
          <div className="sbx-topbar-end">
            <Selector
              label="Session filter"
              isLabelHidden
              size="sm"
              options={sessionOptions}
              value={session}
              onChange={setSession}
              hasClear
              placeholder="All sessions"
              width={220}
            />
            <IconButton
              label={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              variant="ghost"
              size="sm"
              icon={mode === "dark" ? <IconSun width={16} height={16} /> : <IconMoon width={16} height={16} />}
              onClick={toggle}
            />
            <IconButton
              label="Sign out"
              variant="ghost"
              size="sm"
              icon={<IconLogout width={16} height={16} />}
              onClick={() => token.clear()}
            />
          </div>
        </header>

        <div className="sbx-scroll">{children}</div>
      </div>

      <CommandK isOpen={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
