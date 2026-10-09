import { useMemo, useState } from "react";
import { useQuery, useQueries } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Page, Loading } from "../components/Page";
import { SeverityCluster, SeverityTag, Ago } from "../components/tables";
import { LatencyChart } from "../components/Sparkline";
import { Card, Section, StatCard, StatRow } from "../ui";
import { api } from "../lib/api";
import { percentile } from "../lib/format";
import { useSessionFilter } from "../lib/sessionFilter";
import { useEventStream } from "../lib/useEventStream";
import type { AlertData, Event, SessionRow, Stats } from "../lib/types";

export default function OverviewPage() {
  const { session } = useSessionFilter();

  const statsQuery = useQuery({
    queryKey: ["stats"],
    queryFn: () => api.get<Stats>("/api/stats"),
    refetchInterval: 10_000,
  });

  const sessionsQuery = useQuery({
    queryKey: ["sessions", "overview"],
    queryFn: () => api.get<SessionRow[]>("/api/sessions?limit=10"),
    refetchInterval: 15_000,
  });

  // Exec latency chart: when a session is selected, use its own exec.end
  // durations. Otherwise there is no global "/api/events" listing in
  // protocol.md v2 (only per-sandbox/per-session/search) — as a stopgap we
  // fan out across the most recent sessions and merge. design: N+1 fetches
  // over a handful of sessions; a real `/api/events?types=` or folding
  // exec_history into `/api/stats` is a control-plane change, out of scope here.
  const fanoutSessions = session ? [] : (sessionsQuery.data ?? []).slice(0, 5).map((s) => s.pi_session);
  const fanout = useQueries({
    queries: fanoutSessions.map((id) => ({
      queryKey: ["session-execs", id],
      queryFn: () => api.get<Event[]>(`/api/sessions/${id}/events?types=exec.end&limit=200`),
    })),
  });
  const singleExecs = useQuery({
    queryKey: ["session-execs", session],
    queryFn: () => api.get<Event[]>(`/api/sessions/${session}/events?types=exec.end&limit=200`),
    enabled: !!session,
  });

  const execDurations = useMemo(() => {
    const events: Event[] = session ? (singleExecs.data ?? []) : fanout.flatMap((q) => q.data ?? []);
    return events
      .sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime())
      .slice(-200)
      .map((e) => Number((e.data as { duration_ms?: number }).duration_ms ?? 0));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, singleExecs.data, JSON.stringify(fanout.map((q) => q.data?.length))]);

  // stats.exec_p95_ms comes from the server's own (much larger, unseen-here) sample —
  // showing it next to a chart of only these execDurations can read as impossible (a
  // p95 below the visible max). Compute p95 from the same array the chart draws instead,
  // and hide it outright below 20 samples, where a percentile isn't meaningful.
  const p95Local = execDurations.length >= 20 ? percentile(execDurations, 0.95) : null;

  // Live alert feed
  const alertsQuery = useQuery({
    queryKey: ["alerts", "feed", session],
    queryFn: () => api.get<Event[]>(`/api/alerts?limit=20${session ? `&pi_session=${session}` : ""}`),
    refetchInterval: 10_000,
  });
  const [liveAlerts, setLiveAlerts] = useState<Event[]>([]);
  useEventStream({ types: "security.alert", pi_session: session || undefined }, (event) => {
    if (event.type === "security.alert") setLiveAlerts((prev) => [event, ...prev].slice(0, 20));
  });
  const alertFeed = useMemo(() => {
    const byId = new Map<string, Event>();
    for (const e of [...liveAlerts, ...(alertsQuery.data ?? [])]) byId.set(e.id, e);
    return [...byId.values()].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()).slice(0, 7);
  }, [liveAlerts, alertsQuery.data]);

  const stats = statsQuery.data;
  const alerts24h = stats
    ? stats.alerts_24h.critical + stats.alerts_24h.high + stats.alerts_24h.medium + stats.alerts_24h.low
    : 0;

  return (
    <Page title="Overview" description={session ? `Filtered to session ${session}` : "Every session, sandbox and alert this control plane has seen."}>
      {!stats ? (
        <Loading />
      ) : (
        <>
          <StatRow>
            <StatCard
              label="Sandboxes"
              value={stats.sandboxes.total}
              sub={`${stats.sandboxes.ready} ready · ${stats.sandboxes.busy} busy`}
            />
            <StatCard label="Hosts" value={stats.hosts} sub={`egress ${stats.egress.allow_1h} allowed · ${stats.egress.deny_1h} denied (1h)`} />
            <StatCard label="Events" value={stats.events_1h.toLocaleString()} sub="last hour" />
            <StatCard
              label="Alerts"
              value={alerts24h.toLocaleString()}
              sub={`${stats.alerts_24h.critical} critical · ${stats.alerts_24h.high} high (24h)`}
            />
          </StatRow>

          <Section
            title="Exec latency"
            description={`Last ${execDurations.length} exec.end durations${session ? ` for ${session}` : " across recent sessions"}.`}
            action={
              <div className="sbx-row" style={{ gap: 24 }}>
                <div style={{ textAlign: "right" }}>
                  <div className="sbx-label" style={{ fontSize: 12 }}>p50</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 600 }}>{stats.exec_p50_ms}ms</div>
                </div>
                <div style={{ textAlign: "right" }} title={p95Local === null ? "Needs at least 20 samples" : undefined}>
                  <div className="sbx-label" style={{ fontSize: 12 }}>p95</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 600 }}>{p95Local !== null ? `${p95Local}ms` : `— (${execDurations.length}/20 samples)`}</div>
                </div>
              </div>
            }
          >
            <Card>
              <LatencyChart values={execDurations} unit="ms" />
            </Card>
          </Section>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 24 }}>
            <Section
              title="Live alerts"
              action={
                <Link to="/alerts" className="sbx-link" style={{ fontSize: 13 }}>
                  View all
                </Link>
              }
            >
              <Card padding="flush">
                {alertFeed.length === 0 ? (
                  <div className="sbx-table-empty">No alerts.</div>
                ) : (
                  <ul className="sbx-list">
                    {alertFeed.map((e) => {
                      const d = e.data as AlertData;
                      return (
                        <li key={e.id}>
                          <span style={{ width: 76, flex: "none" }}>
                            <SeverityTag severity={d.severity} />
                          </span>
                          <span className="sbx-truncate" style={{ flex: 1, fontSize: 13 }} title={d.msg}>
                            {d.rule}
                          </span>
                          {e.pi_session && (
                            <Link
                              to={`/sessions/${e.pi_session}?tab=timeline&tool_call=${e.tool_call_id}`}
                              className="mono sbx-link sbx-truncate"
                              style={{ fontSize: 12, flex: "0 1 130px", textAlign: "right" }}
                            >
                              {e.pi_session}
                            </Link>
                          )}
                          <span style={{ flex: "0 0 68px", textAlign: "right" }}>
                            <Ago value={e.ts} />
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </Card>
            </Section>

            <Section
              title="Active sessions"
              action={
                <Link to="/sessions" className="sbx-link" style={{ fontSize: 13 }}>
                  View all
                </Link>
              }
            >
              <Card padding="flush">
                {(sessionsQuery.data ?? []).length === 0 ? (
                  <div className="sbx-table-empty">No sessions yet.</div>
                ) : (
                  <ul className="sbx-list">
                    {(sessionsQuery.data ?? []).slice(0, 7).map((s) => (
                      <li key={s.pi_session}>
                        <Link to={`/sessions/${s.pi_session}`} className="mono sbx-link sbx-truncate" style={{ flex: 1, fontSize: 12.5 }}>
                          {s.pi_session}
                        </Link>
                        <span className="sbx-ago" style={{ flex: "0 0 64px", textAlign: "right" }}>
                          {s.execs} execs
                        </span>
                        <span style={{ flex: "0 0 auto" }}>
                          <SeverityCluster alerts={s.alerts} maxWidth={150} />
                        </span>
                        <span style={{ flex: "0 0 68px", textAlign: "right" }}>
                          <Ago value={s.last_ts} />
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </Section>
          </div>
        </>
      )}
    </Page>
  );
}
