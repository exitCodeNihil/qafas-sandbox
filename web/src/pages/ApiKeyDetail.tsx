import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@astryxdesign/core/Button";
import { pixel, proportional } from "@astryxdesign/core/Table";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { useImperativeAlertDialog } from "@astryxdesign/core/AlertDialog";
import { Page, Query, ErrorState } from "../components/Page";
import { sandboxColumns, SeverityCluster, Ago } from "../components/tables";
import { Card, DataTable, EmptyState, KeyValueGrid, Section, StatCard, StatRow, StatusDot, Tag, Tags } from "../ui";
import { api, ApiError } from "../lib/api";
import { limitsSummary, keyPrefixLabel, SINCE_OPTIONS, sinceIso, type SinceKey } from "../lib/apiKeys";
import { durationLabel } from "../lib/format";
import type { ApiKey, ApiKeyUsage, SandboxInfo, SessionRow } from "../lib/types";

function Header({ k }: { k: ApiKey }) {
  const labels = Object.entries(k.labels ?? {});
  return (
    <Card>
      <div className="sbx-stack-24">
        <div className="sbx-row-wrap" style={{ gap: 12 }}>
          {k.revoked_at ? <StatusDot tone="muted" label="revoked" muted /> : <StatusDot tone="ready" label="active" />}
          {k.scopes.map((s) => (
            <Tag key={s} tone={s === "admin" ? "warning" : undefined}>
              {s}
            </Tag>
          ))}
        </div>

        <KeyValueGrid
          columns={4}
          items={[
            { label: "Prefix", value: <span className="mono" style={{ fontSize: 12.5 }}>{keyPrefixLabel(k.prefix)}</span> },
            { label: "Created", value: <Ago value={k.created_at} /> },
            { label: "Last used", value: k.last_used_at ? <Ago value={k.last_used_at} /> : "never" },
            k.revoked_at ? { label: "Revoked", value: <Ago value={k.revoked_at} /> } : null,
            { label: "Limits", wide: true, value: limitsSummary(k.limits) },
            labels.length > 0
              ? {
                  label: "Labels",
                  wide: true,
                  value: (
                    <Tags>
                      {labels.map(([lk, lv]) => (
                        <Tag key={lk} mono>{`${lk}=${lv}`}</Tag>
                      ))}
                    </Tags>
                  ),
                }
              : null,
          ]}
        />
      </div>
    </Card>
  );
}

function UsageCards({ keyId, since }: { keyId: string; since: SinceKey }) {
  const query = useQuery({
    queryKey: ["key-usage", keyId, since],
    queryFn: () => api.get<ApiKeyUsage>(`/api/keys/${keyId}/usage?since=${encodeURIComponent(sinceIso(since))}`),
    retry: false,
  });

  return (
    <Query query={query}>
      {(usage) => (
        <div className="sbx-stack-16">
          <StatRow>
            <StatCard label="Sandboxes created" value={usage.sandboxes_created} />
            <StatCard label="Live now" value={usage.live_sandboxes} />
            <StatCard label="Execs" value={usage.execs} />
            <StatCard label="Sandbox-hours" value={(usage.sandbox_seconds / 3600).toFixed(1)} />
          </StatRow>
          <Card>
            <KeyValueGrid
              columns={3}
              items={[
                { label: "Alerts", value: <SeverityCluster alerts={usage.alerts} maxWidth={280} /> },
                { label: "Egress allow / deny", value: <span className="mono">{`${usage.egress.allow ?? 0} / ${usage.egress.deny ?? 0}`}</span> },
                {
                  label: "By tier (native / vm / remote)",
                  value: <span className="mono">{`${usage.by_tier.native ?? 0} / ${usage.by_tier.vm ?? 0} / ${usage.by_tier.remote ?? 0}`}</span>,
                },
              ]}
            />
          </Card>
        </div>
      )}
    </Query>
  );
}

function KeySandboxes({ keyId }: { keyId: string }) {
  const query = useQuery({
    queryKey: ["sandboxes", "for-key", keyId],
    queryFn: () => api.get<SandboxInfo[]>(`/api/sandboxes?api_key=${encodeURIComponent(keyId)}`),
    retry: false,
  });
  return (
    <Query query={query} empty={<EmptyState title="No sandboxes" description="This key has not created a sandbox yet." />}>
      {(sandboxes) => <DataTable data={sandboxes} idKey="id" empty="No sandboxes." columns={sandboxColumns()} />}
    </Query>
  );
}

const sessionColumns = [
  {
    key: "pi_session",
    header: "Session",
    width: proportional(2, { minWidth: 180 }),
    renderCell: (s: SessionRow) => (
      <Link to={`/sessions/${s.pi_session}`} className="mono sbx-link sbx-truncate" style={{ fontSize: 12.5 }}>
        {s.pi_session}
      </Link>
    ),
  },
  { key: "execs", header: "Execs", width: pixel(80), align: "end" as const, renderCell: (s: SessionRow) => <span className="mono" style={{ fontSize: 12.5 }}>{s.execs}</span> },
  {
    key: "duration",
    header: "Duration",
    width: pixel(100),
    align: "end" as const,
    renderCell: (s: SessionRow) => <span className="mono" style={{ fontSize: 12.5 }}>{durationLabel(s.first_ts, s.last_ts)}</span>,
  },
  {
    key: "last_ts",
    header: "Last activity",
    width: pixel(110),
    renderCell: (s: SessionRow) => <Ago value={s.last_ts} />,
  },
];

function KeySessions({ keyId }: { keyId: string }) {
  const query = useQuery({ queryKey: ["sessions", "for-key"], queryFn: () => api.get<SessionRow[]>("/api/sessions?limit=200") });
  return (
    <Query query={query}>
      {(sessions) => {
        const rows = sessions.filter((s) => s.api_key_id === keyId);
        if (rows.length === 0) return <EmptyState title="No sessions" description="No session has authenticated with this key." />;
        return <DataTable data={rows} idKey="pi_session" columns={sessionColumns} />;
      }}
    </Query>
  );
}

export default function ApiKeyDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const alertDialog = useImperativeAlertDialog();
  const [since, setSince] = useState<SinceKey>("24h");
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["key", id],
    queryFn: () => api.get<ApiKey>(`/api/keys/${id}`),
    enabled: !!id,
    retry: false,
  });

  if (!id) return null;

  const confirmRevoke = (k: ApiKey) => {
    alertDialog.show({
      title: `Revoke ${k.name}?`,
      description: "Sandboxes it already created keep running. New requests with this key get 401. This cannot be undone.",
      actionLabel: "Revoke",
      onAction: async () => {
        setRevokeError(null);
        try {
          await api.del(`/api/keys/${k.id}`);
          void qc.invalidateQueries({ queryKey: ["key", id] });
          void qc.invalidateQueries({ queryKey: ["keys"] });
        } catch (err) {
          setRevokeError(err instanceof ApiError ? err.message : "Revoke failed");
        }
        alertDialog.hide();
      },
    });
  };

  const k = query.data;

  return (
    <Page
      title={k?.name || id}
      description="API key"
      action={k && !k.revoked_at ? <Button label="Revoke" variant="destructive" onClick={() => confirmRevoke(k)} /> : undefined}
    >
      <Query query={query}>
        {(key) => (
          <>
            {revokeError && <ErrorState error={new Error(revokeError)} onRetry={() => setRevokeError(null)} />}
            <Header k={key} />

            <Section
              title="Usage"
              action={
                <SegmentedControl value={since} onChange={(v) => setSince(v as SinceKey)} label="Since">
                  {SINCE_OPTIONS.map((o) => (
                    <SegmentedControlItem key={o.value} value={o.value} label={o.label} />
                  ))}
                </SegmentedControl>
              }
            >
              <UsageCards keyId={key.id} since={since} />
            </Section>

            <Section title="Sandboxes">
              <KeySandboxes keyId={key.id} />
            </Section>

            <Section title="Sessions">
              <KeySessions keyId={key.id} />
            </Section>
          </>
        )}
      </Query>
      {alertDialog.element}
    </Page>
  );
}
