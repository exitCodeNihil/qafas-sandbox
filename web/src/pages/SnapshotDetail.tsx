import { useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@astryxdesign/core/Button";
import { pixel, proportional } from "@astryxdesign/core/Table";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { useToast } from "@astryxdesign/core/Toast";
import { useImperativeAlertDialog } from "@astryxdesign/core/AlertDialog";
import { Page, Query, ErrorState } from "../components/Page";
import { sandboxColumns, Ago, Muted } from "../components/tables";
import { CreateSandboxDrawer } from "../components/CreateSandboxDrawer";
import { WarmCell, kindLabel, stateTone } from "../components/templates";
import { useOpenKey } from "../lib/useOpenKey";
import { Card, CodeBlock, DataTable, EmptyState, KeyValueGrid, Section, StatusDot, Tag, Tags } from "../ui";
import { api, ApiError } from "../lib/api";
import { runtimeLabel } from "../lib/types";
import type { SandboxInfo, SecurityCheck, SnapshotInfo } from "../lib/types";

type Source = { image?: string; dockerfile?: string; sandbox_id?: string };

const GRADE_MEANING: Record<string, string> = {
  A: "Every boundary and hygiene check passed.",
  B: "The boundary holds; the image has one or two hygiene findings worth a look.",
  C: "The boundary holds; the image has several hygiene findings.",
  F: "A boundary check failed. Untrusted work cannot use this template until it is fixed.",
};

/** Failed first, boundary before hygiene, then by name — what an operator reads first. */
function ordered(checks: SecurityCheck[]): SecurityCheck[] {
  const rank = (c: SecurityCheck) => (c.ok ? 2 : 0) + (c.class === "boundary" ? 0 : 1);
  return [...checks].sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id));
}

const checkColumns = [
  {
    key: "ok",
    header: "Result",
    width: pixel(96),
    renderCell: (c: SecurityCheck) =>
      c.ok ? <StatusDot tone="ready" label="pass" /> : <StatusDot tone={c.class === "boundary" ? "danger" : "warning"} label="fail" />,
  },
  {
    key: "id",
    header: "Check",
    width: pixel(170),
    renderCell: (c: SecurityCheck) => <span className="mono" style={{ fontSize: 12.5 }}>{c.id}</span>,
  },
  {
    key: "class",
    header: "Class",
    width: pixel(100),
    renderCell: (c: SecurityCheck) => <Tag>{c.class}</Tag>,
  },
  {
    key: "detail",
    header: "Detail",
    width: proportional(1, { minWidth: 240 }),
    renderCell: (c: SecurityCheck) => <span style={{ fontSize: 12.5 }}>{c.detail}</span>,
  },
];

function SecuritySection({ rows, name }: { rows: SnapshotInfo[]; name: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const hosts = rows.map((r) => r.host_id ?? "—");
  const [host, setHost] = useState(hosts[0]);
  const row = rows.find((r) => (r.host_id ?? "—") === host) ?? rows[0];
  const sec = row?.security;
  const [scanning, setScanning] = useState(false);
  const [showPassed, setShowPassed] = useState(false);

  const rescan = async () => {
    setScanning(true);
    try {
      await api.post(`/api/snapshots/${encodeURIComponent(name)}/scan`);
      toast({ body: `Scanning ${name}; results update when it finishes.` });
      // The daemon scans in the background (seconds; up to a minute on a microVM host).
      for (const ms of [6000, 15000, 40000]) setTimeout(() => void qc.invalidateQueries({ queryKey: ["snapshot", name] }), ms);
    } catch (err) {
      toast({ body: err instanceof Error ? `Rescan: ${err.message}` : "Rescan failed", type: "error" });
    } finally {
      setTimeout(() => setScanning(false), 6000);
    }
  };

  const failed = sec?.findings.filter((c) => !c.ok) ?? [];
  return (
    <Section
      title="Security"
      description="What a sandbox of this template can and cannot do, checked from inside one on this runtime."
      action={
        <div className="sbx-row-wrap" style={{ gap: 8 }}>
          {hosts.length > 1 && (
            <SegmentedControl value={host} onChange={setHost} label="Host">
              {hosts.map((h) => (
                <SegmentedControlItem key={h} value={h} label={h} />
              ))}
            </SegmentedControl>
          )}
          <Button label={scanning ? "Scanning…" : "Rescan"} variant="secondary" isDisabled={scanning || row?.state !== "active"} onClick={rescan} />
        </div>
      }
    >
      {!sec ? (
        <EmptyState title="Not scanned yet" description="Templates are scanned when they are built and base when the daemon starts. Rescan to grade it now." />
      ) : (
        <div className="sbx-stack-16">
          <Card>
            <div className="sbx-row-wrap" style={{ gap: 20, alignItems: "center" }}>
              <span className={`sbx-grade sbx-grade-${sec.grade}`} aria-label={`Grade ${sec.grade}`}>
                {sec.grade}
              </span>
              <div className="sbx-stack-8" style={{ minWidth: 0, flex: 1 }}>
                <div style={{ fontSize: 14, fontWeight: 500 }}>{GRADE_MEANING[sec.grade] ?? ""}</div>
                <Muted>
                  {sec.findings.length - failed.length} of {sec.findings.length} checks passed · scanned <Ago value={sec.scanned_at} /> on {row?.host_id ?? "—"}
                </Muted>
                <span className="mono sbx-truncate" style={{ fontSize: 11.5 }}>
                  <Muted>{sec.image_digest}</Muted>
                </span>
              </div>
            </div>
          </Card>
          {(failed.length > 0 || showPassed) && (
            <DataTable data={ordered(showPassed ? sec.findings : failed)} idKey="id" columns={checkColumns} textOverflow="wrap" />
          )}
          <div>
            <Button
              label={showPassed ? "Hide passed checks" : `Show ${sec.findings.length - failed.length} passed checks`}
              variant="secondary"
              size="sm"
              onClick={() => setShowPassed((v) => !v)}
            />
          </div>
          <Muted>
            <b>Boundary</b> checks test the isolation itself — any failure grades the template F. <b>Hygiene</b> checks look
            at what the image carries (set-id programs, file capabilities, writable paths, baked-in keys and credentials).
            A check whose tool is missing from the image says so and counts as passed.
          </Muted>
        </div>
      )}
    </Section>
  );
}

function SourceSection({ name, source, image }: { name: string; source: Source; image: string }) {
  if (source.sandbox_id) {
    return (
      <Section title="Source" description="A checkpoint of a running sandbox: its filesystem (and on microVMs, its memory) as it was.">
        <Card>
          <KeyValueGrid
            columns={2}
            items={[{ label: "Captured from", value: <Link className="mono sbx-link" to={`/sandboxes/${source.sandbox_id}`}>{source.sandbox_id}</Link> }]}
          />
        </Card>
      </Section>
    );
  }
  return (
    <Section
      title="Source"
      description={
        source.dockerfile !== undefined
          ? "The Dockerfile this template was built from."
          : name === "base"
            ? "The built-in image every host ships (images/base/Dockerfile); microVM hosts boot it as a rootfs."
            : "The image this template was pulled from."
      }
    >
      {source.dockerfile !== undefined ? (
        <CodeBlock code={source.dockerfile} language="Dockerfile" />
      ) : (
        <CodeBlock code={`FROM ${image}`} language={name === "base" ? "Built-in image" : "Image"} />
      )}
    </Section>
  );
}

function UsageSection({ name, image }: { name: string; image: string }) {
  const url = typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:7800";
  const [tab, setTab] = useState("sdk");
  const code: Record<string, [string, string]> = {
    sdk: [
      "TypeScript",
      `import { acquire } from "qafas-sandbox";

const sb = await acquire("${url}", process.cwd(), "my-session", {
  apiKey: process.env.SBX_API_KEY,
  template: "${name}",
});
try {
  console.log((await sb.client.execBuffered("uname -a", sb.workspacePath)).stdout);
} finally {
  await sb.client.destroy();
}`,
    ],
    curl: [
      "HTTP",
      `curl -s -X POST ${url}/api/sandboxes \\
  -H "Authorization: Bearer $SBX_API_KEY" -H 'content-type: application/json' \\
  -d '{"template": "${name}", "pi_session": "my-session"}'`,
    ],
    extend: [
      "Dockerfile",
      `# A new template on top of this one: Templates → Create Template → Dockerfile.
FROM ${image}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends jq \\
 && rm -rf /var/lib/apt/lists/*
# Never put API keys or credentials in the image: the security scan grades
# a model key in ENV as F, and untrusted work cannot use an F template.`,
    ],
  };
  return (
    <Section
      title="Use this template"
      action={
        <SegmentedControl value={tab} onChange={setTab} label="Snippet">
          <SegmentedControlItem value="sdk" label="SDK" />
          <SegmentedControlItem value="curl" label="HTTP" />
          <SegmentedControlItem value="extend" label="Extend" />
        </SegmentedControl>
      }
    >
      <CodeBlock code={code[tab][1]} language={code[tab][0]} />
    </Section>
  );
}

function TemplateSandboxes({ name }: { name: string }) {
  const query = useQuery({ queryKey: ["sandboxes", "for-template"], queryFn: () => api.get<SandboxInfo[]>("/api/sandboxes") });
  return (
    <Query query={query}>
      {(all) => {
        const rows = all.filter((s) => s.template === name && s.state !== "destroyed");
        if (rows.length === 0) return <EmptyState title="No live sandboxes" description="None of the running sandboxes was created from this template." />;
        return <DataTable data={rows} idKey="id" columns={sandboxColumns()} />;
      }}
    </Query>
  );
}

export default function SnapshotDetailPage() {
  const { name = "" } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const alertDialog = useImperativeAlertDialog();
  const [sandboxOpen, setSandboxOpen] = useState(false);
  const sandboxKey = useOpenKey(sandboxOpen);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["snapshot", name],
    queryFn: () => api.get<SnapshotInfo[]>(`/api/snapshots/${encodeURIComponent(name)}`),
    enabled: !!name,
    refetchInterval: (q) => ((q.state.data ?? []).some((s) => s.state === "building") ? 3000 : false),
    retry: false,
  });

  const confirmDelete = () => {
    alertDialog.show({
      title: `Delete ${name}?`,
      description: "Fails if a live sandbox still uses this as its template. This cannot be undone.",
      actionLabel: "Delete",
      onAction: async () => {
        setDeleteError(null);
        try {
          await api.del(`/api/snapshots/${encodeURIComponent(name)}`);
          void qc.invalidateQueries({ queryKey: ["snapshots"] });
          navigate("/snapshots");
        } catch (err) {
          setDeleteError(err instanceof ApiError ? err.message : "Delete failed");
        }
        alertDialog.hide();
      },
    });
  };

  const rows = query.data ?? [];
  const first = rows[0];
  const active = rows.some((r) => r.state === "active");

  return (
    <Page
      title={name}
      description="Template"
      action={
        first && (
          <div className="sbx-row-wrap" style={{ gap: 8 }}>
            <Button label="New sandbox" isDisabled={!active} onClick={() => setSandboxOpen(true)} />
            {name !== "base" && <Button label="Delete" variant="destructive" onClick={confirmDelete} />}
          </div>
        )
      }
    >
      <Query query={query} empty={<EmptyState title="Unknown template" description={`No host has a template named ${name}.`} />}>
        {(list) => {
          const r = list[0];
          const source = (r.source ?? {}) as Source;
          // What a derived Dockerfile starts FROM: the pulled reference, or the image this
          // host tagged the build as (host-local; the same name on every host that built it).
          // On a Firecracker host `base`'s source is its rootfs file, which no Dockerfile can
          // start FROM; prefer a host that reports an image reference.
          const refs = list.map((h) => (h.source as Source | undefined)?.image).filter((i): i is string => !!i && !i.endsWith(".ext4"));
          const image = refs[0] ?? (name === "base" ? "localhost/sbx-base:dev" : `localhost/sbx-snap-${name}`);
          const runtimes = [...new Set(list.map((h) => runtimeLabel(h.runtime)))].join(", ");
          return (
            <>
              {deleteError && <ErrorState error={new Error(deleteError)} onRetry={() => setDeleteError(null)} />}
              <Card>
                <KeyValueGrid
                  columns={4}
                  items={[
                    { label: list.length > 1 ? "Runtimes" : "Runtime", value: runtimes },
                    { label: "Kind", value: kindLabel(r.kind) },
                    { label: "Created", value: <Ago value={r.created_at} /> },
                    { label: "Starts by", value: list.some((h) => h.memory_snapshot) ? (list.every((h) => h.memory_snapshot) ? "memory restore" : "memory restore (microVM hosts), boot") : "boot" },
                    {
                      label: "Hosts",
                      wide: true,
                      value: (
                        <Tags>
                          {list.map((h) => (
                            <Tag key={h.host_id ?? h.name}>
                              <span className="sbx-row" style={{ gap: 6 }}>
                                <StatusDot tone={stateTone[h.state]} label={h.host_id ?? "—"} />
                                <Muted>{runtimeLabel(h.runtime)}</Muted>
                                {h.security && <span className={`sbx-grade-chip sbx-grade-${h.security.grade}`}>{h.security.grade}</span>}
                                {h.error && <Muted>{h.error}</Muted>}
                              </span>
                            </Tag>
                          ))}
                        </Tags>
                      ),
                    },
                    {
                      label: "Warm pool",
                      wide: true,
                      value: (
                        <WarmCell sn={{ name, warm: r.warm ?? 0, warmReady: list.reduce((n, h) => n + (h.warm_ready ?? 0), 0), memorySnapshot: r.memory_snapshot ?? false }} />
                      ),
                    },
                  ]}
                />
              </Card>

              <SecuritySection rows={list} name={name} />
              <SourceSection name={name} source={source} image={image} />
              <UsageSection name={name} image={image} />
              <Section title="Sandboxes from this template">
                <TemplateSandboxes name={name} />
              </Section>
            </>
          );
        }}
      </Query>
      {alertDialog.element}
      <CreateSandboxDrawer key={sandboxKey} isOpen={sandboxOpen} onOpenChange={setSandboxOpen} prefillSnapshot={name} />
    </Page>
  );
}
