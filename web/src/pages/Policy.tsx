import { useQuery } from "@tanstack/react-query";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import { Page, Query } from "../components/Page";
import { SeverityTag, Muted } from "../components/tables";
import { DataTable, EmptyState, Section } from "../ui";
import { api } from "../lib/api";
import { runtimeLabel } from "../lib/types";
import type { Host, PolicyRule } from "../lib/types";

const ruleColumns = [
  {
    key: "rule",
    header: "Rule",
    width: pixel(220),
    renderCell: (r: PolicyRule) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12.5 }}>
        {r.rule}
      </span>
    ),
  },
  { key: "severity", header: "Severity", width: pixel(110), renderCell: (r: PolicyRule) => <SeverityTag severity={r.severity} /> },
  {
    key: "description",
    header: "What it means",
    width: proportional(1, { minWidth: 320 }),
    renderCell: (r: PolicyRule) => (
      <span className="sbx-truncate" style={{ fontSize: 13 }} title={r.description}>
        {r.description}
      </span>
    ),
  },
];

const EGRESS_DETAIL =
  "Deny by default, via the proxy on port 3128. Anything else — and any name resolving to a private, link-local " +
  "or metadata address — is refused and logged as an egress deny. Connections that skip the proxy are dropped at " +
  "the boundary and raise a sandbox.denied alert. A harness may add hosts per sandbox with egress_allow; the " +
  "model never can.";

const WATCH_LABELS: Record<string, string> = {
  sensitive_read: "Reads reported",
  sensitive_write: "Writes reported",
  escape_paths: "Escape surfaces",
  escape_bins: "Escape binaries",
  setuid_bins: "Setuid binaries",
  recon_bins: "Recon binaries",
  metadata_hosts: "Metadata endpoints",
  canaries: "Canary credentials (decoys)",
  protected_env: "Env vars the client cannot set",
};

type ChipKind = "allow" | "deny" | "neutral";

/** One row per policy group: a fixed-width label (amber for enrichment-only
 * "watched" groups, green/red for the two proxy-enforced ones) and its
 * values as bordered chips — allow/deny chips carry the same colour as
 * their label, watched chips stay neutral since they aren't risk-graded. */
function PolicyRow({
  title,
  note,
  kind,
  items,
  detail,
}: {
  title: string;
  note: string;
  kind: ChipKind;
  items: string[];
  /** Longer explanation, shown on hover — for the one row (egress allowlist)
   * with real documentation behind it; everything else is self-explanatory
   * enough at a glance that the compact row shouldn't spend the space. */
  detail?: string;
}) {
  const titleClass = kind === "allow" ? "sbx-policy-row-title-ok" : kind === "deny" ? "sbx-policy-row-title-danger" : "sbx-policy-row-title-warn";
  const chipClass = kind === "allow" ? "sbx-policy-chip-allow" : kind === "deny" ? "sbx-policy-chip-deny" : "";
  const titleEl = <span className={`sbx-policy-row-title ${titleClass}`}>{title}</span>;
  return (
    <div className="sbx-policy-row">
      <div className="sbx-policy-row-label">
        {detail ? <Tooltip content={detail}>{titleEl}</Tooltip> : titleEl}
        <span className="sbx-policy-row-note">{note}</span>
      </div>
      <div className="sbx-policy-row-chips">
        {items.length === 0 ? (
          <Muted>none</Muted>
        ) : (
          items.map((x) => (
            <span key={x} className={`sbx-policy-chip mono ${chipClass}`} title={x}>
              {x}
            </span>
          ))
        )}
      </div>
    </div>
  );
}

function HostPolicy({ host }: { host: Host }) {
  const p = host.policy ?? {};
  const allow = p.egress?.allow ?? [];
  const deny = p.egress?.deny_cidrs_extra ?? [];
  const watch = Object.entries(p.watch ?? {});

  return (
    <div className="sbx-policy-host">
      <div className="sbx-policy-head">
        <span className="mono sbx-policy-host-id">{host.id}</span>
        <span className="mono sbx-policy-host-meta">
          {(host.tiers ?? []).map(runtimeLabel).join(", ") || host.backend} · {host.url}
        </span>
      </div>

      <PolicyRow title="Egress allowlist" note="enforced at the proxy" kind="allow" items={allow} detail={EGRESS_DETAIL} />
      {deny.length > 0 && <PolicyRow title="Denied CIDRs" note="enforced at the proxy" kind="deny" items={deny} />}
      {watch.map(([k, v]) => (
        <PolicyRow key={k} title={WATCH_LABELS[k] ?? k} note="reported, not blocked" kind="neutral" items={v} />
      ))}
    </div>
  );
}

export default function PolicyPage() {
  const query = useQuery({ queryKey: ["hosts"], queryFn: () => api.get<Host[]>("/api/hosts") });
  return (
    <Page title="Policy" description="What each host enforces at the boundary, and what it reports as enrichment.">
      <Query query={query} empty={<EmptyState title="No hosts registered" description="A qafas host registers its policy with the control plane on startup." />}>
        {(hosts) => {
          const rules = hosts.find((h) => h.policy?.rules?.length)?.policy?.rules ?? [];
          return (
            <>
              {hosts.map((h) => (
                <HostPolicy key={h.id} host={h} />
              ))}
              <Section
                title="Detection rules"
                description="Every alert carries one of these rules. Boundary signals (Seatbelt, seccomp, nftables, the proxy) are authoritative; command-line and eBPF matches are enrichment."
              >
                <DataTable
                  data={rules}
                  idKey="rule"
                  empty="No host has reported its rule catalogue yet — upgrade qafas."
                  columns={ruleColumns}
                />
              </Section>
            </>
          );
        }}
      </Query>
    </Page>
  );
}
