import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@astryxdesign/core/Button";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Switch } from "@astryxdesign/core/Switch";
import { RadioList, RadioListItem } from "@astryxdesign/core/RadioList";
import { Page, ErrorState, Loading } from "../components/Page";
import { KeyValueEditor, type KVRow } from "../components/KeyValueEditor";
import { Ago } from "../components/tables";
import { api } from "../lib/api";
import { Card, CodeBlock, KeyValueGrid, Notice, Section, StatCard, StatRow } from "../ui";
import type { ObservabilityCapture, ObservabilityProvider, ObservabilitySettings, ObservabilitySettingsInput, ObservabilityTestResult } from "../lib/types";

function rowsFromHeaders(headers: Record<string, string> | undefined): KVRow[] {
  return Object.entries(headers ?? {}).map(([key, value]) => ({ key, value }));
}

function headersFromRows(rows: KVRow[]): Record<string, string> {
  return Object.fromEntries(rows.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value]));
}

type FormState = {
  enabled: boolean;
  provider: ObservabilityProvider;
  host: string;
  public_key: string;
  secret_key: string;
  otlp_url: string;
  otlp_headers: KVRow[];
  capture: ObservabilityCapture;
};

function toForm(s: ObservabilitySettings): FormState {
  return {
    enabled: s.enabled,
    provider: s.provider,
    host: s.host ?? "",
    public_key: s.public_key ?? "",
    secret_key: "",
    otlp_url: s.otlp_url ?? "",
    otlp_headers: rowsFromHeaders(s.otlp_headers),
    capture: s.capture,
  };
}

function toBody(f: FormState): ObservabilitySettingsInput {
  return {
    enabled: f.enabled,
    provider: f.provider,
    host: f.host.trim() || undefined,
    public_key: f.public_key.trim() || undefined,
    secret_key: f.secret_key.trim() || undefined,
    otlp_url: f.otlp_url.trim() || undefined,
    otlp_headers: headersFromRows(f.otlp_headers),
    capture: f.capture,
  };
}

function PrometheusCard() {
  const origin = window.location.origin;
  const targetsUrl = `${origin}/api/prometheus/targets`;
  const metricsUrl = `${origin}/metrics`;
  const snippet = `scrape_configs:
  - job_name: qafas-sandbox
    http_sd_configs:
      - url: ${targetsUrl}
        authorization:
          type: Bearer
          credentials: <SBX_ADMIN_TOKEN or a host token>
    bearer_token: <SBX_ADMIN_TOKEN or a host token>
`;
  return (
    <Section title="Prometheus" description="Read-only. Point Prometheus at this control plane; it discovers every worker host through the same bearer token.">
      <Card>
        <div className="sbx-stack-16">
          <KeyValueGrid
            columns={2}
            items={[
              { label: "Service discovery", value: <span className="mono sbx-truncate">{targetsUrl}</span> },
              { label: "This host's metrics", value: <span className="mono sbx-truncate">{metricsUrl}</span> },
            ]}
          />
          <div className="sbx-stack-8">
            <span className="sbx-field-label">prometheus.yml</span>
            <CodeBlock code={snippet} language="yaml" />
          </div>
        </div>
      </Card>
    </Section>
  );
}

export default function ObservabilityPage() {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["settings", "observability"],
    queryFn: () => api.get<ObservabilitySettings>("/api/settings/observability"),
    retry: false,
  });

  const [form, setForm] = useState<FormState | null>(null);
  const [seeded, setSeeded] = useState<ObservabilitySettings | null>(null);
  useEffect(() => {
    if (query.data && form === null) {
      setForm(toForm(query.data));
      setSeeded(query.data);
    }
  }, [query.data, form]);
  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setForm((f) => (f ? { ...f, [key]: value } : f));

  // Whether the form has unsaved edits relative to what it was last seeded from —
  // Reload only overwrites the form when this is false.
  const dirty = useMemo(
    () => form !== null && seeded !== null && JSON.stringify(toBody(form)) !== JSON.stringify(toBody(toForm(seeded))),
    [form, seeded],
  );

  const [saving, setSaving] = useState(false);
  const [saveResult, setSaveResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<ObservabilityTestResult | null>(null);
  const [reloading, setReloading] = useState(false);
  const [reloadNotice, setReloadNotice] = useState<string | null>(null);

  const save = async () => {
    if (!form) return;
    setSaving(true);
    setSaveResult(null);
    try {
      const saved = await api.put<ObservabilitySettings>("/api/settings/observability", toBody(form));
      setForm(toForm(saved));
      setSeeded(saved);
      setSaveResult({ ok: true, msg: "Saved." });
      void qc.invalidateQueries({ queryKey: ["settings", "observability"] });
    } catch (err) {
      setSaveResult({ ok: false, msg: err instanceof Error ? err.message : "Save failed" });
    } finally {
      setSaving(false);
    }
  };

  const reload = async () => {
    setReloading(true);
    setReloadNotice(null);
    try {
      const fresh = await query.refetch();
      if (!fresh.data) return;
      if (dirty) {
        setReloadNotice("Settings changed on the server. Save or discard your edits, then reload again to see them.");
      } else {
        setForm(toForm(fresh.data));
        setSeeded(fresh.data);
      }
    } finally {
      setReloading(false);
    }
  };

  const test = async () => {
    if (!form) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.post<ObservabilityTestResult>("/api/settings/observability/test", toBody(form));
      setTestResult(result);
    } catch (err) {
      setTestResult({ ok: false, detail: err instanceof Error ? err.message : "Test failed" });
    } finally {
      setTesting(false);
    }
  };

  const health = query.data?.health;

  return (
    <Page title="Observability" description="Export every session as an OTLP trace — to Langfuse, or any OTLP/HTTP collector.">
      {query.isLoading && <Loading />}
      {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}

      {form && (
        <div className="sbx-stack-24">
          <Section title="Export">
            <Card>
              <div className="sbx-stack-24">
                <Switch label="Enable export" value={form.enabled} onChange={(v) => set("enabled", v)} />

                <RadioList label="Provider" value={form.provider} onChange={(v) => set("provider", v as ObservabilityProvider)}>
                  <RadioListItem value="langfuse" label="Langfuse" description="Pushes an OTLP batch to a Langfuse project with basic auth." />
                  <RadioListItem value="otlp" label="OTLP" description="Pushes an OTLP/HTTP batch to any collector endpoint." />
                </RadioList>

                {form.provider === "langfuse" ? (
                  <div className="sbx-stack-16">
                    <TextInput label="Host" value={form.host} onChange={(v) => set("host", v)} placeholder="https://cloud.langfuse.com" width="100%" />
                    <TextInput label="Public key" value={form.public_key} onChange={(v) => set("public_key", v)} width="100%" />
                    <TextInput
                      label="Secret key"
                      type="password"
                      value={form.secret_key}
                      onChange={(v) => set("secret_key", v)}
                      description={query.data?.secret_key_set ? "Leave blank to keep the stored key." : undefined}
                      isOptional={query.data?.secret_key_set}
                      width="100%"
                    />
                  </div>
                ) : (
                  <div className="sbx-stack-16">
                    <TextInput label="URL" value={form.otlp_url} onChange={(v) => set("otlp_url", v)} placeholder="https://otel-collector:4318/v1/traces" width="100%" />
                    <KeyValueEditor label="Headers" rows={form.otlp_headers} onChange={(rows) => set("otlp_headers", rows)} addLabel="Add header" keyPlaceholder="Header" valuePlaceholder="Value" />
                  </div>
                )}

                <RadioList label="Capture" value={form.capture} onChange={(v) => set("capture", v as ObservabilityCapture)}>
                  <RadioListItem value="all" label="All sessions" />
                  <RadioListItem value="alerts_only" label="Sessions with alerts only" />
                </RadioList>

                {saveResult && (
                  <Notice tone={saveResult.ok ? "success" : "error"} title={saveResult.ok ? "Saved" : "Save failed"}>
                    {saveResult.msg}
                  </Notice>
                )}
                {testResult && (
                  <Notice tone={testResult.ok ? "success" : "error"} title={testResult.ok ? "Connection OK" : "Connection failed"}>
                    {testResult.detail}
                  </Notice>
                )}
                {reloadNotice && <Notice title="Not reloaded">{reloadNotice}</Notice>}

                <div className="sbx-row" style={{ gap: 8 }}>
                  <Button label="Save" onClick={save} isLoading={saving} />
                  <Button label="Test connection" variant="secondary" onClick={test} isLoading={testing} />
                  <Button label="Reload" variant="ghost" onClick={reload} isLoading={reloading} />
                </div>
              </div>
            </Card>
          </Section>

          <Section title="Health">
            <StatRow>
              <StatCard label="Delivered" value={(health?.delivered ?? 0).toLocaleString()} />
              <StatCard label="Dropped" value={(health?.dropped ?? 0).toLocaleString()} />
              <StatCard label="Last OK" value={health?.last_ok_ts ? <Ago value={health.last_ok_ts} /> : "never"} />
              <StatCard label="Last error" value={health?.last_error ?? "none"} />
            </StatRow>
          </Section>

          <PrometheusCard />
        </div>
      )}
    </Page>
  );
}
