import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { HStack } from "@astryxdesign/core/Stack";
import { TextInput } from "@astryxdesign/core/TextInput";
import { NumberInput } from "@astryxdesign/core/NumberInput";
import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { RadioList, RadioListItem } from "@astryxdesign/core/RadioList";
import { Tokenizer } from "@astryxdesign/core/Tokenizer";
import { createStaticSource, type SearchableItem } from "@astryxdesign/core/Typeahead";
import { Button } from "@astryxdesign/core/Button";
import { Banner } from "@astryxdesign/core/Banner";
import { CodeBlock } from "../ui";
import { Drawer, DrawerSection } from "./Drawer";
import { KeyValueEditor, type KVRow } from "./KeyValueEditor";
import { api, ApiError } from "../lib/api";
import { RUNTIMES, SIZE_NAMES } from "../lib/types";
import type { ApiKeyCreated, ApiKeyScope } from "../lib/types";

const emptySource = createStaticSource<SearchableItem>([]);

function rowsToObject(rows: KVRow[]): Record<string, string> | undefined {
  const entries = rows.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value] as const);
  return entries.length ? Object.fromEntries(entries) : undefined;
}

/** One-time key reveal — shown once, right after create, then gone for
 * good (protocol.md §4b: the secret is stored as SHA-256, never returned
 * again). */
function RevealPanel({ created }: { created: ApiKeyCreated }) {
  const controlPlaneUrl = typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:7800";
  return (
    <>
      <Banner status="warning" title="Store it now — it is not shown again" description="This is the only time the full key is displayed. The control plane keeps only its hash." />
      <CodeBlock code={created.key} language="key" />
      <DrawerSection title="Use it">
        <CodeBlock code={`SBX_API_KEY=${created.key} pi --sandbox-url ${controlPlaneUrl} -e ./pi-extension`} language="bash" />
        <CodeBlock code={`import { acquire } from "qafas-sandbox";\n\nconst sb = await acquire("${controlPlaneUrl}", process.cwd(), "my-session", {\n  apiKey: "${created.key}",\n});`} language="typescript" />
        <CodeBlock code={`from qafas_sandbox import acquire\n\nwith acquire("${controlPlaneUrl}", "/path/to/repo", "my-session",\n             api_key="${created.key}") as sb:\n    ...`} language="python" />
      </DrawerSection>
    </>
  );
}

export function CreateApiKeyDrawer({ isOpen, onOpenChange }: { isOpen: boolean; onOpenChange: (open: boolean) => void }) {
  const qc = useQueryClient();

  const [name, setName] = useState("");
  const [scope, setScope] = useState<ApiKeyScope>("sandboxes");
  const [maxConcurrent, setMaxConcurrent] = useState<number | null>(null);
  const [maxPerHour, setMaxPerHour] = useState<number | null>(null);
  const [tiers, setTiers] = useState<Set<string>>(new Set());
  const [maxTtl, setMaxTtl] = useState<number | null>(null);
  const [allowedSizes, setAllowedSizes] = useState<Set<string>>(new Set());
  const [maxCpus, setMaxCpus] = useState<number | null>(null);
  const [maxMemMib, setMaxMemMib] = useState<number | null>(null);
  const [maxDiskMib, setMaxDiskMib] = useState<number | null>(null);
  const [allowedEgress, setAllowedEgress] = useState<SearchableItem[]>([]);
  const [labels, setLabels] = useState<KVRow[]>([]);

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);

  const reset = () => {
    setName("");
    setScope("sandboxes");
    setMaxConcurrent(null);
    setMaxPerHour(null);
    setTiers(new Set());
    setMaxTtl(null);
    setAllowedSizes(new Set());
    setMaxCpus(null);
    setMaxMemMib(null);
    setMaxDiskMib(null);
    setAllowedEgress([]);
    setLabels([]);
    setErrors({});
    setSubmitError(null);
    setCreated(null);
  };

  const close = () => {
    onOpenChange(false);
    reset();
  };

  const toggleTier = (t: string, checked: boolean) =>
    setTiers((prev) => {
      const next = new Set(prev);
      if (checked) next.add(t);
      else next.delete(t);
      return next;
    });

  const toggleSize = (s: string, checked: boolean) =>
    setAllowedSizes((prev) => {
      const next = new Set(prev);
      if (checked) next.add(s);
      else next.delete(s);
      return next;
    });

  const submit = async () => {
    const nextErrors: Record<string, string> = {};
    if (!name.trim()) nextErrors.name = "Required.";
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;

    setSubmitting(true);
    setSubmitError(null);
    try {
      const limits = {
        max_concurrent: maxConcurrent ?? undefined,
        max_per_hour: maxPerHour ?? undefined,
        allowed_tiers: tiers.size ? [...tiers] : undefined,
        max_ttl_secs: maxTtl != null ? maxTtl * 60 : undefined,
        allowed_egress: allowedEgress.length ? allowedEgress.map((t) => t.label) : undefined,
        allowed_sizes: allowedSizes.size ? [...allowedSizes] : undefined,
        max_cpus: maxCpus ?? undefined,
        max_mem_mib: maxMemMib ?? undefined,
        max_disk_mib: maxDiskMib ?? undefined,
      };
      const res = await api.post<ApiKeyCreated>("/api/keys", {
        name: name.trim(),
        scopes: [scope],
        limits,
        labels: rowsToObject(labels),
      });
      void qc.invalidateQueries({ queryKey: ["keys"] });
      setCreated(res);
    } catch (err) {
      setSubmitError(
        err instanceof ApiError && err.status === 404
          ? "Creating API keys needs a v3 host (the connected control plane doesn't serve /api/keys yet)."
          : err instanceof Error
            ? err.message
            : "Create failed",
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      isOpen={isOpen}
      onOpenChange={(open) => (open ? onOpenChange(open) : close())}
      title={created ? "API key created" : "Create API key"}
      footer={
        created ? (
          <Button label="Done" onClick={close} />
        ) : (
          <>
            <Button label="Cancel" variant="secondary" onClick={close} />
            <Button label="Create" onClick={submit} isLoading={submitting} />
          </>
        )
      }
    >
      {created ? (
        <RevealPanel created={created} />
      ) : (
        <>
          {submitError && <Banner status="error" title="Couldn't create the key" description={submitError} />}

          <TextInput
            label="Name"
            value={name}
            onChange={setName}
            placeholder="ci-runner"
            isRequired
            status={errors.name ? { type: "error", message: errors.name } : undefined}
            width="100%"
          />

          <RadioList label="Scope" value={scope} onChange={(v) => setScope(v as ApiKeyScope)}>
            <RadioListItem value="sandboxes" label="Sandboxes" description="Create and manage its own sandboxes." />
            <RadioListItem value="admin" label="Admin" description="Everything the admin token can do." />
          </RadioList>

          <DrawerSection title="Limits">
            <span className="sbx-field-help">Leave a field blank for unlimited.</span>
            <div className="sbx-numrow">
              <span className="sbx-label">Max concurrent</span>
              <NumberInput label="Max concurrent" isLabelHidden value={maxConcurrent} onChange={setMaxConcurrent} hasClear min={0} placeholder="Unlimited" width="100%" />
            </div>
            <div className="sbx-numrow">
              <span className="sbx-label">Max per hour</span>
              <NumberInput label="Max per hour" isLabelHidden value={maxPerHour} onChange={setMaxPerHour} hasClear min={0} placeholder="Unlimited" width="100%" />
            </div>
            <div className="sbx-numrow">
              <span className="sbx-label">Max TTL (min)</span>
              <NumberInput label="Max TTL minutes" isLabelHidden value={maxTtl} onChange={setMaxTtl} hasClear min={0} placeholder="Unlimited" width="100%" />
            </div>
            <div className="sbx-numrow">
              <span className="sbx-label">Max CPUs</span>
              <NumberInput label="Max CPUs" isLabelHidden value={maxCpus} onChange={setMaxCpus} hasClear min={0.25} step={0.25} placeholder="Unlimited" width="100%" />
            </div>
            <div className="sbx-numrow">
              <span className="sbx-label">Max memory (MiB)</span>
              <NumberInput label="Max memory MiB" isLabelHidden value={maxMemMib} onChange={setMaxMemMib} hasClear min={0} placeholder="Unlimited" width="100%" />
            </div>
            <div className="sbx-numrow">
              <span className="sbx-label">Max disk (MiB)</span>
              <NumberInput label="Max disk MiB" isLabelHidden value={maxDiskMib} onChange={setMaxDiskMib} hasClear min={0} placeholder="Unlimited" width="100%" />
            </div>
          </DrawerSection>

          <DrawerSection title="Allowed sizes">
            <HStack gap={4}>
              {SIZE_NAMES.map((s) => (
                <CheckboxInput key={s} label={s} value={allowedSizes.has(s)} onChange={(checked) => toggleSize(s, checked)} />
              ))}
            </HStack>
            <span className="sbx-field-help">None selected means any size, still bounded by the max fields above.</span>
          </DrawerSection>

          <DrawerSection title="Allowed runtimes">
            <HStack gap={4}>
              {RUNTIMES.map((t) => (
                <CheckboxInput key={t.value} label={t.label} value={tiers.has(t.value)} onChange={(checked) => toggleTier(t.value, checked)} />
              ))}
            </HStack>
            <span className="sbx-field-help">None selected means every runtime this control plane offers.</span>
          </DrawerSection>

          <Tokenizer label="Allowed egress" searchSource={emptySource} value={allowedEgress} onChange={setAllowedEgress} hasCreate placeholder="github.com, *.npmjs.org…" width="100%" />

          <KeyValueEditor label="Labels" rows={labels} onChange={setLabels} addLabel="Add Label" keyPlaceholder="key" valuePlaceholder="value" />
        </>
      )}
    </Drawer>
  );
}
