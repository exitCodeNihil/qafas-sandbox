import { useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { TextInput } from "@astryxdesign/core/TextInput";
import { ApiError, token } from "../lib/api";
import { HStack } from "@astryxdesign/core/Stack";
import { Spinner } from "@astryxdesign/core/Spinner";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { PageHeader, Notice } from "../ui";

/**
 * Standard page frame: 32px gutter, 1440 max width, a 28/600 title with a
 * single supporting line, and a right-aligned action slot. Everything below
 * the header is separated on the 32px section rhythm by `.sbx-page`.
 */
export function Page({
  title,
  description,
  id,
  action,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  /** Monospace id line under the title (detail pages). */
  id?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="sbx-page">
      <PageHeader title={title} description={description} id={id} actions={action} />
      {children}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 200, gap: 12 }}>
      <Spinner size="md" />
      <span style={{ fontSize: 13, color: "var(--color-text-secondary)" }}>{label}…</span>
    </div>
  );
}

/** A 401 is not an error to retry, it is a missing token: ask for it right here. */
function SignIn({ onDone }: { onDone?: () => void }) {
  const qc = useQueryClient();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const save = () => {
    if (!value.trim()) {
      setError("Enter your admin token first.");
      return;
    }
    setError(null);
    token.set(value.trim());
    void qc.invalidateQueries();
    onDone?.();
  };
  return (
    <Banner
      status="warning"
      title="Admin token required"
      description="The control plane answered 401. Paste the value of SBX_ADMIN_TOKEN (the default in `make dev-local` is `admin`). It is stored in this browser only."
      endContent={
        <HStack gap={2} vAlign="end">
          <TextInput
            label="Admin token"
            size="sm"
            type="password"
            value={value}
            onChange={(v) => {
              setValue(v);
              if (error) setError(null);
            }}
            placeholder="admin"
            width={220}
            status={error ? { type: "error", message: error } : undefined}
          />
          <Button label="Save" size="sm" onClick={save} />
        </HStack>
      }
    />
  );
}

/** A route the connected control plane hasn't grown yet (§4a v3). Not a
 * bug — the dashboard is meant to run against a v2-only host too. */
export function NeedsV3({ what = "This" }: { what?: string }) {
  return <Notice title="Needs a v3 host">{`${what} needs the v3 control plane routes, which the connected host doesn't serve yet.`}</Notice>;
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (error instanceof ApiError && error.status === 401) return <SignIn onDone={onRetry} />;
  if (error instanceof ApiError && error.status === 404) return <NeedsV3 />;
  const message = error instanceof Error ? error.message : "Something went wrong";
  return (
    <Banner
      status="error"
      title="Request failed"
      description={message}
      endContent={onRetry ? <Button label="Retry" size="sm" variant="secondary" onClick={onRetry} /> : undefined}
    />
  );
}

/**
 * Query-state gate. Keeps every page from re-implementing the
 * loading / error / empty triad by hand.
 */
export function Query<T>({
  query,
  empty,
  children,
}: {
  query: { isLoading: boolean; error: unknown; data: T | undefined; refetch: () => unknown };
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  if (!query.data) return null;
  if (empty && Array.isArray(query.data) && query.data.length === 0) return <>{empty}</>;
  return <>{children(query.data)}</>;
}
