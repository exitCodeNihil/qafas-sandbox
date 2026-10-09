import { useQueryClient } from "@tanstack/react-query";
import { useToast } from "@astryxdesign/core/Toast";
import { api, ApiError } from "./api";
import type { LifecycleVerb } from "./sandboxActions";
import type { SandboxInfo } from "./types";

/**
 * Lifecycle mutations shared by the Sandboxes table row menu and the
 * sandbox detail header — one place that knows how to call the verb,
 * invalidate the right queries, and turn a v3-route 404 (the connected
 * control plane doesn't serve it yet) into a readable toast instead of an
 * uncaught rejection.
 */
export function useSandboxActions() {
  const qc = useQueryClient();
  const toast = useToast();

  const invalidate = (id: string) => {
    void qc.invalidateQueries({ queryKey: ["sandboxes"] });
    void qc.invalidateQueries({ queryKey: ["sandbox", id] });
  };

  const report = (err: unknown, verb: string) => {
    if (err instanceof ApiError && err.status === 404) {
      toast({ body: `${verb}: needs a v3 host — the connected control plane doesn't serve this route yet.`, type: "error" });
    } else {
      toast({ body: err instanceof Error ? `${verb}: ${err.message}` : `${verb} failed`, type: "error" });
    }
  };

  const runVerb = async (sb: SandboxInfo, verb: LifecycleVerb) => {
    try {
      await api.post(`/api/sandboxes/${sb.id}/${verb}`);
      invalidate(sb.id);
    } catch (err) {
      report(err, verb);
    }
  };

  const destroy = async (sb: SandboxInfo) => {
    try {
      await api.del(`/api/sandboxes/${sb.id}`);
      invalidate(sb.id);
    } catch (err) {
      report(err, "Delete");
    }
  };

  return { runVerb, destroy };
}
