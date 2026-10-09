import type { Tone } from "../ui";
import { ttlLabel } from "./format";
import type { SandboxInfo, SandboxState } from "./types";

/** Status-dot tone per lifecycle state — the console never fills a state pill. */
export const stateTone: Record<SandboxState, Tone> = {
  creating: "accent",
  ready: "ready",
  busy: "busy",
  paused: "warning",
  stopped: "warning",
  archived: "muted",
  destroyed: "danger",
};

export type LifecycleVerb = "stop" | "start" | "pause" | "resume" | "archive";

const VERB_LABEL: Record<LifecycleVerb, string> = {
  stop: "Stop",
  start: "Start",
  pause: "Pause",
  resume: "Resume",
  archive: "Archive",
};

const VERB_FROM: Record<LifecycleVerb, SandboxState[]> = {
  stop: ["ready", "busy"],
  start: ["stopped", "archived"],
  pause: ["ready"],
  resume: ["paused"],
  archive: ["ready", "busy", "paused", "stopped"],
};

/**
 * Which lifecycle verbs apply to a sandbox right now, each with a reason
 * when disabled (wrong state, or the tier doesn't support lifecycle at
 * for it — protocol.md §3a v4: stop/start everywhere, pause/resume/archive
 * on remote only). Delete is handled separately since it's valid from every state.
 */
export function lifecycleActions(sb: SandboxInfo): { verb: LifecycleVerb; label: string; disabledReason?: string }[] {
  const isRemote = sb.isolation === "remote";
  return (Object.keys(VERB_FROM) as LifecycleVerb[]).map((verb) => {
    if (!isRemote && verb !== "stop" && verb !== "start") return { verb, label: VERB_LABEL[verb], disabledReason: "Needs the Firecracker runtime" };
    if (!VERB_FROM[verb].includes(sb.state)) return { verb, label: VERB_LABEL[verb], disabledReason: `Not available from ${sb.state}` };
    return { verb, label: VERB_LABEL[verb] };
  });
}

export function canDelete(sb: SandboxInfo): boolean {
  return sb.state !== "destroyed";
}

/**
 * v4 resolved timer as relative text — "sleeps in 12m" while ready/busy
 * (`auto_stop_secs - idle_secs`), "deletes in 23h" while stopped/archived
 * (`auto_delete_secs` minus time since `state_changed_at`), or "running 5h"
 * (`running_secs`) when auto-stop is disabled and the sandbox is just live.
 * `null` when there is nothing to show — the timer is 0/disabled, or the
 * daemon is too old to report `idle_secs`/`running_secs`/`state_changed_at`.
 */
export function timerLabel(sb: SandboxInfo): string | null {
  if (sb.state === "ready" || sb.state === "busy") {
    if (sb.auto_stop_secs && sb.idle_secs !== undefined) {
      const remaining = sb.auto_stop_secs - sb.idle_secs;
      // The countdown hits 0 before the daemon's own stop actually lands; "0s" would
      // read as stuck rather than in-flight.
      return remaining <= 0 ? "stopping…" : `sleeps in ${ttlLabel(remaining)}`;
    }
    if (sb.running_secs !== undefined) return `running ${ttlLabel(sb.running_secs)}`;
    return null;
  }
  if (sb.state === "stopped" || sb.state === "archived") {
    if (sb.auto_delete_secs && sb.state_changed_at) {
      const elapsed = (Date.now() - new Date(sb.state_changed_at).getTime()) / 1000;
      const remaining = sb.auto_delete_secs - elapsed;
      return remaining <= 0 ? "deleting…" : `deletes in ${ttlLabel(remaining)}`;
    }
    return null;
  }
  return null;
}
