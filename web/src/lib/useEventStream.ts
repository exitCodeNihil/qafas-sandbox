import { useEffect, useRef } from "react";
import { token } from "./api";
import type { Event } from "./types";

/**
 * Subscribes to `GET /api/events/stream?<params>` for as long as the component
 * is mounted, reopening whenever `params` changes (compared by value, not
 * identity — build it inline at the call site). `onEvent` fires for every
 * parsed frame; a malformed one (a keep-alive ping) is ignored. `onEvent` is
 * read through a ref so passing a fresh closure each render doesn't reopen
 * the connection — only a change to `params` does.
 */
export function useEventStream(params: Record<string, string | undefined>, onEvent: (event: Event) => void): void {
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;
  const key = JSON.stringify(params);

  useEffect(() => {
    const search = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined) search.set(k, v);
    const t = token.get();
    if (t) search.set("token", t);
    const es = new EventSource(`/api/events/stream?${search}`);
    es.onmessage = (e) => {
      try {
        onEventRef.current(JSON.parse(e.data));
      } catch {
        // ping
      }
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
}
