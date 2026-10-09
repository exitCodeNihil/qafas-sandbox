import { createContext, use, useEffect } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Global session filter: shown in the shell header, narrows Sandboxes,
 * Alerts, Egress and Overview. Persisted in the URL (`?session=`, so a link
 * is shareable) and mirrored to localStorage (so it survives navigating to a
 * page that clears the query string).
 */
const KEY = "sbx_session_filter";

const SessionFilterContext = createContext<{
  session: string | null;
  setSession: (s: string | null) => void;
}>({ session: null, setSession: () => {} });

export function SessionFilterProvider({ children }: { children: React.ReactNode }) {
  const [params, setParams] = useSearchParams();
  const session = params.get("session");

  // Re-seed `?session=` from localStorage whenever it's missing from the
  // URL — a fresh tab, or a sidebar link that navigated to a bare path
  // (React Router's <Link> doesn't carry the query string across routes).
  useEffect(() => {
    if (session) return;
    const stored = localStorage.getItem(KEY);
    if (stored) {
      setParams(
        (p) => {
          p.set("session", stored);
          return p;
        },
        { replace: true },
      );
    }
  }, [session, setParams]);

  const setSession = (s: string | null) => {
    if (s) localStorage.setItem(KEY, s);
    else localStorage.removeItem(KEY);
    setParams(
      (p) => {
        if (s) p.set("session", s);
        else p.delete("session");
        return p;
      },
      { replace: true },
    );
  };

  return <SessionFilterContext value={{ session, setSession }}>{children}</SessionFilterContext>;
}

export const useSessionFilter = () => use(SessionFilterContext);
