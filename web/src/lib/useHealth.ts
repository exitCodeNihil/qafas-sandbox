import { useQuery } from "@tanstack/react-query";

/**
 * GET /healthz — shared by the login gate and the shell's connection status
 * (reachability + version label). One `["healthz"]` query (react-query dedupes
 * by key), instead of each caller fetching it separately.
 */
export function useHealth() {
  return useQuery({
    queryKey: ["healthz"],
    queryFn: async (): Promise<{ reachable: boolean; version: string | null }> => {
      const res = await fetch("/healthz");
      if (!res.ok) return { reachable: false, version: null };
      const data = (await res.json().catch(() => ({}))) as { version?: string };
      return { reachable: true, version: data.version ?? null };
    },
    refetchInterval: 15_000,
    retry: false,
  });
}
