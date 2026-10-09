// Shared API client. All calls are same-origin; auth is a token stored in
// localStorage sent as Bearer header.

const TOKEN_KEY = "sbx_admin_token";
const listeners = new Set<() => void>();

export const token = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => {
    localStorage.setItem(TOKEN_KEY, t);
    listeners.forEach((l) => l());
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY);
    listeners.forEach((l) => l());
  },
  /** For useAuthed() (lib/auth.ts) — re-render the login gate whenever the
   * token changes, from the login form or from ConnectionStatus's "Clear". */
  subscribe: (cb: () => void) => {
    listeners.add(cb);
    return () => listeners.delete(cb);
  },
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  const t = token.get();
  if (t) headers["Authorization"] = `Bearer ${t}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 204) return undefined as T;

  let payload: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!res.ok) {
    const msg =
      (payload && typeof payload === "object" && "error" in payload
        ? String((payload as { error: unknown }).error)
        : typeof payload === "string"
          ? payload
          : "") || `Request failed (${res.status})`;
    throw new ApiError(res.status, msg);
  }
  return payload as T;
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b ?? {}),
  put: <T>(p: string, b?: unknown) => request<T>("PUT", p, b ?? {}),
  del: <T>(p: string) => request<T>("DELETE", p),
};
