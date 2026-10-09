import { useSyncExternalStore } from "react";
import { token } from "./api";

/** Gate for App.tsx: an admin token is present in this browser. Individual
 * pages still handle a wrong/expired token via Page.tsx's existing 401
 * banner — this only covers the "no token at all" case with a real screen. */
export function useAuthed(): boolean {
  return useSyncExternalStore(token.subscribe, () => !!token.get());
}
