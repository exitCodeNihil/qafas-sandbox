import { useRef } from "react";

/** A `key` that changes on every *open*: the drawer remounts with fresh form state each
 *  time it opens, while the closing instance stays mounted for the Dialog's exit transition. */
export function useOpenKey(isOpen: boolean): number {
  const seq = useRef(0);
  const was = useRef(false);
  if (isOpen && !was.current) seq.current += 1;
  was.current = isOpen;
  return seq.current;
}
