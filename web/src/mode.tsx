import { createContext, use } from "react";
import type { Mode } from "./theme";

export const ModeContext = createContext<{ mode: Mode; toggle: () => void }>({
  mode: "dark",
  toggle: () => {},
});

export const useMode = () => use(ModeContext);
