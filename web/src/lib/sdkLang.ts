import { useState } from "react";

/** SDK language toggle (Get Started page), persisted like the theme mode. */
export type SdkLang = "ts" | "python";
const KEY = "sbx_sdk_lang";

export function useSdkLang() {
  const [lang, setLangState] = useState<SdkLang>(() => (localStorage.getItem(KEY) === "python" ? "python" : "ts"));
  const setLang = (l: SdkLang) => {
    localStorage.setItem(KEY, l);
    setLangState(l);
  };
  return { lang, setLang };
}
