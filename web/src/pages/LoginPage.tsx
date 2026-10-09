import { useState, type FormEvent } from "react";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Button } from "@astryxdesign/core/Button";
import { token } from "../lib/api";
import { useHealth } from "../lib/useHealth";
import { StatusDot } from "../ui";
import { IconSignal, IconKey } from "../components/icons";
import { version as pkgVersion } from "../../package.json";

/**
 * Full-screen sign-in gate (App.tsx renders this instead of Shell+Routes
 * while useAuthed() is false). Validates the token for real against
 * /api/stats rather than accepting it blind — a wrong token used to just
 * bounce the user straight into a wall of per-page 401 banners.
 */
export default function LoginPage() {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  const health = useHealth();
  const reachable = health.data?.reachable ?? false;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const t = value.trim();
    if (!t) {
      setError("Enter your admin token first.");
      return;
    }
    setChecking(true);
    setError(null);
    try {
      const res = await fetch("/api/stats", { headers: { Authorization: `Bearer ${t}` } });
      if (res.status === 401) {
        setError("That token was rejected. Check SBX_ADMIN_TOKEN on the control plane.");
        return;
      }
      if (!res.ok) {
        setError(`Control plane returned an error (${res.status}).`);
        return;
      }
      token.set(t);
    } catch {
      setError("Could not reach the control plane. Is it running?");
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="sbx-login">
      <div className="sbx-login-box">
        <div className="sbx-login-brand">
          <IconSignal width={20} height={20} />
          <span>Qafas Sandbox</span>
        </div>

        <form className="sbx-card sbx-login-card" onSubmit={submit}>
          <div className="sbx-login-head">
            <h1 className="sbx-login-title">Sign in to this console</h1>
            <p className="sbx-login-desc">
              Paste the value of <code>SBX_ADMIN_TOKEN</code> (the default in <code>make dev-local</code> is{" "}
              <code>admin</code>). It is stored in this browser only.
            </p>
          </div>

          <TextInput
            label="Admin token"
            type="password"
            value={value}
            onChange={(v) => {
              setValue(v);
              if (error) setError(null);
            }}
            placeholder="Paste admin token"
            startIcon={<IconKey width={14} height={14} />}
            status={error ? { type: "error", message: error } : undefined}
            width="100%"
            hasAutoFocus
          />

          <Button type="submit" label={checking ? "Checking…" : "Sign in"} isLoading={checking} width="100%" />
        </form>

        <div className="sbx-login-status">
          <StatusDot tone={reachable ? "ready" : "danger"} label={reachable ? "Control plane reachable" : "Control plane unreachable"} />
          <span className="sbx-login-version mono">v{health.data?.version ?? pkgVersion}</span>
        </div>
      </div>
    </div>
  );
}
