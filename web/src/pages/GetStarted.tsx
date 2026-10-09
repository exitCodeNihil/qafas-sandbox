import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Button } from "@astryxdesign/core/Button";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Page } from "../components/Page";
import { Card, CodeBlock } from "../ui";
import { useSdkLang } from "../lib/sdkLang";
import { token } from "../lib/api";

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <div className="sbx-step">
      <span className="sbx-step-n">{n}</span>
      <div className="sbx-step-body">
        <h3>{title}</h3>
        {children}
      </div>
    </div>
  );
}

function TokenField() {
  const qc = useQueryClient();
  const [value, setValue] = useState(token.get() ?? "");
  const [error, setError] = useState<string | null>(null);
  const save = () => {
    if (!value.trim()) {
      setError("Enter your admin token first.");
      return;
    }
    setError(null);
    token.set(value.trim());
    void qc.invalidateQueries();
  };
  return (
    <div className="sbx-row" style={{ gap: 8, alignItems: "flex-end" }}>
      <TextInput
        label="Admin token"
        type="password"
        value={value}
        onChange={(v) => {
          setValue(v);
          if (error) setError(null);
        }}
        placeholder="admin"
        width={280}
        status={error ? { type: "error", message: error } : undefined}
      />
      <Button label="Save" onClick={save} />
    </div>
  );
}

export default function GetStartedPage() {
  const { lang, setLang } = useSdkLang();
  const navigate = useNavigate();
  const url = typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:7800";

  const isTs = lang === "ts";
  const installCode = isTs ? "npm install qafas-sandbox" : "pip install qafas-sandbox";
  const createCode = isTs
    ? `import { acquire } from "qafas-sandbox";

const sb = await acquire("${url}", process.cwd(), "my-session", {
  apiKey: process.env.SBX_API_KEY,
  runtime: "firecracker",
});
try {
  const res = await sb.client.execBuffered("echo hello", sb.workspacePath);
  console.log(res.stdout);
} finally {
  await sb.client.destroy();
}`
    : `from qafas_sandbox import acquire

with acquire("${url}", "/path/to/repo", "my-session",
             api_key=os.environ["SBX_API_KEY"]) as sb:
    result = sb.exec_buffered("echo hello")
    print(result.stdout)`;

  return (
    <Page
      title="Get Started"
      description="Install the SDK and get your sandboxes running."
      action={
        <SegmentedControl value={lang} onChange={(v) => setLang(v as "ts" | "python")} label="SDK language">
          <SegmentedControlItem value="ts" label="TypeScript" />
          <SegmentedControlItem value="python" label="Python" />
        </SegmentedControl>
      }
    >
      <Card>
        <div className="sbx-steps">
          <Step n={1} title="Install the SDK">
            <p>Run the following command in your terminal to install the Qafas Sandbox SDK:</p>
            <CodeBlock code={installCode} language="bash" />
          </Step>

          <Step n={2} title="Create an API key">
            <p>
              Sandboxes are acquired with a scoped API key, never this console&rsquo;s admin token. A key can be limited to
              a scope, a tier, concurrency, TTL and egress. Set it as SBX_API_KEY wherever the SDK or the pi extension
              runs.
            </p>
            <div>
              <Button label="Create API key" onClick={() => navigate("/keys?create=1")} />
            </div>
          </Step>

          <Step n={3} title="Sign in to this console">
            <p>
              The dashboard authenticates with the admin token — the value of SBX_ADMIN_TOKEN on the control plane host
              ({url}), which is <code>admin</code> under <code>make dev-local</code>. It is stored in this browser only and
              never sent anywhere but the control plane.
            </p>
            <TokenField />
          </Step>

          <Step n={4} title="Create a sandbox">
            <p>Acquire a sandbox, run a command, destroy it — the whole cycle is seconds, not minutes.</p>
            <CodeBlock code={createCode} language={isTs ? "typescript" : "python"} />
          </Step>

          <Step n={5} title="Run the pi extension">
            <p>The reference harness. It routes every tool call through the sandbox instead of the host.</p>
            <CodeBlock code={`pi --sandbox-url ${url} -e ./pi-extension`} language="bash" />
          </Step>
        </div>
      </Card>
    </Page>
  );
}
