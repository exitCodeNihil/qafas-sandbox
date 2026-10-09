# qafas-sandbox (Rust)

Async Rust client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox): the control plane (`:7800`), which places the sandbox and hands back the worker to use, or one worker (`:7700`) directly. tokio, hyper and rustls (no OpenSSL, no reqwest); streaming exec, session logs and live events are built in. The wire types are the daemon's own `proto` crate, re-exported.

## Install

From the repository (it is not published to crates.io):

```toml
[dependencies]
qafas-sandbox = { git = "https://github.com/exitCodeNihil/qafas-sandbox", tag = "v0.1.0" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Or from a source checkout: `qafas-sandbox = { path = "path/to/sdk/rust" }`. Import as `qafas_sandbox`. Needs Rust 1.89.

## 30 seconds

```rust
use qafas_sandbox::{AcquireOptions, ExecOptions, Sandbox};

#[tokio::main]
async fn main() -> qafas_sandbox::Result<()> {
    // No cwd: the sandbox gets its own /home/agent and nothing is uploaded implicitly.
    let sb = Sandbox::create(
        Some("http://127.0.0.1:7800"),
        None,
        Some("my-session"),
        AcquireOptions::new().runtime("docker"),
    )
    .await?;
    let outcome = async {
        sb.upload("./fixtures", &format!("{}/fixtures", sb.workspace_path), false).await?;
        let result = sb.exec_buffered("pytest -q", &ExecOptions::default()).await?;
        println!("{} {}", result.stdout, result.exit);
        sb.download(&format!("{}/fixtures/report.json", sb.workspace_path), "./report.json", false).await
    }
    .await;
    sb.destroy().await?; // there is no destroy-on-drop: call it, also on the error path
    outcome
}
```

- `runtime` is `"process" | "docker" | "firecracker"` (the wire's `native | vm | remote`, which `.isolation()` also takes). Omit it and the control plane picks, Firecracker first.
- Pass a `cwd` as the second argument to start from a local directory: it is mounted at the same path (`native`, `vm`) or tarred and uploaded (`remote`, unless `.upload_workspace(false)`).
- `exec` and `exec_with(cmd, opts, |chunk, stream| ...)` stream over WebSocket; `exec_buffered` is one request. `events()` returns a `Stream` of `Result<Event>` for the sandbox; dropping it closes the connection.
- The handle also covers lifecycle and sleep/wake, sessions (`create_session`, `exec`, `exec_async`, `logs`), snapshots (`snapshots(url, token)`, the `Image` Dockerfile builder) and preview URLs. Errors are one `Error` enum: `Http { status, body }` (displayed as `HTTP <status>: <server text>`), `NotFound` for a missing file, and a few more. The types mirror the wire contract, `docs/protocol.md`.

Configuration: `SBX_API_KEY` (an API key from the dashboard, preferred) or `SBX_ADMIN_TOKEN` against the control plane, `SBX_TOKEN` against a worker, `SANDBOX_URL` as the default URL, and `SBX_CA_FILE` (PEM) for an `https://` control plane or worker on an internal CA: it is trusted for https and wss on top of the system roots.

## Tests and examples

```bash
cargo test -p qafas-sandbox              # unit tests always run; tests/live.rs needs a worker (below) and skips without one
SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev cargo test -p qafas-sandbox --test live -- --nocapture
cargo run -p qafas-sandbox --example run_command
cargo run -p qafas-sandbox --example agent_loop   # SBX_CWD= (empty) sends no workspace; the default is the current directory
```
