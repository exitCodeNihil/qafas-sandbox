# qafas-sandbox (Go)

Go client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox): the control plane (`:7800`), which places the sandbox and hands back the worker to use, or one worker (`:7700`) directly. Standard library plus [`github.com/coder/websocket`](https://github.com/coder/websocket) for streaming exec and live events. Every network call takes a `context.Context`.

## Install

From this repository, by tag (it is not on any other registry; the module is versioned with the server, so use the SDK version that matches your server):

```bash
go get github.com/exitCodeNihil/qafas-sandbox/sdk/go@v0.2.0  # x-release-please-version
```

Each release pushes a `sdk/go/vX.Y.Z` tag, which is how Go resolves a module that lives in a subdirectory. Import as `qafas "github.com/exitCodeNihil/qafas-sandbox/sdk/go"` (package name `qafas`). Requires Go 1.22.

## 30 seconds

```go
ctx := context.Background()

// No cwd: the sandbox gets its own /home/agent and nothing is uploaded implicitly.
sb, err := qafas.Create(ctx, "http://127.0.0.1:7800", "", "my-session", &qafas.AcquireOptions{Runtime: "docker"})
if err != nil {
	log.Fatal(err)
}
defer sb.Destroy(ctx)

sb.Upload(ctx, "./fixtures", sb.WorkspacePath+"/fixtures", false)
res, _ := sb.ExecBuffered(ctx, "pytest -q", nil)
fmt.Println(res.Stdout, res.Exit)
sb.Download(ctx, sb.WorkspacePath+"/fixtures/report.json", "./report.json", false)

// Stream output as it arrives:
sb.Exec(ctx, "make test", &qafas.ExecOptions{OnOutput: func(chunk []byte, stream string) { os.Stdout.Write(chunk) }})
```

- `Runtime` is `"process" | "docker" | "firecracker"` (the wire's `native | vm | remote`, which `Isolation` also takes). Omit it and the control plane picks, Firecracker first.
- Pass a `cwd` (third argument) to start from a local directory: it is mounted at the same path (`native`, `vm`) or tarred and uploaded (`remote`, unless `SkipWorkspaceUpload`). `""` means none.
- Optional numbers where `0` is meaningful (`TTLSecs`, `AutoStopSecs`, ...) are `*int`: `nil` is not sent.
- `ReadFile`, `Stat` and `ListDir` return an error matching `errors.Is(err, qafas.ErrNotFound)` for a missing path; any non-2xx answer is a `*qafas.Error{Status, Body}` (`errors.As`).
- Live events: `sb.Events(ctx, func(qafas.Event) error { ... })` calls back for each event of this sandbox and returns when `ctx` ends, the callback returns an error, or the server closes the stream.
- The handle also covers lifecycle and sleep/wake (`Stop`, `Pause`, `Resume`, `Archive`, `Start`), sessions (`CreateSession`), snapshots (`qafas.NewSnapshots`, with the `qafas.NewImage` Dockerfile builder) and preview URLs. The types mirror the wire contract, `docs/protocol.md`.

Configuration: `SBX_API_KEY` (an API key from the dashboard, preferred) or `SBX_ADMIN_TOKEN` against the control plane, `SBX_TOKEN` against a worker, `SANDBOX_URL` as the default URL, and `SBX_CA_FILE` (PEM, trusted in addition to the system roots) for an `https://` control plane or worker on an internal CA.

## Tests and examples

```bash
cd sdk/go
go test ./...    # unit tests always run; live tests run when SBX_TOKEN is set and SANDBOX_URL (default :7700) answers /healthz
SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev go test -v ./...
go run ./examples/run_command
go run ./examples/agent_loop
```
