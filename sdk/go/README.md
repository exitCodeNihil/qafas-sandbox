# qafas-sandbox (Go)

Go client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox). Standard library plus [`github.com/coder/websocket`](https://github.com/coder/websocket) for streaming exec and live events. Every network call takes a `context.Context`.

## Install

Requires Go 1.22. The module is installed from this repository, by tag; it is not on any other registry. It is versioned with the server, so use the SDK version that matches your server:

```bash
go get github.com/exitCodeNihil/qafas-sandbox/sdk/go@v0.4.0  # x-release-please-version
```

Each release pushes a `sdk/go/vX.Y.Z` tag, which is how Go resolves a module that lives in a subdirectory.

Import as `qafas "github.com/exitCodeNihil/qafas-sandbox/sdk/go"` (package name `qafas`).

## Quick start

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

## Connecting

Point the client at the control plane (`:7800`), which places the sandbox and hands back the worker to use, or directly at one worker (`:7700`).

| variable | |
|---|---|
| `SANDBOX_URL` | the default URL |
| `SBX_API_KEY` | an API key from the dashboard, for the control plane (preferred) |
| `SBX_ADMIN_TOKEN` | the control plane's admin token, when there is no key |
| `SBX_TOKEN` | a worker's own token, when talking to a worker directly |
| `SBX_CA_FILE` | a CA (PEM, trusted in addition to the system roots) for an `https://` control plane or worker on an internal CA |

## Common operations

| task | call |
|---|---|
| run a command, wait for the result | `sb.ExecBuffered(ctx, cmd, nil)` |
| stream output as it arrives | `sb.Exec(ctx, cmd, &qafas.ExecOptions{OnOutput: ...})` |
| files | `ReadFile`, `WriteFile`, `WriteString`, `ListDir`, `Stat`, `Mkdir`, `Upload`, `Download` |
| shell sessions | `sb.CreateSession(ctx, ...)`, then `Exec`, `Logs`, `Input`, `Delete` on the session |
| lifecycle and sleep/wake | `Stop`, `Pause`, `Resume`, `Archive`, `Start`, `Info`, `Destroy` |
| live events | `sb.Events(ctx, func(qafas.Event) error { ... })` |
| preview URL | `sb.Preview(ctx, port, nil)` |
| browser (CDP) | `sb.CDPURL()` |
| snapshots | `qafas.NewSnapshots(url, token)`, with the `qafas.NewImage` Dockerfile builder |

`sb.Events` calls back for each event of this sandbox and returns when `ctx` ends, the callback returns an error, or the server closes the stream.

## Errors

- `ReadFile`, `Stat` and `ListDir` return an error matching `errors.Is(err, qafas.ErrNotFound)` for a missing path.
- Any non-2xx answer is a `*qafas.Error{Status, Body}` (`errors.As`).

## Tests and examples

```bash
cd sdk/go
go test ./...    # unit tests always run; live tests run when SBX_TOKEN is set and SANDBOX_URL (default :7700) answers /healthz
SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev go test -v ./...
go run ./examples/run_command
go run ./examples/agent_loop
```

## Links

- [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox#readme): what it is and how to run it.
- [Wire protocol](https://github.com/exitCodeNihil/qafas-sandbox/blob/main/docs/protocol.md) (`docs/protocol.md`): the types mirror it.
