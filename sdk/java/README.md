# qafas-sandbox (Java)

Synchronous Java 17 client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox). HTTP and WebSocket come from `java.net.http`; the only runtime dependencies are Gson (JSON) and Apache commons-compress (tar).

## Install

From Maven Central (it pulls in Gson and commons-compress):

```xml
<dependency>
  <groupId>io.github.exitcodenihil</groupId>
  <artifactId>qafas-sandbox</artifactId>
  <version>0.4.0</version> <!-- x-release-please-version -->
</dependency>
```

```groovy
implementation 'io.github.exitcodenihil:qafas-sandbox:0.4.0' // x-release-please-version
```

The package is `io.github.exitcodenihil.qafas`.

Offline (an air-gapped site):

1. Download `qafas-sandbox-<version>.jar` and `.pom` from the [GitHub release](https://github.com/exitCodeNihil/qafas-sandbox/releases).
2. Install them into your local Maven repository: `mvn install:install-file -Dfile=qafas-sandbox-<version>.jar -DpomFile=qafas-sandbox-<version>.pom`.
3. Put `mavenLocal()` first in Gradle's `repositories`; Gson and commons-compress then come from your Maven mirror.

From a source checkout, `cd sdk/java && mvn -B verify` builds `target/qafas-sandbox-<version>.jar`.

## Quick start

```java
import io.github.exitcodenihil.qafas.*;
import java.nio.file.Path;

// No cwd: the sandbox gets its own /home/agent and nothing is uploaded implicitly.
try (Sandbox sb = Sandbox.create("http://127.0.0.1:7800", null, "my-session",
        AcquireOptions.builder().runtime("docker").build())) {
    sb.upload(Path.of("./fixtures"), sb.workspacePath() + "/fixtures");
    ExecResult result = sb.execBuffered("pytest -q");
    System.out.println(result.stdout() + result.exit());
    sb.download(sb.workspacePath() + "/fixtures/report.json", Path.of("./report.json"));
}   // close() destroys the sandbox
```

- `runtime` is `"process" | "docker" | "firecracker"` (the wire's `native | vm | remote`, which `isolation` also takes). Omit it and the control plane picks, Firecracker first. An unknown value throws `IllegalArgumentException` naming the accepted ones.
- Pass a `cwd` as the second argument to start from a local directory: it is mounted at the same path (`native`, `vm`) or tarred and uploaded (`remote`, unless `uploadWorkspace(false)`).
- `Sandbox.create(...)` and `Qafas.acquire(...)` are the same call.

## Connecting

Point the client at the control plane (`:7800`), which places the sandbox and hands back the worker to use, or directly at one worker (`:7700`).

| variable | |
|---|---|
| `SANDBOX_URL` | the default URL |
| `SBX_API_KEY` | an API key from the dashboard, for the control plane (preferred) |
| `SBX_ADMIN_TOKEN` | the control plane's admin token, when there is no key |
| `SBX_TOKEN` | a worker's own token, when talking to a worker directly |
| `SBX_CA_FILE` | a CA (PEM) for an `https://` control plane or worker on an internal CA: it is trusted for HTTPS and WSS in addition to the JVM's own roots |

## Common operations

| task | call |
|---|---|
| run a command, wait for the result | `sb.execBuffered(cmd)` |
| stream output as it arrives | `sb.exec(cmd, new ExecOptions().onOutput(...))` |
| files | `readFile`, `writeFile`, `listdir`, `stat`, `mkdir`, `upload`, `download` |
| shell sessions | `sb.createSession()`, then `exec`, `logs`, `input`, `delete` on the session |
| lifecycle and sleep/wake | `stop`, `start`, `pause`, `resume`, `archive`, `info`, `destroy` |
| live events | `sb.events()` |
| preview URL | `sb.preview(port)` |
| browser (CDP) | `sb.cdpUrl()` |
| snapshots | `Qafas.snapshots(url, token)`, with the `Image` Dockerfile builder |

```java
// Live events: the stream holds a WebSocket open, so close it.
try (EventStream events = sb.events()) {
    Event e = events.poll(Duration.ofSeconds(5));   // or: for (Event ev : events) { ... }
}
```

## Errors

- A non-2xx reply throws the unchecked `SandboxException` (`status()`, `body()`; message `HTTP <status>: <server error text, else the body>`).
- Every method that touches the network or the local disk declares `throws IOException`; a missing remote path on `readFile`/`stat`/`listdir` throws `java.nio.file.NoSuchFileException`.
- Bad arguments (runtime name, a remote path outside the workspace without `allowOutside`) are `IllegalArgumentException`.
- `Sandbox.close()` never throws a checked exception.

## Tests and examples

```bash
mvn -B verify    # unit tests always; live tests skip unless GET $SANDBOX_URL/healthz answers and SBX_TOKEN is set
SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev mvn -B verify   # also runs the live tests (URL defaults to :7700)
```

The examples are compiled with the tests (`src/test/java/io/github/exitcodenihil/qafas/examples`); run one with:

```bash
SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev mvn -q test-compile org.codehaus.mojo:exec-maven-plugin:3.5.0:java \
  -Dexec.mainClass=io.github.exitcodenihil.qafas.examples.RunCommand -Dexec.classpathScope=test   # or ...examples.AgentLoop
```

## Links

- [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox#readme): what it is and how to run it.
- [Wire protocol](https://github.com/exitCodeNihil/qafas-sandbox/blob/main/docs/protocol.md) (`docs/protocol.md`): the types are records mirroring it.
