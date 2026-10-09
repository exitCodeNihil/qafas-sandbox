package io.github.exitcodenihil.qafas;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Everything that needs no daemon: a fake HTTP server stands in for qafas and the control plane. */
class ClientTest {
    private static final String CREATE_CP = """
            {"id":"sbx_1","endpoint":"%s/sandboxes/sbx_1/agent","token":"scoped","backend":"podman",
             "workspace_path":"/w","expires_at":"later","isolation":"vm"}""";

    private static Sandbox sandbox(FakeServer srv) {
        return new Sandbox(srv.url + "/sandboxes/sbx_1/agent", "tok", "sess", "sbx_1", "b", "/w");
    }

    // ---- runtime mapping, errors, guard, image

    @Test
    void runtimeMapping() {
        assertEquals("native", Qafas.runtimeToIsolation("process"));
        assertEquals("vm", Qafas.runtimeToIsolation("docker"));
        assertEquals("remote", Qafas.runtimeToIsolation("firecracker"));
        assertNull(Qafas.runtimeToIsolation("auto"));
        assertNull(Qafas.runtimeToIsolation(null));
        assertEquals("process", Qafas.isolationToRuntime("native"));
        assertEquals("docker", Qafas.isolationToRuntime("vm"));
        assertEquals("firecracker", Qafas.isolationToRuntime("remote"));
        assertNull(Qafas.isolationToRuntime(null));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Qafas.runtimeToIsolation("kubernetes"));
        assertEquals("invalid runtime \"kubernetes\": expected one of auto|process|docker|firecracker", e.getMessage());
    }

    @Test
    void errorMessageExtraction() {
        SandboxException e = new SandboxException(409, "{\"error\":\"lifecycle needs the remote tier\"}");
        assertEquals("HTTP 409: lifecycle needs the remote tier", e.getMessage());
        assertEquals(409, e.status());
        assertEquals("{\"error\":\"lifecycle needs the remote tier\"}", e.body());
        assertEquals("HTTP 404: not found", new SandboxException(404, "not found").getMessage());
        assertEquals("HTTP 500: {\"error\":5}", new SandboxException(500, "{\"error\":5}").getMessage());
        assertEquals("HTTP 500: {\"error\":\"\"}", new SandboxException(500, "{\"error\":\"\"}").getMessage());
        assertEquals("HTTP 502: ", new SandboxException(502, new byte[0]).getMessage());
    }

    @Test
    void workspaceGuard() {
        Sandbox sb = new Sandbox("http://127.0.0.1:1/sandboxes/sbx_x/agent", "t", "s", "sbx_x", "b", "/workspace/repo");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> sb.upload(Path.of("/does/not/matter"), "/etc/passwd"));
        assertEquals("/etc/passwd is outside the workspace (/workspace/repo); pass allowOutside=true to override", e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> sb.download("/etc/passwd", Path.of("/does/not/matter")));
        assertThrows(IllegalArgumentException.class, () -> sb.upload(Path.of("x"), "/workspace/repo/../other"));
        assertThrows(IllegalArgumentException.class, () -> sb.upload(Path.of("x"), "/workspace/repo2/f"));
        // inside, or allowOutside, passes the guard and only then hits the network (nothing listens on port 1)
        assertThrows(IOException.class, () -> sb.upload(Path.of("/does/not/matter"), "/workspace/repo/sub/file.txt"));
        assertThrows(IOException.class, () -> sb.upload(Path.of("/does/not/matter"), "/etc/passwd", true));
        Sandbox.assertInsideWorkspace("/workspace/repo", "/workspace/repo", false);
        Sandbox.assertInsideWorkspace("/workspace/repo/a/../b", "/workspace/repo/", false);
        Sandbox.assertInsideWorkspace("/anything", "", false);
    }

    @Test
    void imageMatchesPythonByteForByte() throws IOException {
        Image image = Image.base("node:22-bookworm").run("npm i -g pnpm")
                .pipInstall(List.of("requests", "it's")).pipInstall(List.of())
                .npmInstall(List.of("typescript", "@types/node")).workdir("/w")
                .env(new LinkedHashMap<>(Map.of("K", "v"))).env(Map.of("A", "b c"))
                .copyText("/etc/m o'tď", "héllo 'wörld'\n");
        String fixture = new String(getClass().getResourceAsStream("/image.dockerfile").readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(fixture, image.toDockerfile());
        assertEquals(fixture, image.toString());
    }

    // ---- acquire

    @Test
    void acquireRuntimeWinsOverIsolationAndMapsReply() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{\"ok\":true}").on("POST /api/sandboxes", 201, CREATE_CP.formatted(srv.url));
            Sandbox sb = Sandbox.create(srv.url, "/tmp", "sess",
                    AcquireOptions.builder().runtime("docker").isolation("native").token("adm").build());
            JsonObject body = srv.requests.get(1).json();
            assertEquals("vm", body.get("isolation").getAsString());
            assertEquals("Bearer adm", srv.requests.get(1).headers().getFirst("Authorization"));
            assertEquals("base", body.get("template").getAsString());
            assertEquals("trusted", body.get("trust").getAsString());
            assertEquals("sess", body.get("pi_session").getAsString());
            assertEquals("/tmp", body.getAsJsonObject("workspace").get("host_path").getAsString());
            assertEquals("sbx_1", sb.id());
            assertEquals("podman", sb.backend());
            assertEquals("vm", sb.isolation());
            assertEquals("docker", sb.runtime());
            assertEquals("/w", sb.workspacePath());
            assertEquals("scoped", sb.token());
            assertEquals(srv.url + "/sandboxes/sbx_1/agent", sb.endpoint());
            assertTrue(sb.tools().isEmpty());
            assertTrue(sb.missingTools().isEmpty());
        }
    }

    @Test
    void acquireWithoutRuntimeOrIsolationOmitsIsolation() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{\"ok\":true}")
                    .on("POST /api/sandboxes", 201, CREATE_CP.formatted(srv.url).replace("\"vm\"", "\"native\""));
            Sandbox sb = Sandbox.create(srv.url, "/tmp", "sess", AcquireOptions.builder().runtime("auto").build());
            assertFalse(srv.requests.get(1).json().has("isolation"));
            assertEquals("process", sb.runtime());
        }
    }

    @Test
    void acquireBadRuntimeNeverReachesTheWire() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{\"ok\":true}");
            assertThrows(IllegalArgumentException.class,
                    () -> Qafas.acquire(srv.url, null, "s", AcquireOptions.builder().runtime("kubernetes").build()));
            assertFalse(srv.seen.contains("POST /api/sandboxes"));
        }
    }

    @Test
    void acquireWorkerUsesSandboxesPathAndSerialisesEveryField() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{\"ok\":true,\"backend\":\"podman\",\"host_id\":\"h\"}")
                    .on("POST /sandboxes", 201, """
                            {"id":"sbx_1","endpoint":"%s/sandboxes/sbx_1/agent","token":"scoped","backend":"podman",
                             "workspace_path":"/w","isolation":"vm","tools":{"node":"22.1.0"},"missing_tools":["git"],
                             "size":"mini","limits":{"cpus":1,"mem_mib":1024,"disk_mib":1024,"pids":256},
                             "info":{"id":"sbx_1","name":"sbx_1","state":"ready"}}""".formatted(srv.url));
            Sandbox sb = Qafas.acquire(srv.url, null, "sess", AcquireOptions.builder()
                    .token("wtok").name("my-box").labels(Map.of("team", "sdk")).env(Map.of("FOO", "bar"))
                    .autoStopSecs(60).autoArchiveSecs(120).autoDeleteSecs(0).maxAgeSecs(3600).ttlSecs(30)
                    .snapshot("node-base").template("ignored").trust("untrusted").tools(List.of("node@22"))
                    .egressAllow(List.of("*.example.com")).size("mini").build());
            JsonObject b = srv.requests.get(1).json();
            assertEquals("node-base", b.get("template").getAsString()); // snapshot aliases template
            assertEquals("untrusted", b.get("trust").getAsString());
            assertEquals("my-box", b.get("name").getAsString());
            assertEquals("sdk", b.getAsJsonObject("labels").get("team").getAsString());
            assertEquals("bar", b.getAsJsonObject("env").get("FOO").getAsString());
            assertEquals(60, b.get("auto_stop_secs").getAsInt());
            assertEquals(120, b.get("auto_archive_secs").getAsInt());
            assertEquals(0, b.get("auto_delete_secs").getAsInt());
            assertEquals(3600, b.get("max_age_secs").getAsInt());
            assertEquals(30, b.get("ttl_secs").getAsInt());
            assertEquals("node@22", b.getAsJsonArray("tools").get(0).getAsString());
            assertEquals("*.example.com", b.getAsJsonArray("egress_allow").get(0).getAsString());
            assertEquals("mini", b.get("size").getAsString());
            assertFalse(b.has("limits"));
            assertFalse(b.has("workspace")); // no cwd: nothing sent, nothing uploaded
            assertEquals("mini", sb.size());
            assertEquals(new SandboxLimits(1, 1024, 1024, 256), sb.limits());
            assertEquals("22.1.0", sb.tools().get("node"));
            assertEquals(List.of("git"), sb.missingTools());
            assertEquals("sbx_1", sb.createInfo().get("id").getAsString());
        }
    }

    @Test
    void acquireCustomLimitsAndNeitherSizeNorLimits() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{}").on("POST /api/sandboxes", 201, CREATE_CP.formatted(srv.url));
            Qafas.acquire(srv.url, null, "s", AcquireOptions.builder().limits(new SandboxLimits(0.5, 512, 512, null)).build());
            JsonObject b = srv.requests.get(1).json();
            assertEquals(0.5, b.getAsJsonObject("limits").get("cpus").getAsDouble());
            assertEquals(512, b.getAsJsonObject("limits").get("mem_mib").getAsInt());
            assertEquals(512, b.getAsJsonObject("limits").get("disk_mib").getAsInt());
            assertFalse(b.has("size"));
            Qafas.acquire(srv.url, null, "s");
            JsonObject b2 = srv.requests.get(3).json();
            assertFalse(b2.has("size"));
            assertFalse(b2.has("limits"));
        }
    }

    @Test
    void acquireDefaultsPiSession() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{}").on("POST /api/sandboxes", 201, CREATE_CP.formatted(srv.url));
            Sandbox sb = Qafas.acquire(srv.url, null, null);
            assertEquals("sbx-java-" + ProcessHandle.current().pid(), sb.piSession());
        }
    }

    @Test
    void acquireDestroysSandboxWhenWorkspaceUploadFails(@TempDir Path local) throws IOException {
        Files.writeString(local.resolve("f.txt"), "x");
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{}")
                    .on("POST /api/sandboxes", 201, CREATE_CP.formatted(srv.url).replace("\"vm\"", "\"remote\""))
                    .on("PUT /sandboxes/sbx_1/agent/fs/tar?path=" + Http.quote(local.toString()), 413,
                            "{\"error\":\"body over SBX_MAX_UPLOAD_MB (512 MiB)\"}")
                    .on("DELETE /sandboxes/sbx_1", 204, "");
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> Qafas.acquire(srv.url, local.toString(), "sess"));
            assertTrue(e.getMessage().contains("workspace upload failed (HTTP 413: body over SBX_MAX_UPLOAD_MB (512 MiB))"), e.getMessage());
            assertTrue(e.getMessage().contains("pass uploadWorkspace(false) or a smaller directory (.sbxignore)"));
            assertTrue(srv.seen.contains("DELETE /sandboxes/sbx_1"), "a failed upload must destroy the sandbox: " + srv.seen);
        }
    }

    @Test
    void acquireUploadsWorkspaceOnRemoteTierUnlessDisabled(@TempDir Path local) throws IOException {
        Files.writeString(local.resolve("f.txt"), "x");
        Files.writeString(local.resolve(".env"), "SECRET");
        try (FakeServer srv = new FakeServer()) {
            String tar = "PUT /sandboxes/sbx_1/agent/fs/tar?path=" + Http.quote(local.toString());
            srv.on("GET /healthz", 200, "{}")
                    .on("POST /api/sandboxes", 201, CREATE_CP.formatted(srv.url).replace("\"vm\"", "\"remote\""))
                    .on(tar, 204, "");
            Qafas.acquire(srv.url, local.toString(), "sess");
            assertTrue(srv.seen.contains(tar));
            assertFalse(new String(srv.requests.get(2).body(), StandardCharsets.ISO_8859_1).contains("SECRET"));
            srv.seen.clear();
            Qafas.acquire(srv.url, local.toString(), "sess", AcquireOptions.builder().uploadWorkspace(false).build());
            assertFalse(srv.seen.contains(tar));
        }
    }

    // ---- sandbox handle

    @Test
    void headersAndExecBuffered() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("POST /sandboxes/sbx_1/agent/exec", req -> new FakeServer.Reply(200,
                    "{\"exit\":3,\"stdout\":\"out\",\"stderr\":\"err\",\"duration_ms\":12,\"truncated\":true}"));
            Sandbox sb = sandbox(srv);
            ExecResult r = sb.execBuffered("echo hi", new ExecOptions().env(Map.of("A", "b")).timeout(Duration.ofMillis(1500)).toolCallId("tc1"));
            assertEquals(new ExecResult(3, "out", "err", 12, true, false), r);
            FakeServer.Req req = srv.requests.get(0);
            assertEquals("Bearer tok", req.headers().getFirst("Authorization"));
            assertEquals("sess", req.headers().getFirst("x-pi-session"));
            assertEquals("tc1", req.headers().getFirst("x-tool-call-id"));
            JsonObject b = req.json();
            assertEquals("echo hi", b.get("cmd").getAsString());
            assertEquals("/w", b.get("cwd").getAsString());
            assertEquals("b", b.getAsJsonObject("env").get("A").getAsString());
            assertEquals(1500, b.get("timeout_ms").getAsInt());
            sb.execBuffered("x");
            assertEquals("", srv.requests.get(1).headers().getFirst("x-tool-call-id"));
            assertFalse(srv.requests.get(1).json().has("timeout_ms"));
        }
    }

    @Test
    void fsRoutesAndNotFound() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /sandboxes/sbx_1/agent/fs/read?path=/w/a%20b.txt", 200, "data")
                    .on("PUT /sandboxes/sbx_1/agent/fs/write?path=/w/x.txt", 204, "")
                    .on("POST /sandboxes/sbx_1/agent/fs/mkdir", 204, "")
                    .on("GET /sandboxes/sbx_1/agent/fs/stat?path=/w", 200, "{\"is_dir\":true,\"size\":4096,\"mode\":493,\"mtime\":\"t\"}")
                    .on("GET /sandboxes/sbx_1/agent/fs/list?path=/w", 200, "[\"a\",\"b\"]")
                    .on("GET /sandboxes/sbx_1/agent/fs/read?path=/w/boom", 500, "{\"error\":\"disk\"}");
            Sandbox sb = sandbox(srv);
            assertEquals("data", new String(sb.readFile("/w/a b.txt"), StandardCharsets.UTF_8));
            sb.writeFile("/w/x.txt", "hello");
            assertEquals("hello", new String(srv.requests.get(1).body(), StandardCharsets.UTF_8));
            sb.mkdir("/w/d");
            assertEquals("/w/d", srv.requests.get(2).json().get("path").getAsString());
            assertEquals(new FsStat(true, 4096, 493, "t"), sb.stat("/w"));
            assertEquals(List.of("a", "b"), sb.listdir("/w"));
            assertThrows(NoSuchFileException.class, () -> sb.readFile("/w/missing"));
            assertThrows(NoSuchFileException.class, () -> sb.stat("/w/missing"));
            assertThrows(NoSuchFileException.class, () -> sb.listdir("/w/missing"));
            SandboxException e = assertThrows(SandboxException.class, () -> sb.readFile("/w/boom"));
            assertEquals(500, e.status());
            assertEquals("HTTP 500: disk", e.getMessage());
        }
    }

    @Test
    void lifecyclePreviewSessionsAndDestroy() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            String info = "{\"id\":\"sbx_1\",\"state\":\"ready\",\"name\":\"my-box\",\"backend\":\"b\",\"template\":\"t\","
                    + "\"workspace_path\":\"/w\",\"pi_session\":\"s\",\"created_at\":\"t\",\"endpoint\":\"e\",\"future_field\":1}";
            srv.on("POST /sandboxes/sbx_1/stop", 204, "").on("POST /sandboxes/sbx_1/pause", 204, "")
                    .on("POST /sandboxes/sbx_1/resume", 204, "").on("POST /sandboxes/sbx_1/archive", 204, "")
                    .on("POST /sandboxes/sbx_1/start", 200, info).on("GET /sandboxes/sbx_1", 200, info)
                    .on("POST /sandboxes/sbx_1/preview", req -> new FakeServer.Reply(200,
                            "{\"url\":\"u\",\"token\":\"tok\",\"port\":" + req.json().get("port") + ",\"expires_at\":\"x\"}"))
                    .on("POST /sandboxes/sbx_1/agent/sessions", 201, "{\"id\":\"sess_1\"}")
                    .on("POST /sandboxes/sbx_1/agent/sessions/sess_1/exec", req -> req.json().has("async")
                            ? new FakeServer.Reply(202, "{\"command_id\":\"c2\"}")
                            : new FakeServer.Reply(200, "{\"command_id\":\"c1\",\"cmd\":\"echo hi\",\"state\":\"done\",\"exit\":0,\"stdout\":\"hi\\n\",\"stderr\":\"\",\"started_at\":\"t\",\"ended_at\":\"t\"}"))
                    .on("GET /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1", 200, "{\"command_id\":\"c1\",\"cmd\":\"echo hi\",\"state\":\"done\",\"exit\":0,\"started_at\":\"t\"}")
                    .on("POST /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1/input", 204, "")
                    .on("DELETE /sandboxes/sbx_1/agent/sessions/sess_1", 204, "")
                    .on("DELETE /sandboxes/sbx_1", 204, "");
            Sandbox sb = sandbox(srv);
            sb.stop();
            assertEquals("ready", sb.start().state());
            sb.pause();
            sb.resume();
            sb.archive();
            assertEquals("my-box", sb.info().name());
            PreviewInfo p = sb.preview(8080, 60);
            assertEquals(8080, p.port());
            assertEquals(60, srv.requests.get(srv.requests.size() - 1).json().get("ttl_secs").getAsInt());

            Session s = sb.createSession(null, "/w", null);
            assertEquals("sess_1", s.id());
            assertEquals("/w", srv.requests.get(srv.requests.size() - 1).json().get("cwd").getAsString());
            SessionCommand c = s.exec("echo hi");
            assertEquals(0, c.exit());
            assertEquals("hi\n", c.stdout());
            SessionCommand a = s.exec("sleep 1", true, 5000);
            assertEquals(new SessionCommand("c2", "", "running", "", null, null, null, null), a);
            assertEquals("c1", s.command("c1").commandId());
            s.input("c1", "aGVsbG8=");
            s.delete();

            sb.destroy();
            sb.delete(); // the fake answers 204 both times
            assertEquals("Bearer tok", srv.requests.get(srv.requests.size() - 1).headers().getFirst("Authorization"));
            assertNull(srv.requests.get(srv.requests.size() - 1).headers().getFirst("x-pi-session"), "destroy sends only Authorization");
        }
    }

    @Test
    void destroyTreats404AsSuccessAndCloseDestroys() throws IOException {
        try (FakeServer srv = new FakeServer()) { // no routes: everything is 404
            Sandbox sb = sandbox(srv);
            sb.destroy();
            sb.close();
            assertEquals(List.of("DELETE /sandboxes/sbx_1", "DELETE /sandboxes/sbx_1"), srv.seen);
        }
    }

    @Test
    void destroyTreatsARevokedScopedTokenAsAlreadyGone() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("DELETE /sandboxes/sbx_1", 401, "token revoked with its sandbox");
            sandbox(srv).destroy();
            srv.on("DELETE /sandboxes/sbx_1", 401, "bad or missing bearer token");
            assertEquals(401, assertThrows(SandboxException.class, () -> sandbox(srv).destroy()).status());
        }
    }

    @Test
    void lifecycleErrorIsTyped() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("POST /sandboxes/sbx_1/stop", 409, "{\"error\":\"lifecycle needs the remote tier\"}");
            SandboxException e = assertThrows(SandboxException.class, () -> sandbox(srv).stop());
            assertEquals(409, e.status());
            assertTrue(e.getMessage().contains("lifecycle needs the remote tier"));
        }
    }

    @Test
    void cdpUrlAndRuntime() {
        Sandbox sb = new Sandbox("https://h:7700/sandboxes/sbx_1/agent", "t", "s", "sbx_1", "b", "/w");
        assertEquals("wss://h:7700/sandboxes/sbx_1/agent/browser/cdp", sb.cdpUrl());
        assertNull(sb.runtime());
    }

    // ---- snapshots

    @Test
    void snapshotsOnControlPlane() throws Exception {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{\"ok\":true}")
                    .on("POST /api/snapshots", req -> {
                        assertEquals("{\"name\":\"img1\",\"source\":{\"image\":\"node:22-bookworm\"}}",
                                new String(req.body(), StandardCharsets.UTF_8));
                        return new FakeServer.Reply(202, "[{\"name\":\"img1\",\"state\":\"building\",\"kind\":\"image\",\"source\":{\"image\":\"node:22-bookworm\"},\"created_at\":\"t\"}]");
                    })
                    .on("GET /api/snapshots/img1", 200, "{\"name\":\"img1\",\"state\":\"active\",\"kind\":\"image\",\"source\":{\"image\":\"node:22-bookworm\"},\"created_at\":\"t\"}")
                    .on("GET /api/snapshots", 200, "[{\"name\":\"img1\",\"state\":\"active\",\"kind\":\"image\",\"source\":{},\"created_at\":\"t\"}]")
                    .on("DELETE /api/snapshots/img1", 204, "")
                    .on("PUT /api/snapshots/img3", req -> {
                        assertEquals("{\"warm\":5}", new String(req.body(), StandardCharsets.UTF_8));
                        return new FakeServer.Reply(200, "[{\"name\":\"img3\",\"state\":\"active\",\"kind\":\"image\",\"source\":{},\"created_at\":\"t\",\"warm\":5,\"memory_snapshot\":false,\"warm_ready\":5}]");
                    });
            Snapshots snaps = Qafas.snapshots(srv.url, "admintok");
            SnapshotInfo created = snaps.create("img1", new SnapshotOptions().image("node:22-bookworm"));
            assertEquals("building", created.state());
            assertTrue(created.memorySnapshot()); // default when the daemon does not say
            assertEquals(0, created.warm());
            assertEquals("active", snaps.waitReady("img1", Duration.ofSeconds(2)).state());
            assertEquals(1, snaps.list().size());
            snaps.delete("img1");
            snaps.delete("gone"); // 404 is success
            SnapshotInfo w = snaps.setWarm("img3", 5);
            assertEquals(5, w.warm());
            assertEquals(5, w.warmReady());
            assertFalse(w.memorySnapshot());
            assertEquals("Bearer admintok", srv.requests.get(1).headers().getFirst("Authorization"));
        }
    }

    @Test
    void snapshotsOnWorkerAcceptImageBuilderAndWarmFields() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{\"ok\":true,\"backend\":\"podman\",\"host_id\":\"h\"}")
                    .on("POST /snapshots", req -> new FakeServer.Reply(202,
                            "{\"name\":\"img2\",\"state\":\"building\",\"kind\":\"image\",\"source\":" + req.json().get("source") + ",\"created_at\":\"t\"}"));
            Image image = Image.base("node:22-bookworm").run("npm i -g pnpm").workdir("/w");
            SnapshotInfo s = Qafas.snapshots(srv.url, "tok")
                    .create("img2", new SnapshotOptions().dockerfile(image).warm(2).memorySnapshot(false).sandboxId("sbx_9"));
            JsonObject body = srv.requests.get(1).json();
            assertEquals(image.toDockerfile(), body.getAsJsonObject("source").get("dockerfile").getAsString());
            assertEquals("sbx_9", body.getAsJsonObject("source").get("sandbox_id").getAsString());
            assertEquals(2, body.get("warm").getAsInt());
            assertFalse(body.get("memory_snapshot").getAsBoolean());
            assertNotNull(s.source());
        }
    }

    @Test
    void snapshotNamesAreUrlEncodedAndWaitReadyTimesOut() throws IOException {
        try (FakeServer srv = new FakeServer()) {
            srv.on("GET /healthz", 200, "{}")
                    .on("GET /api/snapshots/a%20b", 200, "{\"name\":\"a b\",\"state\":\"building\",\"kind\":\"image\",\"source\":{},\"created_at\":\"t\"}");
            Snapshots snaps = Qafas.snapshots(srv.url, "t");
            assertEquals("a b", snaps.get("a b").name());
            java.util.concurrent.TimeoutException e = assertThrows(java.util.concurrent.TimeoutException.class,
                    () -> snaps.waitReady("a b", Duration.ofMillis(300)));
            assertEquals("snapshot a b still building after 0.3s", e.getMessage());
        }
    }
}
