package io.github.exitcodenihil.qafas;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Live tests against a real worker. Skipped unless {@code GET $SANDBOX_URL/healthz} answers (default
 * http://127.0.0.1:7700; token from {@code SBX_TOKEN}). Never passes a local cwd (the worker may be a remote VM)
 * and destroys everything it creates.
 */
class LiveTest {
    private static String url;
    private static Sandbox sb;

    @BeforeAll
    static void connect() throws Exception {
        url = Qafas.envOr("SANDBOX_URL", "http://127.0.0.1:7700");
        boolean up;
        try {
            HttpResponse<Void> r = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(url + "/healthz")).timeout(Duration.ofSeconds(2)).build(),
                    HttpResponse.BodyHandlers.discarding());
            up = r.statusCode() == 200;
        } catch (IOException | IllegalArgumentException e) {
            up = false;
        }
        Assumptions.assumeTrue(up, "no worker reachable at " + url);
        // A process cannot set its own environment, so unlike the Python tests there is no "dev" default.
        Assumptions.assumeTrue(!Qafas.envOr("SBX_TOKEN", "").isEmpty(), "SBX_TOKEN is not set");
        sb = Sandbox.create(url, null, "sdk-java-live-test");
    }

    @AfterAll
    static void cleanup() throws IOException {
        if (sb != null) sb.destroy();
    }

    @Test
    void acquiredHandle() {
        assertTrue(sb.id().startsWith("sbx_"), sb.id());
        assertTrue(sb.endpoint().endsWith("/sandboxes/" + sb.id() + "/agent"));
        assertNotNull(sb.backend());
        assertNotNull(sb.isolation());
        assertEquals(Qafas.isolationToRuntime(sb.isolation()), sb.runtime());
        assertFalse(sb.workspacePath().isEmpty());
        assertNotNull(sb.createInfo());
    }

    @Test
    void execBufferedAndStreaming() throws IOException {
        ExecResult r = sb.execBuffered("echo hello; echo oops >&2; exit 3");
        assertEquals(3, r.exit());
        assertEquals("hello\n", r.stdout());
        assertEquals("oops\n", r.stderr());

        List<String> seen = Collections.synchronizedList(new ArrayList<>());
        ExecResult s = sb.exec("echo one; echo two >&2; sleep 0.2; echo three",
                new ExecOptions().onOutput((chunk, stream) -> seen.add(stream + ":" + new String(chunk, StandardCharsets.UTF_8).strip())));
        assertEquals(0, s.exit());
        assertEquals("one\nthree\n", s.stdout());
        assertEquals("two\n", s.stderr());
        assertTrue(seen.contains("stdout:one"), seen.toString());
        assertTrue(seen.contains("stderr:two"), seen.toString());
        assertFalse(s.timedOut());

        ExecResult t = sb.exec("sleep 30", new ExecOptions().timeout(Duration.ofMillis(500)));
        assertTrue(t.timedOut(), t.toString());

        ExecResult env = sb.exec("echo $FOO; pwd", new ExecOptions().env(Map.of("FOO", "bar")).cwd("/tmp").toolCallId("tc-1"));
        assertEquals("bar\n/tmp\n", env.stdout());
    }

    @Test
    void filesystem() throws IOException {
        String dir = sb.workspacePath() + "/java-fs-test";
        sb.mkdir(dir);
        sb.writeFile(dir + "/a b.txt", "héllo");
        sb.uploadBytes(dir + "/bin.dat", new byte[] {0, 1, 2, (byte) 255});
        assertEquals("héllo", new String(sb.readFile(dir + "/a b.txt"), StandardCharsets.UTF_8));
        assertEquals(List.of(0, 1, 2, 255), toInts(sb.readFile(dir + "/bin.dat")));
        FsStat st = sb.stat(dir);
        assertTrue(st.isDir());
        assertFalse(sb.stat(dir + "/bin.dat").isDir());
        assertEquals(4, sb.stat(dir + "/bin.dat").size());
        assertTrue(sb.listdir(dir).containsAll(List.of("a b.txt", "bin.dat")));
        assertThrows(NoSuchFileException.class, () -> sb.readFile(dir + "/nope"));
        assertThrows(NoSuchFileException.class, () -> sb.stat(dir + "/nope"));
        assertThrows(NoSuchFileException.class, () -> sb.listdir(dir + "/nope"));
        sb.execBuffered("rm -rf '" + dir + "'");
    }

    private static List<Integer> toInts(byte[] b) {
        List<Integer> l = new ArrayList<>();
        for (byte x : b) l.add(x & 0xff);
        return l;
    }

    @Test
    void uploadDownloadAndTar(@TempDir Path local, @TempDir Path back) throws IOException {
        Files.writeString(local.resolve("hello.txt"), "hello sandbox");
        Files.createDirectories(local.resolve("sub"));
        Files.writeString(local.resolve("sub/nested.txt"), "nested");
        Files.writeString(local.resolve(".env"), "SECRET=1"); // never uploaded
        String ws = sb.workspacePath();

        String remoteFile = ws + "/java-updown.txt";
        sb.upload(local.resolve("hello.txt"), remoteFile);
        assertEquals("hello sandbox", new String(sb.readFile(remoteFile), StandardCharsets.UTF_8));

        String remoteDir = ws + "/java-updir";
        sb.mkdir(remoteDir);
        sb.upload(local, remoteDir);
        List<String> names = sb.listdir(remoteDir);
        assertTrue(names.contains("hello.txt") && names.contains("sub"), names.toString());
        assertFalse(names.contains(".env"), names.toString());

        sb.download(remoteFile, back.resolve("x/hello.txt"));
        assertEquals("hello sandbox", Files.readString(back.resolve("x/hello.txt")));
        sb.download(remoteDir, back.resolve("updir"));
        assertEquals("hello sandbox", Files.readString(back.resolve("updir/hello.txt")));
        assertEquals("nested", Files.readString(back.resolve("updir/sub/nested.txt")));

        byte[] tar = sb.downloadTar(remoteDir);
        Pack.unpackTar(tar, back.resolve("tar"));
        assertEquals("nested", Files.readString(back.resolve("tar/sub/nested.txt")));

        assertThrows(IllegalArgumentException.class, () -> sb.upload(local.resolve("hello.txt"), "/etc/passwd"));
        sb.execBuffered("rm -rf '" + remoteFile + "' '" + remoteDir + "'");
    }

    @Test
    void processesInfoPreviewCdp() throws IOException {
        for (JsonObject p : sb.processes()) assertTrue(p.has("pid"));
        SandboxInfo info = sb.info();
        assertEquals(sb.id(), info.id());
        assertNotNull(info.state());
        assertTrue(sb.cdpUrl().startsWith("ws") && sb.cdpUrl().endsWith("/agent/browser/cdp"));
        PreviewInfo p = sb.preview(8080, 60);
        assertEquals(8080, p.port());
        assertFalse(p.url().isEmpty());
    }

    @Test
    void lifecycle() throws IOException {
        // Its own sandbox: stop() makes the next request start it again, which must not disturb the shared one.
        try (Sandbox own = Sandbox.create(url, null, "sdk-java-live-lifecycle")) {
            if ("remote".equals(own.isolation())) return; // pause/resume/archive work there; covered by the fake server
            // stop/start exist on every tier since v4; pause/resume/archive are remote-only: a typed 409 elsewhere.
            own.stop();
            assertEquals("stopped", own.info().state());
            assertEquals("back\n", own.execBuffered("echo back").stdout()); // transparent start
            SandboxException e = assertThrows(SandboxException.class, own::pause);
            assertEquals(409, e.status());
            assertThrows(SandboxException.class, own::archive);
            assertEquals("ready", own.start().state());
        }
    }

    @Test
    void sessions() throws IOException {
        Session s = sb.createSession();
        try {
            SessionCommand sync = s.exec("export K=v; echo sync-$K");
            assertEquals("done", sync.state());
            assertEquals(0, sync.exit());
            assertTrue(sync.stdout().contains("sync-v"), sync.toString());
            assertTrue(s.exec("echo again-$K").stdout().contains("again-v"), "session state persists");

            SessionCommand started = s.exec("echo a; sleep 1; echo b", true, null);
            assertFalse(started.commandId().isEmpty());
            assertEquals("running", started.state());
            List<String> chunks = Collections.synchronizedList(new ArrayList<>());
            SessionCommand done = s.logs(started.commandId(), (chunk, stream) -> chunks.add(new String(chunk, StandardCharsets.UTF_8)));
            assertEquals("done", done.state());
            assertEquals(0, done.exit());
            assertTrue(done.stdout().contains("a") && done.stdout().contains("b"), done.toString());
            assertTrue(String.join("", chunks).contains("b"), chunks.toString());
            assertEquals(done.commandId(), s.command(started.commandId()).commandId());
        } finally {
            s.delete();
            s.delete(); // 404 is success
        }
    }

    @Test
    void eventsForThisSandbox() throws IOException {
        try (EventStream events = sb.events()) {
            sb.execBuffered("echo event-probe", new ExecOptions().toolCallId("tc-events"));
            Event e = events.poll(Duration.ofSeconds(15));
            assertNotNull(e, "no event frame for this sandbox within 15s");
            assertEquals(sb.id(), e.sandboxId());
            assertNotNull(e.type());
        }
    }

    @Test
    void snapshotsListAndGet() throws Exception {
        Snapshots snaps = Qafas.snapshots(url, null);
        assertFalse(snaps.list().isEmpty());
        SnapshotInfo base = snaps.get("base");
        assertEquals("base", base.name());
        assertNotNull(base.state());
        assertNotNull(snaps.waitReady("base", Duration.ofSeconds(30)));
    }

    @Test
    void destroyTwiceIsANoOp() throws IOException {
        Sandbox other = Sandbox.create(url, null, "sdk-java-live-destroy",
                AcquireOptions.builder().runtime("docker").name("java-destroy-test").build());
        try {
            assertEquals("docker", other.runtime());
            assertEquals("hi\n", other.execBuffered("echo hi").stdout());
        } finally {
            other.destroy();
            other.destroy();
        }
    }
}
