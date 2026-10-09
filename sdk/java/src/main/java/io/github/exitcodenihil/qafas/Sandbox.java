package io.github.exitcodenihil.qafas;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A single acquired sandbox. {@code close()} destroys it, so use try-with-resources. See {@link Qafas} for
 * the error model: HTTP errors are {@link SandboxException}, I/O methods declare {@code IOException}.
 * Headers {@code x-pi-session} and {@code x-tool-call-id} (empty unless given) ride on every call except destroy.
 */
public final class Sandbox implements AutoCloseable {
    private final String endpoint;
    private final String token;
    private final String piSession;
    private final String id;
    private final String backend;
    private final String workspacePath;
    private final String isolation;
    private final Map<String, String> tools;
    private final List<String> missingTools;
    private final String size;
    private final SandboxLimits limits;
    private final JsonObject createInfo;

    public Sandbox(String endpoint, String token, String piSession, String id, String backend, String workspacePath) {
        this(endpoint, token, piSession, id, backend, workspacePath, null, null, null, null, null, null);
    }

    public Sandbox(String endpoint, String token, String piSession, String id, String backend, String workspacePath,
                   String isolation, Map<String, String> tools, List<String> missingTools, String size,
                   SandboxLimits limits, JsonObject createInfo) {
        this.endpoint = endpoint;
        this.token = token;
        this.piSession = piSession;
        this.id = id;
        this.backend = backend;
        this.workspacePath = workspacePath;
        this.isolation = isolation;
        this.tools = tools != null ? tools : Map.of();
        this.missingTools = missingTools != null ? missingTools : List.of();
        this.size = size;
        this.limits = limits;
        this.createInfo = createInfo;
    }

    /** Same as {@link Qafas#acquire(String, String, String, AcquireOptions)}. */
    public static Sandbox create(String url, String cwd, String piSession, AcquireOptions options) throws IOException {
        return Qafas.acquire(url, cwd, piSession, options);
    }

    public static Sandbox create(String url, String cwd, String piSession) throws IOException {
        return Qafas.acquire(url, cwd, piSession, null);
    }

    public String endpoint() { return endpoint; }
    public String token() { return token; }
    public String piSession() { return piSession; }
    public String id() { return id; }
    public String backend() { return backend; }
    public String workspacePath() { return workspacePath; }
    /** The tier the daemon picked: native|vm|remote. */
    public String isolation() { return isolation; }
    /** {@link #isolation()} in the runtime naming: process|docker|firecracker. */
    public String runtime() { return Qafas.isolationToRuntime(isolation); }
    public Map<String, String> tools() { return tools; }
    public List<String> missingTools() { return missingTools; }
    /** v5: a size name or "custom". */
    public String size() { return size; }
    /** v5: the ceilings actually applied. */
    public SandboxLimits limits() { return limits; }
    /** v5.1: the daemon's record right after create ({@link #info()} is the live refresh). */
    public JsonObject createInfo() { return createInfo; }
    public String cdpUrl() { return Http.toWs(endpoint) + "/browser/cdp"; }

    /** Destroys the sandbox (a 404 is success). */
    @Override
    public void close() {
        try {
            destroy();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Map<String, String> headers(String toolCallId) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Authorization", "Bearer " + token);
        h.put(Qafas.HDR_PI_SESSION, piSession);
        h.put(Qafas.HDR_TOOL_CALL_ID, toolCallId == null ? "" : toolCallId);
        return h;
    }

    Map<String, String> headers() {
        return headers("");
    }

    private String agentBase() {
        return endpoint.endsWith("/agent") ? endpoint.substring(0, endpoint.length() - "/agent".length()) : endpoint;
    }

    private String qafasRoot() {
        int i = endpoint.indexOf("/sandboxes/");
        return i != -1 ? endpoint.substring(0, i) : endpoint;
    }

    // ---------------------------------------------------------------- exec

    private Map<String, Object> execBody(String cmd, ExecOptions o) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cmd", cmd);
        body.put("cwd", o.cwd != null && !o.cwd.isEmpty() ? o.cwd : workspacePath);
        if (o.env != null && !o.env.isEmpty()) body.put("env", o.env);
        if (o.timeout != null && !o.timeout.isZero()) body.put("timeout_ms", o.timeout.toMillis());
        return body;
    }

    public ExecResult execBuffered(String cmd) throws IOException {
        return execBuffered(cmd, new ExecOptions());
    }

    /** {@code POST /exec}: waits for the command and returns everything at once ({@code onOutput} is ignored). */
    public ExecResult execBuffered(String cmd, ExecOptions o) throws IOException {
        JsonElement r = Http.json("POST", endpoint + "/exec", headers(o.toolCallId), execBody(cmd, o));
        return Http.GSON.fromJson(r, ExecResult.class);
    }

    public ExecResult exec(String cmd) throws IOException {
        return exec(cmd, new ExecOptions());
    }

    /**
     * Runs {@code cmd} over {@code /exec/ws}, calling {@code onOutput(chunk, "stdout"|"stderr")} per chunk on the
     * calling thread, and returns when the exit frame arrives. Output is decoded as UTF-8, lossily.
     */
    public ExecResult exec(String cmd, ExecOptions o) throws IOException {
        Map<String, Object> start = execBody(cmd, o);
        start.put("type", "start");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = 1;
        long durationMs = 0;
        boolean timedOut = false;
        try (Http.Ws ws = new Http.Ws(Http.toWs(endpoint) + "/exec/ws", headers(o.toolCallId))) {
            ws.send(Http.GSON.toJson(start));
            for (String raw; (raw = ws.next()) != null; ) {
                JsonObject f = Http.parse(raw.getBytes(StandardCharsets.UTF_8)).getAsJsonObject();
                String t = Qafas.str(f, "type");
                if ("stdout".equals(t) || "stderr".equals(t)) {
                    byte[] chunk = java.util.Base64.getDecoder().decode(f.get("data").getAsString());
                    ("stdout".equals(t) ? out : err).writeBytes(chunk);
                    if (o.onOutput != null) o.onOutput.accept(chunk, t);
                } else if ("exit".equals(t)) {
                    code = f.has("code") ? f.get("code").getAsInt() : 1;
                    durationMs = f.has("duration_ms") ? f.get("duration_ms").getAsLong() : 0;
                    timedOut = f.has("timed_out") && f.get("timed_out").getAsBoolean();
                    break;
                }
            }
        }
        return new ExecResult(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8),
                durationMs, false, timedOut);
    }

    // ------------------------------------------------------------------ fs

    private byte[] fsGet(String route, String path) throws IOException {
        Http.Response r = Http.send("GET", endpoint + route + "?path=" + Http.quote(path), headers(), null);
        if (r.status() == 404) throw new NoSuchFileException(path);
        if (r.status() >= 400) throw new SandboxException(r.status(), r.body());
        return r.body();
    }

    /** @throws NoSuchFileException on a 404 */
    public byte[] readFile(String path) throws IOException {
        return fsGet("/fs/read", path);
    }

    public void writeFile(String path, String content) throws IOException {
        writeFile(path, content.getBytes(StandardCharsets.UTF_8));
    }

    public void writeFile(String path, byte[] content) throws IOException {
        Http.ok("PUT", endpoint + "/fs/write?path=" + Http.quote(path), headers(), content);
    }

    /** Alias of {@link #writeFile(String, byte[])}, named for symmetry with readFile/upload/download. */
    public void uploadBytes(String path, byte[] content) throws IOException {
        writeFile(path, content);
    }

    public void mkdir(String path) throws IOException {
        Http.json("POST", endpoint + "/fs/mkdir", headers(), Map.of("path", path));
    }

    /** @throws NoSuchFileException on a 404 */
    public FsStat stat(String path) throws IOException {
        return Http.GSON.fromJson(Http.parse(fsGet("/fs/stat", path)), FsStat.class);
    }

    /** @throws NoSuchFileException on a 404 */
    public List<String> listdir(String path) throws IOException {
        return new ArrayList<>(Arrays.asList(Http.GSON.fromJson(Http.parse(fsGet("/fs/list", path)), String[].class)));
    }

    public void uploadTar(String path, byte[] tar) throws IOException {
        Http.ok("PUT", endpoint + "/fs/tar?path=" + Http.quote(path), headers(), tar);
    }

    public byte[] downloadTar(String path) throws IOException {
        return Http.ok("GET", endpoint + "/fs/tar?path=" + Http.quote(path), headers(), null);
    }

    public void upload(Path local, String remote) throws IOException {
        upload(local, remote, false);
    }

    /**
     * Uploads a local file or directory to {@code remote}. A directory is packed like a remote-tier workspace
     * ({@link Pack#packWorkspace}: {@code .sbxignore} + {@link Pack#DEFAULT_IGNORE}) and sent as a tar; a file
     * goes through {@link #writeFile}. A {@code remote} outside the workspace is refused (an
     * {@link IllegalArgumentException}) unless {@code allowOutside}: the daemon enforces the real boundary,
     * this only catches a typo before a wasted round trip.
     */
    public void upload(Path local, String remote, boolean allowOutside) throws IOException {
        assertInsideWorkspace(remote, workspacePath, allowOutside);
        if (Files.isDirectory(local)) {
            uploadTar(remote, Pack.packWorkspace(local));
        } else {
            writeFile(remote, Files.readAllBytes(local));
        }
    }

    public void download(String remote, Path local) throws IOException {
        download(remote, local, false);
    }

    /** Downloads {@code remote} (file or directory) to {@code local}; same workspace guard as {@link #upload}. */
    public void download(String remote, Path local, boolean allowOutside) throws IOException {
        assertInsideWorkspace(remote, workspacePath, allowOutside);
        if (stat(remote).isDir()) {
            Pack.unpackTar(downloadTar(remote), local);
        } else {
            Path parent = local.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            Files.write(local, readFile(remote));
        }
    }

    /** Lexical check, like {@code os.path.relpath}: is {@code path} the workspace or inside it? */
    static void assertInsideWorkspace(String path, String workspace, boolean allowOutside) {
        if (allowOutside || workspace == null || workspace.isEmpty()) return;
        List<String> p = components(path);
        List<String> w = components(workspace);
        boolean inside = path.startsWith("/") == workspace.startsWith("/")
                && p.size() >= w.size() && p.subList(0, w.size()).equals(w);
        if (!inside) {
            throw new IllegalArgumentException(
                    path + " is outside the workspace (" + workspace + "); pass allowOutside=true to override");
        }
    }

    private static List<String> components(String path) {
        List<String> out = new ArrayList<>();
        for (String c : path.split("/")) {
            if (c.isEmpty() || c.equals(".")) continue;
            if (c.equals("..") && !out.isEmpty() && !out.get(out.size() - 1).equals("..")) {
                out.remove(out.size() - 1);
            } else if (!c.equals("..") || !path.startsWith("/")) {
                out.add(c);
            }
        }
        return out;
    }

    // ------------------------------------------------------------ qafas

    /** v2: {@code GET /sandboxes/{id}/processes}, the live process tree. */
    public List<JsonObject> processes() throws IOException {
        JsonArray a = Http.json("GET", agentBase() + "/processes", headers(), null).getAsJsonArray();
        List<JsonObject> out = new ArrayList<>();
        for (JsonElement e : a) out.add(e.getAsJsonObject());
        return out;
    }

    /**
     * Live events for this sandbox from the {@code /events/ws} firehose, filtered client-side to this sandbox
     * id. The returned stream holds a WebSocket open: <b>close it</b> (try-with-resources).
     */
    public EventStream events() throws IOException {
        Http.Ws ws = new Http.Ws(Http.toWs(qafasRoot()) + "/events/ws", Map.of("Authorization", "Bearer " + token));
        return new EventStream(ws, id);
    }

    // ------------------------------------------------------------- v3: lifecycle

    /** {@code GET /sandboxes/{id}}: the current record, including state and timers. */
    public SandboxInfo info() throws IOException {
        return Http.GSON.fromJson(Http.json("GET", agentBase(), headers(), null), SandboxInfo.class);
    }

    /** Every tier since v4 (a stopped sandbox starts again on its next request); {@link #pause}/{@link #resume}/{@link #archive} are remote-only and answer 409 elsewhere. */
    public void stop() throws IOException {
        lifecycle("stop");
    }

    public SandboxInfo start() throws IOException {
        return Http.GSON.fromJson(Http.json("POST", agentBase() + "/start", headers(), null), SandboxInfo.class);
    }

    public void pause() throws IOException {
        lifecycle("pause");
    }

    public void resume() throws IOException {
        lifecycle("resume");
    }

    public void archive() throws IOException {
        lifecycle("archive");
    }

    private void lifecycle(String verb) throws IOException {
        Http.ok("POST", agentBase() + "/" + verb, headers(), null);
    }

    /**
     * DELETE the sandbox; already gone is success, so calling it twice is a no-op. "Gone" is a 404, or, on a
     * worker, the 401 {@code token revoked with its sandbox} (the first destroy revokes the scoped token, so
     * the second call is rejected before the route is reached).
     */
    public void destroy() throws IOException {
        Http.Response r = Http.send("DELETE", agentBase(), Map.of("Authorization", "Bearer " + token), null);
        boolean revoked = r.status() == 401 && new String(r.body(), StandardCharsets.UTF_8).contains("token revoked with its sandbox");
        if (r.status() >= 400 && r.status() != 404 && !revoked) throw new SandboxException(r.status(), r.body());
    }

    /** Alias of {@link #destroy()}, the name Daytona/E2B users expect. */
    public void delete() throws IOException {
        destroy();
    }

    // -------------------------------------------------------------- v3: preview

    public PreviewInfo preview(int port) throws IOException {
        return preview(port, null);
    }

    /** {@code POST /sandboxes/{id}/preview}: a signed URL for a port inside the sandbox. */
    public PreviewInfo preview(int port, Integer ttlSecs) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("port", port);
        if (ttlSecs != null) body.put("ttl_secs", ttlSecs);
        return Http.GSON.fromJson(Http.json("POST", agentBase() + "/preview", headers(), body), PreviewInfo.class);
    }

    // ------------------------------------------------------------- v3: sessions

    public Session createSession() throws IOException {
        return createSession(null, null, null);
    }

    /** {@code POST /sessions}: a persistent shell, alive until deleted or the sandbox stops. All arguments optional. */
    public Session createSession(String id, String cwd, Map<String, String> env) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        if (id != null && !id.isEmpty()) body.put("id", id);
        if (cwd != null && !cwd.isEmpty()) body.put("cwd", cwd);
        if (env != null && !env.isEmpty()) body.put("env", env);
        JsonObject r = Http.json("POST", endpoint + "/sessions", headers(), body).getAsJsonObject();
        return new Session(this, r.get("id").getAsString());
    }
}
