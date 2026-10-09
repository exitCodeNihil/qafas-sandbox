package io.github.exitcodenihil.qafas;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Entry points, constants and the small pure helpers of the Qafas Sandbox client. Synchronous; the wire
 * contract is docs/protocol.md.
 *
 * <p><b>Errors.</b> A non-2xx reply throws the unchecked {@link SandboxException} (status and body
 * attached). Every method that talks to the network or the local disk declares {@code throws IOException}
 * (transport failures, local file errors); {@code read}/{@code stat}/{@code listdir} on a missing remote path
 * throw {@link java.nio.file.NoSuchFileException}. A bad argument (runtime name, path outside the workspace)
 * is an {@link IllegalArgumentException}. {@code Sandbox.close()} is the one method that never throws a
 * checked exception.
 */
public final class Qafas {
    private Qafas() {}

    public static final String VERSION = "0.1.0"; // x-release-please-version

    public static final String HDR_PI_SESSION = "x-pi-session";
    public static final String HDR_TOOL_CALL_ID = "x-tool-call-id";

    public static final List<String> SIZE_NAMES = List.of("micro", "mini", "medium", "high");
    public static final String DEFAULT_SIZE = "medium";
    /** Compiled defaults; {@code SBX_SIZES} on the binaries replaces the table wholesale. medium = the pre-v5 unit. */
    public static final Map<String, SandboxLimits> DEFAULT_SIZES;

    static {
        Map<String, SandboxLimits> m = new LinkedHashMap<>();
        m.put("micro", new SandboxLimits(0.5, 512, 512, 128));
        m.put("mini", new SandboxLimits(1, 1024, 1024, 256));
        m.put("medium", new SandboxLimits(2, 2048, 2048, 512));
        m.put("high", new SandboxLimits(4, 4096, 4096, 1024));
        DEFAULT_SIZES = java.util.Collections.unmodifiableMap(m);
    }

    public static final List<String> RUNTIME_VALUES = List.of("auto", "process", "docker", "firecracker");
    private static final Map<String, String> RUNTIME_TO_ISOLATION =
            Map.of("process", "native", "docker", "vm", "firecracker", "remote");
    private static final Map<String, String> ISOLATION_TO_RUNTIME =
            Map.of("native", "process", "vm", "docker", "remote", "firecracker");

    /**
     * Daytona/E2B-style tier name to this project's {@code isolation}. {@code null} and {@code "auto"} leave
     * the tier to the daemon (returns null); anything outside the accepted values throws.
     */
    public static String runtimeToIsolation(String runtime) {
        if (runtime == null) return null;
        if (!RUNTIME_VALUES.contains(runtime)) {
            throw new IllegalArgumentException(
                    "invalid runtime \"" + runtime + "\": expected one of " + String.join("|", RUNTIME_VALUES));
        }
        return RUNTIME_TO_ISOLATION.get(runtime);
    }

    public static String isolationToRuntime(String isolation) {
        return isolation == null || isolation.isEmpty() ? null : ISOLATION_TO_RUNTIME.get(isolation);
    }

    /** Bearer for the control plane: an API key identifies the application; the admin token is the root fallback. */
    public static String controlPlaneToken(String apiKey) {
        if (apiKey != null && !apiKey.isEmpty()) return apiKey;
        String k = System.getenv("SBX_API_KEY");
        if (k != null && !k.isEmpty()) return k;
        String a = System.getenv("SBX_ADMIN_TOKEN");
        return a == null ? "" : a;
    }

    static String envOr(String name, String fallback) {
        String v = System.getenv(name);
        return v == null ? fallback : v;
    }

    /** {@code GET /healthz}: a worker (qafas) answers with a {@code backend} key, the control plane does not. */
    static boolean isWorker(String base) throws IOException {
        byte[] data = Http.ok("GET", base + "/healthz", Map.of(), null);
        if (data.length == 0) return false;
        JsonElement h = Http.parse(data);
        return h.isJsonObject() && h.getAsJsonObject().has("backend");
    }

    public static Sandbox acquire(String url, String cwd, String piSession) throws IOException {
        return acquire(url, cwd, piSession, null);
    }

    /**
     * Acquires a sandbox. {@code url} may point at the control plane (:7800) or straight at a worker (:7700);
     * null falls back to {@code $SANDBOX_URL}, then {@code http://127.0.0.1:7700}. {@code piSession} defaults to
     * {@code sbx-java-<pid>}. {@code cwd} is never defaulted: pass it to mount (native, vm) or upload (remote) a
     * workspace; null gives the sandbox its own /home/agent. {@code options} may be null.
     */
    public static Sandbox acquire(String url, String cwd, String piSession, AcquireOptions options) throws IOException {
        AcquireOptions o = options != null ? options : AcquireOptions.defaults();
        String base = url != null && !url.isEmpty() ? url : envOr("SANDBOX_URL", "http://127.0.0.1:7700");
        String pi = piSession != null && !piSession.isEmpty() ? piSession : "sbx-java-" + ProcessHandle.current().pid();
        boolean worker = isWorker(base);

        String isolation = runtimeToIsolation(o.runtime);
        if (isolation == null) isolation = o.isolation;
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("template", o.snapshot != null && !o.snapshot.isEmpty() ? o.snapshot : o.template);
        req.put("pi_session", pi);
        req.put("trust", o.trust);
        if (cwd != null) req.put("workspace", Map.of("host_path", cwd));
        if (isolation != null) req.put("isolation", isolation);
        if (!o.tools.isEmpty()) req.put("tools", o.tools);
        if (!o.egressAllow.isEmpty()) req.put("egress_allow", o.egressAllow);
        if (o.ttlSecs != null) req.put("ttl_secs", o.ttlSecs);
        if (o.name != null && !o.name.isEmpty()) req.put("name", o.name);
        if (o.labels != null && !o.labels.isEmpty()) req.put("labels", o.labels);
        if (o.env != null && !o.env.isEmpty()) req.put("env", o.env);
        if (o.autoStopSecs != null) req.put("auto_stop_secs", o.autoStopSecs);
        if (o.autoArchiveSecs != null) req.put("auto_archive_secs", o.autoArchiveSecs);
        if (o.autoDeleteSecs != null) req.put("auto_delete_secs", o.autoDeleteSecs);
        if (o.maxAgeSecs != null) req.put("max_age_secs", o.maxAgeSecs);
        if (o.size != null) req.put("size", o.size);
        if (o.limits != null) req.put("limits", o.limits);

        String tok = o.token != null && !o.token.isEmpty() ? o.token
                : worker ? envOr("SBX_TOKEN", "") : controlPlaneToken(o.apiKey);
        JsonObject r = Http.json("POST", base + (worker ? "/sandboxes" : "/api/sandboxes"),
                Map.of("Authorization", "Bearer " + tok), req).getAsJsonObject();

        Sandbox sb = new Sandbox(
                required(r, "endpoint"), required(r, "token"), pi, required(r, "id"), required(r, "backend"),
                required(r, "workspace_path"),
                str(r, "isolation"),
                present(r, "tools") ? Http.GSON.fromJson(r.get("tools"), new TypeToken<Map<String, String>>() {}.getType()) : null,
                present(r, "missing_tools") ? Http.GSON.fromJson(r.get("missing_tools"), new TypeToken<List<String>>() {}.getType()) : null,
                str(r, "size"),
                present(r, "limits") ? Http.GSON.fromJson(r.get("limits"), SandboxLimits.class) : null,
                present(r, "info") ? r.get("info").getAsJsonObject() : null);

        // A microVM has no bind mount: the cwd travels as a tar, minus build output and credentials.
        if (cwd != null && "remote".equals(sb.isolation()) && o.uploadWorkspace) {
            try {
                sb.uploadTar(cwd, Pack.packWorkspace(Path.of(cwd)));
            } catch (IOException | RuntimeException e) {
                // Do not leak a running sandbox the caller has no handle to.
                try {
                    sb.destroy();
                } catch (IOException | RuntimeException ignored) {
                    // the upload error is the one worth reporting
                }
                throw new IllegalStateException("workspace upload failed (" + e.getMessage()
                        + "): pass uploadWorkspace(false) or a smaller directory (.sbxignore)", e);
            }
        }
        return sb;
    }

    /** Snapshots (named images) are top-level; {@code token} null = {@code $SBX_TOKEN} (worker) or the control-plane token. */
    public static Snapshots snapshots(String url, String token) {
        return new Snapshots(url, token);
    }

    private static boolean present(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull();
    }

    static String str(JsonObject o, String key) {
        return present(o, key) ? o.get(key).getAsString() : null;
    }

    private static String required(JsonObject o, String key) throws IOException {
        String v = str(o, key);
        if (v == null) throw new IOException("malformed reply: missing \"" + key + "\"");
        return v;
    }
}
