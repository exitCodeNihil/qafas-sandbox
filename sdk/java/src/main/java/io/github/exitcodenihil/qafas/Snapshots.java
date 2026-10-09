package io.github.exitcodenihil.qafas;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Snapshots (named images a sandbox can be created from) are top-level, not tied to any one sandbox. Every call
 * does the same worker-vs-control-plane detection as {@link Qafas#acquire}. {@code token} null = {@code $SBX_TOKEN}
 * (worker) or the control-plane token ({@code $SBX_API_KEY}, {@code $SBX_ADMIN_TOKEN}).
 */
public final class Snapshots {
    private final String url;
    private final String token;

    public Snapshots(String url, String token) {
        this.url = url;
        this.token = token;
    }

    private record Target(String root, Map<String, String> headers) {}

    private Target target() throws IOException {
        boolean worker = Qafas.isWorker(url);
        String tok = token != null && !token.isEmpty() ? token
                : worker ? Qafas.envOr("SBX_TOKEN", "") : Qafas.controlPlaneToken(null);
        return new Target(url + (worker ? "/snapshots" : "/api/snapshots"), Map.of("Authorization", "Bearer " + tok));
    }

    /** The control plane fans a create or a warm change out to every host and answers a list: element 0. */
    private static SnapshotInfo one(JsonElement e) {
        return Http.GSON.fromJson(e.isJsonArray() ? e.getAsJsonArray().get(0) : e, SnapshotInfo.class);
    }

    public SnapshotInfo create(String name, SnapshotOptions o) throws IOException {
        Map<String, String> source = new LinkedHashMap<>();
        if (o.image != null && !o.image.isEmpty()) source.put("image", o.image);
        if (o.dockerfile != null && !o.dockerfile.isEmpty()) source.put("dockerfile", o.dockerfile);
        if (o.sandboxId != null && !o.sandboxId.isEmpty()) source.put("sandbox_id", o.sandboxId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("source", source);
        if (o.warm != null) body.put("warm", o.warm);
        if (o.memorySnapshot != null) body.put("memory_snapshot", o.memorySnapshot);
        Target t = target();
        return one(Http.json("POST", t.root(), t.headers(), body));
    }

    public List<SnapshotInfo> list() throws IOException {
        Target t = target();
        JsonArray a = Http.json("GET", t.root(), t.headers(), null).getAsJsonArray();
        List<SnapshotInfo> out = new ArrayList<>();
        for (JsonElement e : a) out.add(Http.GSON.fromJson(e, SnapshotInfo.class));
        return out;
    }

    public SnapshotInfo get(String name) throws IOException {
        Target t = target();
        return Http.GSON.fromJson(Http.json("GET", t.root() + "/" + Http.quote(name), t.headers(), null), SnapshotInfo.class);
    }

    /** A 404 (already gone) is success. */
    public void delete(String name) throws IOException {
        Target t = target();
        Http.Response r = Http.send("DELETE", t.root() + "/" + Http.quote(name), t.headers(), null);
        if (r.status() >= 400 && r.status() != 404) throw new SandboxException(r.status(), r.body());
    }

    /** v4 {@code PUT /snapshots/{name} {"warm": n}}: sets the pool's warm target live. */
    public SnapshotInfo setWarm(String name, int n) throws IOException {
        Target t = target();
        return one(Http.json("PUT", t.root() + "/" + Http.quote(name), t.headers(), Map.of("warm", n)));
    }

    public SnapshotInfo waitReady(String name) throws IOException, TimeoutException {
        return waitReady(name, Duration.ofSeconds(120));
    }

    /** Polls {@link #get} every second until the state leaves "building" or {@code timeout} elapses. */
    public SnapshotInfo waitReady(String name, Duration timeout) throws IOException, TimeoutException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            SnapshotInfo info = get(name);
            if (!"building".equals(info.state())) return info;
            if (System.nanoTime() > deadline) {
                throw new TimeoutException("snapshot " + name + " still building after " + timeout.toMillis() / 1000.0 + "s");
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("waitReady interrupted");
            }
        }
    }
}
