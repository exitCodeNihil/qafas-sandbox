package io.github.exitcodenihil.qafas;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * A persistent shell inside a sandbox. Reached through the owning {@link Sandbox}'s endpoint and token, so it
 * never needs its own auth.
 */
public final class Session {
    private final Sandbox sb;
    private final String id;

    public Session(Sandbox sandbox, String id) {
        this.sb = sandbox;
        this.id = id;
    }

    public String id() {
        return id;
    }

    private String base() {
        return sb.endpoint() + "/sessions/" + id;
    }

    public SessionCommand exec(String cmd) throws IOException {
        return exec(cmd, false, null);
    }

    /**
     * {@code POST /sessions/{id}/exec}. Sync returns exit/stdout/stderr. Async returns at once with only
     * {@code commandId} set; poll {@link #command} or stream {@link #logs}. One command per session at a time.
     */
    public SessionCommand exec(String cmd, boolean async, Integer timeoutMs) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cmd", cmd);
        if (async) body.put("async", true);
        if (timeoutMs != null) body.put("timeout_ms", timeoutMs);
        return Http.GSON.fromJson(Http.json("POST", base() + "/exec", sb.headers(), body), SessionCommand.class);
    }

    /** {@code GET /sessions/{id}/commands/{cid}}, including stdout/stderr (capped like /exec). */
    public SessionCommand command(String cid) throws IOException {
        return Http.GSON.fromJson(Http.json("GET", base() + "/commands/" + cid, sb.headers(), null), SessionCommand.class);
    }

    /** Sends {@code data} (base64, as the wire expects) to the stdin of the running command {@code cid}. */
    public void input(String cid, String data) throws IOException {
        Http.json("POST", base() + "/commands/" + cid + "/input", sb.headers(), Map.of("data", data));
    }

    /**
     * Streams stdout/stderr of {@code cid} over WebSocket (buffered output replayed, then live) until its exit
     * frame, calling {@code onOutput(chunk, stream)} on the calling thread; then returns {@link #command}
     * (the authoritative final state). {@code onOutput} may be null.
     */
    public SessionCommand logs(String cid, BiConsumer<byte[], String> onOutput) throws IOException {
        try (Http.Ws ws = new Http.Ws(Http.toWs(sb.endpoint()) + "/sessions/" + id + "/commands/" + cid + "/logs/ws", sb.headers())) {
            for (String raw; (raw = ws.next()) != null; ) {
                JsonObject f = Http.parse(raw.getBytes(StandardCharsets.UTF_8)).getAsJsonObject();
                String t = Qafas.str(f, "type");
                if (("stdout".equals(t) || "stderr".equals(t)) && onOutput != null) {
                    onOutput.accept(Base64.getDecoder().decode(f.get("data").getAsString()), t);
                } else if ("exit".equals(t)) {
                    break;
                }
            }
        }
        return command(cid);
    }

    /** {@code DELETE /sessions/{id}}: kills the shell's process group; a 404 is success. */
    public void delete() throws IOException {
        Http.Response r = Http.send("DELETE", base(), sb.headers(), null);
        if (r.status() >= 400 && r.status() != 404) throw new SandboxException(r.status(), r.body());
    }
}
