package io.github.exitcodenihil.qafas;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;

/**
 * Non-2xx response from qafas or the control plane. The message is {@code HTTP <status>: <server {"error"}
 * text, else the body>}.
 */
public class SandboxException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final int status;
    private final String body;

    public SandboxException(int status, byte[] body) {
        this(status, new String(body, StandardCharsets.UTF_8));
    }

    public SandboxException(int status, String body) {
        super("HTTP " + status + ": " + orBody(extractError(body), body));
        this.status = status;
        this.body = body;
    }

    public int status() {
        return status;
    }

    public String body() {
        return body;
    }

    private static String orBody(String err, String body) {
        return err != null && !err.isEmpty() ? err : body;
    }

    static String extractError(String body) {
        try {
            JsonElement j = JsonParser.parseString(body);
            if (j.isJsonObject() && j.getAsJsonObject().get("error") instanceof com.google.gson.JsonPrimitive p && p.isString()) {
                return p.getAsString();
            }
        } catch (JsonParseException e) {
            // not JSON: fall back to the raw body
        }
        return null;
    }
}
