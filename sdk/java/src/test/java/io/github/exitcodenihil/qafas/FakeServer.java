package io.github.exitcodenihil.qafas;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** A tiny fake qafas / control plane (JDK HttpServer): routes keyed {@code "METHOD /path?query"}. */
final class FakeServer implements AutoCloseable {
    record Req(String method, String uri, Headers headers, byte[] body) {
        JsonObject json() {
            return JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject();
        }
    }

    record Reply(int status, String body) {}

    interface Route {
        Reply handle(Req req);
    }

    private final HttpServer server;
    private final Map<String, Route> routes = new HashMap<>();
    final List<String> seen = Collections.synchronizedList(new ArrayList<>());
    final List<Req> requests = Collections.synchronizedList(new ArrayList<>());
    final String url;

    FakeServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        url = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/", ex -> {
            byte[] body = ex.getRequestBody().readAllBytes();
            String key = ex.getRequestMethod() + " " + ex.getRequestURI();
            Req req = new Req(ex.getRequestMethod(), ex.getRequestURI().toString(), ex.getRequestHeaders(), body);
            seen.add(key);
            requests.add(req);
            Route r = routes.get(key);
            Reply reply = r == null ? new Reply(404, "not found") : r.handle(req);
            byte[] out = reply.body().getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("content-type", "application/json");
            if (out.length == 0) {
                ex.sendResponseHeaders(reply.status(), -1);
            } else {
                ex.sendResponseHeaders(reply.status(), out.length);
                ex.getResponseBody().write(out);
            }
            ex.close();
        });
        server.start();
    }

    FakeServer on(String key, int status, String body) {
        routes.put(key, req -> new Reply(status, body));
        return this;
    }

    FakeServer on(String key, Route route) {
        routes.put(key, route);
        return this;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
