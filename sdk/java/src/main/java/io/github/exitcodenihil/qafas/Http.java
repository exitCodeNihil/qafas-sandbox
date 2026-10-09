package io.github.exitcodenihil.qafas;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** The one HTTP/WebSocket plumbing layer (java.net.http), shared by every class in this package. */
final class Http {
    private Http() {}

    static final Gson GSON = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .disableHtmlEscaping()
            .create();

    record Response(int status, byte[] body) {}

    private static HttpClient client;
    private static String clientCa;

    /** One client per {@code SBX_CA_FILE} value: its trust store holds the JVM's CAs plus that PEM. */
    static synchronized HttpClient client() throws IOException {
        String ca = System.getenv("SBX_CA_FILE");
        if (ca != null && ca.isEmpty()) ca = null;
        if (client == null || !Objects.equals(ca, clientCa)) {
            HttpClient.Builder b = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(30));
            if (ca != null) b.sslContext(sslContext(Path.of(ca)));
            client = b.build();
            clientCa = ca;
        }
        return client;
    }

    static SSLContext sslContext(Path pem) throws IOException {
        try {
            TrustManagerFactory sys = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            sys.init((KeyStore) null);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int i = 0;
            for (var tm : sys.getTrustManagers()) {
                if (tm instanceof X509TrustManager x) {
                    for (var c : x.getAcceptedIssuers()) ks.setCertificateEntry("sys-" + i++, c);
                }
            }
            try (InputStream in = Files.newInputStream(pem)) {
                for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                    ks.setCertificateEntry("ca-" + i++, c);
                }
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IOException("SBX_CA_FILE " + pem + ": " + e.getMessage(), e);
        }
    }

    static Response send(String method, String url, Map<String, String> headers, byte[] body) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url));
        headers.forEach(b::header);
        b.method(method, body == null ? BodyPublishers.noBody() : BodyPublishers.ofByteArray(body));
        try {
            HttpResponse<byte[]> r = client().send(b.build(), BodyHandlers.ofByteArray());
            return new Response(r.statusCode(), r.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException(method + " " + url + " interrupted");
        }
    }

    /** Status >= 400 raises {@link SandboxException}. */
    static byte[] ok(String method, String url, Map<String, String> headers, byte[] body) throws IOException {
        Response r = send(method, url, headers, body);
        if (r.status() >= 400) throw new SandboxException(r.status(), r.body());
        return r.body();
    }

    /** JSON in, JSON out ({@code null} when the reply has no body). */
    static JsonElement json(String method, String url, Map<String, String> headers, Object obj) throws IOException {
        Map<String, String> h = headers;
        byte[] body = null;
        if (obj != null) {
            body = GSON.toJson(obj).getBytes(StandardCharsets.UTF_8);
            h = new java.util.LinkedHashMap<>(headers);
            h.put("content-type", "application/json");
        }
        byte[] data = ok(method, url, h, body);
        return data.length == 0 ? null : parse(data);
    }

    static JsonElement parse(byte[] data) throws IOException {
        try {
            return JsonParser.parseString(new String(data, StandardCharsets.UTF_8));
        } catch (JsonParseException e) {
            throw new IOException("malformed JSON reply: " + e.getMessage(), e);
        }
    }

    /** Percent-encodes like Python's {@code urllib.parse.quote}: unreserved characters and {@code /} stay. */
    static String quote(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "_.-~/".indexOf(c) >= 0) {
                sb.append((char) c);
            } else {
                sb.append('%').append("0123456789ABCDEF".charAt(c >> 4)).append("0123456789ABCDEF".charAt(c & 15));
            }
        }
        return sb.toString();
    }

    static String toWs(String url) {
        return url.replaceFirst("^http", "ws");
    }

    /**
     * A WebSocket whose text frames are read on the caller's thread ({@link #next()}), one at a time: the next
     * frame is only requested once the previous one was taken.
     */
    static final class Ws implements AutoCloseable {
        private static final Object END = new Object();
        private final BlockingQueue<Object> q = new LinkedBlockingQueue<>();
        private final StringBuilder partial = new StringBuilder();
        private final WebSocket ws;

        Ws(String url, Map<String, String> headers) throws IOException {
            WebSocket.Builder b = client().newWebSocketBuilder();
            headers.forEach(b::header);
            try {
                ws = b.buildAsync(URI.create(url), new Listener()).get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("websocket connect interrupted");
            } catch (ExecutionException e) {
                if (e.getCause() instanceof WebSocketHandshakeException h) {
                    byte[] body = new byte[0];
                    try {
                        if (h.getResponse().body() instanceof InputStream in) body = in.readAllBytes();
                    } catch (IOException ignored) {
                        // the status is what matters
                    }
                    throw new SandboxException(h.getResponse().statusCode(), body);
                }
                throw new IOException("websocket " + url + ": " + e.getCause(), e.getCause());
            }
        }

        void send(String text) throws IOException {
            try {
                ws.sendText(text, true).get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("websocket send interrupted");
            } catch (ExecutionException e) {
                throw new IOException("websocket send: " + e.getCause(), e.getCause());
            }
        }

        /** Next text frame; {@code null} once the server closed the socket. */
        String next() throws IOException {
            return take(null);
        }

        /** Next text frame, or {@code null} on timeout or close. */
        String next(Duration timeout) throws IOException {
            return take(timeout);
        }

        private String take(Duration timeout) throws IOException {
            try {
                Object o = timeout == null ? q.take() : q.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
                if (o == null) return null;
                if (o == END || o instanceof Throwable) {
                    q.add(o); // stay ended for later calls
                    if (o instanceof Throwable t) throw new IOException("websocket: " + t, t);
                    return null;
                }
                ws.request(1);
                return (String) o;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("websocket read interrupted");
            }
        }

        @Override
        public void close() {
            ws.abort();
        }

        private final class Listener implements WebSocket.Listener {
            @Override
            public void onOpen(WebSocket w) {
                w.request(1);
            }

            @Override
            public CompletionStage<?> onText(WebSocket w, CharSequence data, boolean last) {
                partial.append(data);
                if (last) {
                    q.add(partial.toString());
                    partial.setLength(0);
                } else {
                    w.request(1);
                }
                return null;
            }

            @Override
            public CompletionStage<?> onBinary(WebSocket w, ByteBuffer data, boolean last) {
                w.request(1);
                return null;
            }

            @Override
            public CompletionStage<?> onClose(WebSocket w, int code, String reason) {
                q.add(END);
                return null;
            }

            @Override
            public void onError(WebSocket w, Throwable t) {
                q.add(t);
            }
        }
    }
}
