package io.github.exitcodenihil.qafas;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code SBX_CA_FILE} support: an internal-CA https server is trusted with the PEM and refused without it. */
class TlsTest {
    private static void keytool(Path dir, String... args) throws Exception {
        String[] cmd = new String[args.length + 1];
        cmd[0] = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        assertEquals(0, p.waitFor(), String.join(" ", cmd));
    }

    @Test
    void customCaIsTrustedAlongsideTheSystemOnes(@TempDir Path dir) throws Exception {
        keytool(dir, "-genkeypair", "-alias", "srv", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=localhost",
                "-ext", "san=ip:127.0.0.1,dns:localhost", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", "ks.p12", "-storepass", "changeit");
        keytool(dir, "-exportcert", "-rfc", "-alias", "srv", "-keystore", "ks.p12", "-storepass", "changeit", "-file", "ca.pem");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(dir.resolve("ks.p12"))) {
            ks.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);
        HttpsServer srv = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.setHttpsConfigurator(new HttpsConfigurator(serverCtx));
        srv.createContext("/", ex -> {
            ex.sendResponseHeaders(200, 2);
            ex.getResponseBody().write("ok".getBytes());
            ex.close();
        });
        srv.start();
        try {
            URI uri = URI.create("https://127.0.0.1:" + srv.getAddress().getPort() + "/");
            HttpRequest req = HttpRequest.newBuilder(uri).build();
            HttpClient trusted = HttpClient.newBuilder().sslContext(Http.sslContext(dir.resolve("ca.pem"))).build();
            assertEquals("ok", trusted.send(req, HttpResponse.BodyHandlers.ofString()).body());
            assertThrows(SSLHandshakeException.class, () -> HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString()));
            assertThrows(IOException.class, () -> Http.sslContext(dir.resolve("missing.pem")));
        } finally {
            srv.stop(0);
        }
    }
}
