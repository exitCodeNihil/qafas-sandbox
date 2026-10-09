package io.github.exitcodenihil.qafas;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Declarative Dockerfile builder for {@link SnapshotOptions#dockerfile(Image)}. String concatenation, not a
 * Dockerfile AST; the output is byte-identical to the Python and TypeScript builders.
 */
public final class Image {
    private final List<String> lines = new ArrayList<>();

    public Image(String base) {
        lines.add("FROM " + base);
    }

    public static Image base(String image) {
        return new Image(image);
    }

    /** Single-quotes {@code s} for a POSIX shell, escaping embedded quotes. */
    private static String shQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    private static String quoted(List<String> pkgs) {
        return pkgs.stream().map(Image::shQuote).collect(Collectors.joining(" "));
    }

    public Image run(String cmd) {
        lines.add("RUN " + cmd);
        return this;
    }

    public Image workdir(String directory) {
        lines.add("WORKDIR " + directory);
        return this;
    }

    /** One {@code ENV K="v"} line per entry, in the map's iteration order (use a LinkedHashMap). */
    public Image env(Map<String, String> vars) {
        vars.forEach((k, v) -> lines.add("ENV " + k + "=\"" + v + "\""));
        return this;
    }

    public Image pipInstall(List<String> pkgs) {
        if (!pkgs.isEmpty()) lines.add("RUN pip install --no-cache-dir " + quoted(pkgs));
        return this;
    }

    public Image npmInstall(List<String> pkgs) {
        if (!pkgs.isEmpty()) lines.add("RUN npm install -g " + quoted(pkgs));
        return this;
    }

    /**
     * Writes {@code content} to {@code destPath} in the image. A Dockerfile COPY needs a build-context file
     * that does not exist here, so the content is embedded as base64 and decoded in a RUN step.
     */
    public Image copyText(String destPath, String content) {
        String b64 = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
        lines.add("RUN mkdir -p \"$(dirname " + shQuote(destPath) + ")\" && echo " + shQuote(b64) + " | base64 -d > "
                + shQuote(destPath));
        return this;
    }

    public String toDockerfile() {
        return String.join("\n", lines) + "\n";
    }

    @Override
    public String toString() {
        return toDockerfile();
    }
}
