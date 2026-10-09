package io.github.exitcodenihil.qafas;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Port of sdk/python/tests/test_pack.py plus the tar-unpack guards. */
class PackTest {
    private static void write(Path root, String rel, String body) throws IOException {
        Path p = root.resolve(rel);
        Files.createDirectories(p.getParent());
        Files.writeString(p, body);
    }

    private static Map<String, TarArchiveEntry> entries(byte[] tar) throws IOException {
        Map<String, TarArchiveEntry> m = new HashMap<>();
        try (TarArchiveInputStream in = new TarArchiveInputStream(new ByteArrayInputStream(tar))) {
            for (TarArchiveEntry e; (e = in.getNextEntry()) != null; ) m.put(e.getName(), e);
        }
        return m;
    }

    private static List<String> names(byte[] tar) throws IOException {
        List<String> l = new ArrayList<>(entries(tar).keySet());
        Collections.sort(l);
        return l;
    }

    @Test
    void defaultIgnoreIsThePythonList() {
        assertEquals(24, Pack.DEFAULT_IGNORE.size());
        assertEquals("node_modules", Pack.DEFAULT_IGNORE.get(0));
        assertEquals("!.env.example", Pack.DEFAULT_IGNORE.get(12));
        assertEquals("secrets*", Pack.DEFAULT_IGNORE.get(23));
    }

    @Test
    void defaultIgnoreExcludesSecretsAndBuildOutput(@TempDir Path root) throws IOException {
        write(root, "src/main.py", "x");
        write(root, ".git/config", "x");
        write(root, ".env", "OPENAI_API_KEY=sk-live");
        write(root, ".env.example", "OPENAI_API_KEY=");
        write(root, "node_modules/left-pad/index.js", "x");
        write(root, "dist/bundle.js", "x");
        write(root, "deploy/server.key", "x");
        write(root, ".ssh/id_rsa", "x");
        write(root, "credentials.json", "x");
        write(root, "debug.log", "x");

        assertEquals(List.of(".env.example", ".git/config", "src/main.py"), names(Pack.packWorkspace(root)));
    }

    @Test
    void sbxignoreSupportsAnchoredDirOnlyAndNegatedRules(@TempDir Path root) throws IOException {
        write(root, "src/main.py", "x");
        write(root, "secrets/db.json", "x"); // dir-only rule "secrets/" excludes the whole tree
        write(root, "notes/keep.txt", "x"); // negated "!keep.txt" survives a broader exclude
        write(root, "notes/draft.txt", "x");
        write(root, "vendor/notes/draft.txt", "x"); // anchored "notes/draft.txt" must NOT match this nested copy
        write(root, ".sbxignore", "secrets/\nnotes/draft.txt\n!keep.txt\n");

        assertEquals(List.of(".sbxignore", "notes/keep.txt", "src/main.py", "vendor/notes/draft.txt"),
                names(Pack.packWorkspace(root)));
    }

    @Test
    void extraIgnoreAndGlobsAndLastRuleWins(@TempDir Path root) throws IOException {
        write(root, "a.txt", "x");
        write(root, "b.tmp", "x");
        write(root, "c1.dat", "x");
        write(root, "cc.dat", "x");
        write(root, ".sbxignore", "# comment\n\n*.tmp\n");
        // "?" matches one non-slash char; the later "!a.txt" wins over the earlier "a.*".
        assertEquals(List.of(".sbxignore", "a.txt", "cc.dat"),
                names(Pack.packWorkspace(root, List.of("a.*", "!a.txt", "c?.dat", "!cc.dat"))));
    }

    @Test
    void symlinksTravelAsLinksAndAreNotFollowed(@TempDir Path d) throws IOException {
        Files.createDirectories(d.resolve("real"));
        Files.writeString(d.resolve("real/f.txt"), "x");
        Files.createSymbolicLink(d.resolve("linkdir"), Path.of("real"));
        Files.createSymbolicLink(d.resolve("linkfile"), Path.of("real/f.txt"));
        Files.createSymbolicLink(d.resolve("outside"), Path.of("/etc/passwd"));

        Map<String, TarArchiveEntry> m = entries(Pack.packWorkspace(d));
        assertTrue(m.get("linkdir").isSymbolicLink());
        assertEquals("real", m.get("linkdir").getLinkName());
        assertTrue(m.get("linkfile").isSymbolicLink());
        assertTrue(m.get("outside").isSymbolicLink());
        assertEquals("/etc/passwd", m.get("outside").getLinkName());
        assertFalse(m.containsKey("linkdir/f.txt"), "a symlinked directory is not descended into");
        assertTrue(m.containsKey("real/f.txt"));
    }

    @Test
    void roundTripKeepsContentModeAndLinks(@TempDir Path src, @TempDir Path dst) throws IOException {
        write(src, "bin/run.sh", "#!/bin/sh\n");
        Files.setPosixFilePermissions(src.resolve("bin/run.sh"), java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        write(src, "sub/n.txt", "nested");
        Files.createSymbolicLink(src.resolve("l"), Path.of("sub/n.txt"));

        Pack.unpackTar(Pack.packWorkspace(src), dst.resolve("out"));
        assertEquals("nested", Files.readString(dst.resolve("out/sub/n.txt")));
        assertTrue(Files.isExecutable(dst.resolve("out/bin/run.sh")));
        assertEquals(Path.of("sub/n.txt"), Files.readSymbolicLink(dst.resolve("out/l")));
    }

    private static byte[] tarWith(String name, byte linkType, String linkName) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (TarArchiveOutputStream t = new TarArchiveOutputStream(buf)) {
            TarArchiveEntry e = new TarArchiveEntry(name, linkType, true);
            if (linkType == TarConstants.LF_SYMLINK) {
                e.setLinkName(linkName);
            } else {
                byte[] data = "pwned".getBytes(StandardCharsets.UTF_8);
                e.setSize(data.length);
                t.putArchiveEntry(e);
                t.write(data);
                t.closeArchiveEntry();
                t.finish();
                return buf.toByteArray();
            }
            t.putArchiveEntry(e);
            t.closeArchiveEntry();
            t.finish();
        }
        return buf.toByteArray();
    }

    @Test
    void unpackRefusesMembersOutsideDestination(@TempDir Path base) throws IOException {
        Path dest = base.resolve("dest");
        IOException e = assertThrows(IOException.class,
                () -> Pack.unpackTar(tarWith("../x", TarConstants.LF_NORMAL, null), dest));
        assertEquals("refusing to extract tar member outside destination: ../x", e.getMessage());
        assertFalse(Files.exists(base.resolve("x")));

        Path abs = base.resolve("abs-target");
        e = assertThrows(IOException.class,
                () -> Pack.unpackTar(tarWith(abs.toString(), TarConstants.LF_NORMAL, null), dest));
        assertTrue(e.getMessage().startsWith("refusing to extract tar member outside destination: "));
        assertFalse(Files.exists(abs));
    }

    @Test
    void unpackRefusesSymlinksThatEscape(@TempDir Path base) {
        Path dest = base.resolve("dest");
        assertThrows(IOException.class, () -> Pack.unpackTar(tarWith("l", TarConstants.LF_SYMLINK, "../outside"), dest));
        assertThrows(IOException.class, () -> Pack.unpackTar(tarWith("l", TarConstants.LF_SYMLINK, "/etc/passwd"), dest));
        assertFalse(Files.exists(dest.resolve("l"), java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }
}
