package io.github.exitcodenihil.qafas;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;

/**
 * Workspace tar packing and unpacking, with the same ignore engine as the Python and TypeScript SDKs
 * (sdk/ts/src/pack.ts), so all packers exclude the same files. The one thing this must never do is upload
 * a credential.
 */
public final class Pack {
    private Pack() {}

    /** What never leaves the machine. Same entries, same order as the Python and TypeScript SDKs. */
    public static final List<String> DEFAULT_IGNORE = List.of(
            "node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build", ".next", ".cache",
            "*.log", ".env", ".env.*", "!.env.example", "*.pem", "*.key", "id_rsa*", ".aws", ".ssh", ".gnupg",
            ".netrc", ".npmrc", ".pypirc", "credentials*", "secrets*");

    private record Rule(Pattern re, boolean dirOnly, boolean anchored, boolean negate) {}

    /** {@code #} comments, {@code !} re-includes, trailing {@code /} = directories only, a {@code /} anywhere anchors to the root. */
    static Rule compile(String line) {
        String p = line.strip();
        if (p.isEmpty() || p.startsWith("#")) return null;
        boolean negate = p.startsWith("!");
        if (negate) p = p.substring(1);
        boolean dirOnly = p.endsWith("/");
        if (dirOnly) p = p.substring(0, p.length() - 1);
        boolean anchored = p.contains("/");
        if (p.startsWith("/")) p = p.substring(1);
        if (p.isEmpty()) return null;
        StringBuilder re = new StringBuilder();
        for (char c : p.toCharArray()) {
            re.append(c == '*' ? "[^/]*" : c == '?' ? "[^/]" : Pattern.quote(String.valueOf(c)));
        }
        return new Rule(Pattern.compile(re.toString()), dirOnly, anchored, negate);
    }

    /** Last matching rule wins, so {@code !.env.example} survives {@code .env.*}. */
    private static boolean ignored(List<Rule> rules, String rel, boolean isDir) {
        String name = rel.substring(rel.lastIndexOf('/') + 1);
        boolean ignored = false;
        for (Rule r : rules) {
            if (r.dirOnly() && !isDir) continue;
            if (r.re().matcher(r.anchored() ? rel : name).matches()) ignored = !r.negate();
        }
        return ignored;
    }

    public static byte[] packWorkspace(Path cwd) throws IOException {
        return packWorkspace(cwd, List.of());
    }

    /**
     * Tar of {@code cwd}: relative {@code /}-separated names, files and symlinks only (links are stored as
     * links, never followed; directories are implied by their files), honouring {@link #DEFAULT_IGNORE}, the
     * lines of {@code <cwd>/.sbxignore}, then {@code extraIgnore}. Buffered in memory.
     */
    // ponytail: whole tar in a byte[] (Python does too); stream into a PipedInputStream body if huge workspaces matter
    public static byte[] packWorkspace(Path cwd, List<String> extraIgnore) throws IOException {
        List<String> lines = new ArrayList<>(DEFAULT_IGNORE);
        Path sbxignore = cwd.resolve(".sbxignore");
        if (Files.isRegularFile(sbxignore)) lines.addAll(Files.readAllLines(sbxignore));
        lines.addAll(extraIgnore);
        List<Rule> rules = new ArrayList<>();
        for (String l : lines) {
            Rule r = compile(l);
            if (r != null) rules.add(r);
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(buf)) {
            tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            tar.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
            walk(cwd, "", rules, tar);
            tar.finish();
        }
        return buf.toByteArray();
    }

    private static void walk(Path dir, String relDir, List<Rule> rules, TarArchiveOutputStream tar) throws IOException {
        List<Path> entries;
        try (Stream<Path> s = Files.list(dir)) {
            entries = s.sorted(Comparator.comparing(p -> p.getFileName().toString())).toList();
        }
        List<Path> subdirs = new ArrayList<>();
        List<Path> files = new ArrayList<>();
        for (Path p : entries) {
            boolean symlink = Files.isSymbolicLink(p);
            // os.walk semantics: a symlink to a directory is listed among the directories.
            if (symlink && Files.isDirectory(p)) {
                if (!ignored(rules, relDir + p.getFileName(), true)) addEntry(tar, p, relDir + p.getFileName());
            } else if (!symlink && Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
                if (!ignored(rules, relDir + p.getFileName(), true)) subdirs.add(p);
            } else {
                files.add(p);
            }
        }
        for (Path p : files) {
            String rel = relDir + p.getFileName();
            if (!ignored(rules, rel, false)) addEntry(tar, p, rel);
        }
        for (Path p : subdirs) walk(p, relDir + p.getFileName() + "/", rules, tar);
    }

    private static void addEntry(TarArchiveOutputStream tar, Path p, String name) throws IOException {
        if (Files.isSymbolicLink(p)) {
            TarArchiveEntry e = new TarArchiveEntry(name, TarConstants.LF_SYMLINK);
            e.setLinkName(Files.readSymbolicLink(p).toString());
            e.setModTime(Files.getLastModifiedTime(p, LinkOption.NOFOLLOW_LINKS));
            tar.putArchiveEntry(e);
            tar.closeArchiveEntry();
        } else if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
            TarArchiveEntry e = new TarArchiveEntry(p, name);
            e.setMode(mode(p));
            tar.putArchiveEntry(e);
            Files.copy(p, tar);
            tar.closeArchiveEntry();
        } // sockets, fifos and devices are skipped, like tarfile does
    }

    /** rwx bits as in {@code st_mode & 0777}; 0644 where the file system has no POSIX permissions. */
    private static int mode(Path p) throws IOException {
        try {
            int mode = 0;
            for (PosixFilePermission perm : Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS)) {
                mode |= 0400 >> perm.ordinal();
            }
            return mode;
        } catch (UnsupportedOperationException e) {
            return 0644;
        }
    }

    /**
     * Extracts a tar (as produced by {@link #packWorkspace} or {@code download_tar}) into {@code dest}, refusing
     * any member, or symlink target, that would land outside it (the tar comes from a host we do not fully trust).
     */
    // ponytail: lexical containment check only; a symlink already on disk inside dest can still redirect a later member. Resolve real paths if dest may hold foreign links
    public static void unpackTar(byte[] data, Path dest) throws IOException {
        Files.createDirectories(dest);
        Path root = dest.toAbsolutePath().normalize();
        try (TarArchiveInputStream tar = new TarArchiveInputStream(new ByteArrayInputStream(data))) {
            TarArchiveEntry e;
            while ((e = tar.getNextEntry()) != null) {
                Path target = root.resolve(e.getName()).normalize();
                if (!target.startsWith(root)) {
                    throw new IOException("refusing to extract tar member outside destination: " + e.getName());
                }
                if (e.isDirectory()) {
                    Files.createDirectories(target);
                } else if (e.isSymbolicLink()) {
                    Path link = Path.of(e.getLinkName());
                    Path resolved = link.isAbsolute() ? link.normalize() : target.getParent().resolve(link).normalize();
                    if (!resolved.startsWith(root)) {
                        throw new IOException("refusing to extract tar member outside destination: " + e.getName()
                                + " -> " + e.getLinkName());
                    }
                    Files.createDirectories(target.getParent());
                    Files.deleteIfExists(target);
                    Files.createSymbolicLink(target, link);
                } else if (e.isLink()) {
                    Path src = root.resolve(e.getLinkName()).normalize();
                    if (!src.startsWith(root)) {
                        throw new IOException("refusing to extract tar member outside destination: " + e.getName()
                                + " -> " + e.getLinkName());
                    }
                    Files.createDirectories(target.getParent());
                    Files.copy(src, target, StandardCopyOption.REPLACE_EXISTING);
                } else if (e.isFile()) {
                    Files.createDirectories(target.getParent());
                    Files.copy(tar, target, StandardCopyOption.REPLACE_EXISTING);
                    chmod(target, e.getMode());
                    Files.setLastModifiedTime(target, e.getLastModifiedTime());
                }
            }
        }
    }

    private static void chmod(Path p, int mode) throws IOException {
        PosixFilePermission[] all = PosixFilePermission.values(); // OWNER_READ .. OTHERS_EXECUTE, 0400 .. 0001
        Set<PosixFilePermission> perms = new java.util.HashSet<>();
        for (int i = 0; i < 9; i++) {
            if ((mode & (0400 >> i)) != 0) perms.add(all[i]);
        }
        try {
            Files.setPosixFilePermissions(p, perms);
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX file system
        }
    }
}
