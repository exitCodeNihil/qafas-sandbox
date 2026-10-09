//! Workspace tar: what a `remote` (microVM) sandbox gets instead of a bind mount, and what
//! `upload`/`download` move. The ignore engine is the one in `sdk/python` and `sdk/ts/src/pack.ts`
//! (anchored, directory-only, negated rules; last match wins) so every SDK excludes the same
//! files. The one thing this must never do is upload a credential.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::{Error, Result};

/// Never uploaded: build output and caches (big, reproducible), then secrets (small, catastrophic).
pub const DEFAULT_IGNORE: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".next",
    ".cache",
    "*.log",
    ".env",
    ".env.*",
    "!.env.example",
    "*.pem",
    "*.key",
    "id_rsa*",
    ".aws",
    ".ssh",
    ".gnupg",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials*",
    "secrets*",
];

struct Rule {
    pat: Vec<char>,
    dir_only: bool,
    anchored: bool,
    negate: bool,
}

/// Mirrors `_compile_ignore_rule`: `#` comments, `!` re-includes, a trailing `/` for directories
/// only, a `/` anywhere anchors the pattern to the workspace root instead of the basename.
fn compile(line: &str) -> Option<Rule> {
    let mut p = line.trim();
    if p.is_empty() || p.starts_with('#') {
        return None;
    }
    let negate = p.starts_with('!');
    if negate {
        p = &p[1..];
    }
    let dir_only = p.ends_with('/');
    if dir_only {
        p = &p[..p.len() - 1];
    }
    let anchored = p.contains('/');
    p = p.strip_prefix('/').unwrap_or(p);
    if p.is_empty() {
        return None;
    }
    Some(Rule { pat: p.chars().collect(), dir_only, anchored, negate })
}

/// `*` is `[^/]*`, `?` is `[^/]`, everything else literal; the whole string must match.
// ponytail: backtracking, exponential in the number of `*` in one rule; fine for ignore lines,
// swap for the two-pointer form if someone ever writes a pathological pattern.
fn glob(p: &[char], s: &[char]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some('*') => {
            let mut i = 0;
            loop {
                if glob(&p[1..], &s[i..]) {
                    return true;
                }
                if i < s.len() && s[i] != '/' {
                    i += 1;
                } else {
                    return false;
                }
            }
        }
        Some('?') => s.first().is_some_and(|c| *c != '/') && glob(&p[1..], &s[1..]),
        Some(c) => s.first() == Some(c) && glob(&p[1..], &s[1..]),
    }
}

/// Last matching rule wins, so `!.env.example` survives `.env.*`.
fn is_ignored(rules: &[Rule], rel: &str, is_dir: bool) -> bool {
    let name: Vec<char> = rel.rsplit('/').next().unwrap_or(rel).chars().collect();
    let full: Vec<char> = rel.chars().collect();
    let mut ignored = false;
    for r in rules {
        if r.dir_only && !is_dir {
            continue;
        }
        if glob(&r.pat, if r.anchored { &full } else { &name }) {
            ignored = !r.negate;
        }
    }
    ignored
}

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

struct Entry {
    name: String,
    path: PathBuf,
}

/// Tar of `cwd` (relative `/`-separated names; symlinks kept as links and never followed)
/// honouring `DEFAULT_IGNORE`, `<cwd>/.sbxignore` and `extra_ignore`.
// ponytail: buffers the whole tar in memory and skips sockets/fifos; stream the body into the
// request if a very large workspace upload ever needs it.
pub fn pack_workspace(cwd: impl AsRef<Path>, extra_ignore: &[&str]) -> Result<Vec<u8>> {
    let cwd = cwd.as_ref();
    let mut lines: Vec<String> = DEFAULT_IGNORE.iter().map(|s| s.to_string()).collect();
    if let Ok(b) = fs::read(cwd.join(".sbxignore")) {
        lines.extend(String::from_utf8_lossy(&b).lines().map(str::to_owned));
    }
    lines.extend(extra_ignore.iter().map(|s| s.to_string()));
    let rules: Vec<Rule> = lines.iter().filter_map(|l| compile(l)).collect();

    let mut b = tar::Builder::new(Vec::new());
    b.follow_symlinks(false);
    walk(cwd, "", &rules, &mut b)?;
    Ok(b.into_inner()?)
}

fn walk(dir: &Path, rel_dir: &str, rules: &[Rule], b: &mut tar::Builder<Vec<u8>>) -> Result<()> {
    let (mut link_dirs, mut files, mut dirs) = (Vec::new(), Vec::new(), Vec::new());
    for e in fs::read_dir(dir)? {
        let e = e?;
        let ft = e.file_type()?;
        let ent = Entry { name: e.file_name().to_string_lossy().into_owned(), path: e.path() };
        if ft.is_symlink() {
            // Like os.walk: a link to a directory is listed as a directory (for the dir-only
            // rules), a link to a file or a dangling one as a file. Either way it is stored as a link.
            if fs::metadata(&ent.path).is_ok_and(|m| m.is_dir()) {
                link_dirs.push(ent)
            } else {
                files.push(ent)
            }
        } else if ft.is_dir() {
            dirs.push(ent)
        } else if ft.is_file() {
            files.push(ent)
        }
    }
    for v in [&mut link_dirs, &mut files, &mut dirs] {
        v.sort_by(|a, b| a.name.cmp(&b.name));
    }
    for e in &link_dirs {
        let rel = join_rel(rel_dir, &e.name);
        if !is_ignored(rules, &rel, true) {
            b.append_path_with_name(&e.path, &rel)?;
        }
    }
    for e in &files {
        let rel = join_rel(rel_dir, &e.name);
        if !is_ignored(rules, &rel, false) {
            b.append_path_with_name(&e.path, &rel)?;
        }
    }
    for e in &dirs {
        let rel = join_rel(rel_dir, &e.name);
        if !is_ignored(rules, &rel, true) {
            walk(&e.path, &rel, rules, b)?;
        }
    }
    Ok(())
}

/// Lexical `..`/`.` resolution, no filesystem access (Python's `os.path.normpath`).
pub(crate) fn lexclean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !p.has_root() {
                    out.push("..");
                }
            }
            c => out.push(c.as_os_str()),
        }
    }
    out
}

/// Python's `os.path.abspath`: relative paths are taken from the current directory.
pub(crate) fn abspath(p: &Path) -> PathBuf {
    let full = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(p) };
    lexclean(&full)
}

/// Extracts a tar (as produced by `pack_workspace` / `download_tar`) into `dest`, refusing any
/// member, symlink target or hardlink target that would land outside it. Defence in depth: the
/// tar is the response to our own request, but a compromised host is exactly who this guards against.
pub fn unpack_tar(data: &[u8], dest: impl AsRef<Path>) -> Result<()> {
    let dest = dest.as_ref();
    fs::create_dir_all(dest)?;
    let dest_abs = abspath(dest);
    let mut ar = tar::Archive::new(data);
    for entry in ar.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.into_owned();
        let target = lexclean(&dest_abs.join(&name));
        if !target.starts_with(&dest_abs) {
            return Err(Error::Invalid(format!(
                "refusing to extract tar member outside destination: {}",
                name.display()
            )));
        }
        if let Some(link) = entry.link_name()? {
            let base = if entry.header().entry_type().is_hard_link() {
                dest_abs.clone()
            } else {
                target.parent().unwrap_or(&dest_abs).to_path_buf()
            };
            if !lexclean(&base.join(&link)).starts_with(&dest_abs) {
                return Err(Error::Invalid(format!(
                    "refusing to extract tar link outside destination: {} -> {}",
                    name.display(),
                    link.display()
                )));
            }
        }
        entry.unpack_in(dest)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "qafas-sdk-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn members(tar_bytes: &[u8]) -> Vec<String> {
        let mut ar = tar::Archive::new(tar_bytes);
        let mut v: Vec<String> =
            ar.entries().unwrap().map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn default_ignore_has_the_same_24_entries_as_python_and_typescript() {
        assert_eq!(DEFAULT_IGNORE.len(), 24);
        assert_eq!(DEFAULT_IGNORE[0], "node_modules");
        assert_eq!(DEFAULT_IGNORE[12], "!.env.example");
        assert_eq!(DEFAULT_IGNORE[23], "secrets*");
    }

    #[test]
    fn default_ignore_excludes_secrets_and_build_output() {
        let root = tmp("pack1");
        write(&root, "src/main.py", "x");
        write(&root, ".git/config", "x");
        write(&root, ".env", "OPENAI_API_KEY=sk-live");
        write(&root, ".env.example", "OPENAI_API_KEY=");
        write(&root, "node_modules/left-pad/index.js", "x");
        write(&root, "dist/bundle.js", "x");
        write(&root, "deploy/server.key", "x");
        write(&root, ".ssh/id_rsa", "x");
        write(&root, "credentials.json", "x");
        write(&root, "debug.log", "x");
        assert_eq!(members(&pack_workspace(&root, &[]).unwrap()), [".env.example", ".git/config", "src/main.py"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sbxignore_supports_anchored_dir_only_and_negated_rules() {
        let root = tmp("pack2");
        write(&root, "src/main.py", "x");
        write(&root, "secrets/db.json", "x"); // dir-only rule "secrets/" excludes the whole tree
        write(&root, "notes/keep.txt", "x"); // negated "!keep.txt" survives a broader exclude
        write(&root, "notes/draft.txt", "x");
        write(&root, "vendor/notes/draft.txt", "x"); // anchored "notes/draft.txt" must NOT match this nested copy
        write(&root, ".sbxignore", "secrets/\nnotes/draft.txt\n!keep.txt\n");
        assert_eq!(
            members(&pack_workspace(&root, &[]).unwrap()),
            [".sbxignore", "notes/keep.txt", "src/main.py", "vendor/notes/draft.txt"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn extra_ignore_comments_blank_lines_and_wildcards() {
        let root = tmp("pack3");
        write(&root, "a.tmp", "x");
        write(&root, "dir/b.tmp", "x");
        write(&root, "dir/c.txt", "x");
        write(&root, "dir/sub/d1.dat", "x");
        write(&root, "dir/sub/dd.dat", "x");
        let tar = pack_workspace(&root, &["# comment", "", "  ", "*.tmp", "/dir/sub/d?.dat", "!a.tmp"]).unwrap();
        // `*` and `?` never cross a `/`; the leading `/` anchors; `!a.tmp` re-includes (last match wins).
        assert_eq!(members(&tar), ["a.tmp", "dir/c.txt"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinks_travel_as_links_and_are_not_followed() {
        let root = tmp("pack4");
        fs::create_dir_all(root.join("real")).unwrap();
        write(&root, "real/f.txt", "x");
        symlink("real", root.join("linkdir")).unwrap();
        symlink("real/f.txt", root.join("linkfile")).unwrap();
        symlink("/etc/passwd", root.join("outside")).unwrap();
        let data = pack_workspace(&root, &[]).unwrap();
        let mut ar = tar::Archive::new(&data[..]);
        let mut got = std::collections::BTreeMap::new();
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            let link = e.link_name().unwrap().map(|l| l.to_string_lossy().into_owned());
            got.insert(e.path().unwrap().to_string_lossy().into_owned(), (e.header().entry_type().is_symlink(), link));
        }
        assert_eq!(got["linkdir"], (true, Some("real".into())));
        assert!(got["linkfile"].0);
        assert_eq!(got["outside"], (true, Some("/etc/passwd".into())));
        assert!(!got.contains_key("linkdir/f.txt"), "a symlinked directory is not descended into");
        assert!(got.contains_key("real/f.txt"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pack_then_unpack_round_trips_content_and_mode() {
        let root = tmp("pack5");
        write(&root, "sub/run.sh", "#!/bin/sh\n");
        fs::set_permissions(root.join("sub/run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("run.sh", root.join("sub/link")).unwrap();
        let dest = tmp("pack5-out").join("nested/out");
        unpack_tar(&pack_workspace(&root, &[]).unwrap(), &dest).unwrap();
        assert_eq!(fs::read_to_string(dest.join("sub/run.sh")).unwrap(), "#!/bin/sh\n");
        assert_eq!(fs::metadata(dest.join("sub/run.sh")).unwrap().permissions().mode() & 0o111, 0o111);
        assert_eq!(fs::read_link(dest.join("sub/link")).unwrap(), PathBuf::from("run.sh"));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(dest.parent().unwrap().parent().unwrap()).unwrap();
    }

    /// A tar with a raw header, because `tar::Builder` refuses to write `..` / absolute names.
    fn raw_tar(name: &str, kind: u8, link: &str) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        h[124..135].copy_from_slice(b"00000000000");
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h[155] = b' ';
        let mut v = h.to_vec();
        v.extend([0u8; 1024]);
        v
    }

    #[test]
    fn unpack_refuses_members_and_links_that_escape_the_destination() {
        let base = tmp("unpack");
        let dest = base.join("dest");
        for (name, kind, link) in [
            ("../x", b'0', ""),
            ("/tmp/qafas-sdk-abs", b'0', ""),
            ("a/../../y", b'0', ""),
            ("l", b'2', "../../etc"),
            ("l", b'2', "/etc/passwd"),
            ("h", b'1', "../outside"),
        ] {
            let err = unpack_tar(&raw_tar(name, kind, link), &dest).unwrap_err();
            assert!(matches!(err, Error::Invalid(_)), "{name} {link}: {err}");
            assert!(err.to_string().starts_with("refusing to extract tar "), "{err}");
        }
        assert_eq!(
            unpack_tar(&raw_tar("../x", b'0', ""), &dest).unwrap_err().to_string(),
            "refusing to extract tar member outside destination: ../x"
        );
        assert!(!base.join("x").exists() && !Path::new("/tmp/qafas-sdk-abs").exists());
        // A harmless relative symlink and "./" prefixes (what the guest's tar produces) are fine.
        unpack_tar(&raw_tar("./ok", b'2', "sub/target"), &dest).unwrap();
        assert!(dest.join("ok").symlink_metadata().is_ok());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn lexical_helpers() {
        assert_eq!(lexclean(Path::new("/a/b/../c/./d")), PathBuf::from("/a/c/d"));
        assert_eq!(lexclean(Path::new("/../a")), PathBuf::from("/a"));
        assert_eq!(lexclean(Path::new("a/../../b")), PathBuf::from("../b"));
    }
}
