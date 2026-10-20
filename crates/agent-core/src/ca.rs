//! `POST /ca {pem}` (protocol §2, v5.4, D34): the egress proxy's CA, written
//! where this sandbox's TLS clients are told to look. qafas calls it when a
//! route applies to the sandbox, before handing it out and again on a wake.
//!
//! `ca.pem` is the CA alone (`NODE_EXTRA_CA_CERTS` adds it to Node's store);
//! `bundle.pem` is the system bundle plus the CA (`SSL_CERT_FILE` and friends
//! replace the store, so every other host must still verify). Both are public
//! material: the CA's key never leaves the egress proxy.

use std::path::{Path, PathBuf};

use axum::response::{IntoResponse, Response};

/// Where a guest keeps it. The vm tier's `/tmp` is the container's own tmpfs,
/// a microVM's is its own.
pub const CA_DIR: &str = "/tmp/qafas-ca";

/// The distributions' system bundles (Debian/Ubuntu, RHEL/Rocky, macOS and
/// Alpine), first found wins.
pub const SYSTEM_BUNDLES: [&str; 3] =
    ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"];

const MAX_PEM: usize = 64 * 1024;

/// `CA_DIR`, except on the native tier: its `/tmp` is the host's, shared by
/// every native sandbox, so its CA goes in its own scratch (`SBX_SCRATCH`).
pub fn ca_dir() -> PathBuf {
    match std::env::var("SBX_SCRATCH").ok().filter(|s| !s.is_empty()) {
        Some(s) => Path::new(&s).join("qafas-ca"),
        None => PathBuf::from(CA_DIR),
    }
}

#[derive(serde::Deserialize)]
struct CaReq {
    pem: String,
}

pub async fn handler(body: axum::body::Bytes) -> Response {
    let req: CaReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match install(&ca_dir(), &req.pem) {
        Ok(()) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Writes `ca.pem` and `bundle.pem` into `dir` (0755, files 0644), each
/// atomically, so a client never reads half a bundle. Idempotent. Only a
/// certificate is accepted: a key handed here by mistake is refused, not
/// planted where the sandbox reads.
pub fn install(dir: &Path, pem: &str) -> Result<(), String> {
    if pem.len() > MAX_PEM || !pem.contains("-----BEGIN CERTIFICATE-----") || pem.contains("PRIVATE KEY") {
        return Err("pem must be one or more certificates and nothing else".into());
    }
    own_dir(dir)?;
    let system = SYSTEM_BUNDLES.iter().find_map(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    let pem = format!("{}\n", pem.trim_end());
    let bundle = match system.is_empty() {
        true => pem.clone(),
        false => format!("{}\n{pem}", system.trim_end()),
    };
    write_atomic(&dir.join("ca.pem"), pem.as_bytes())?;
    write_atomic(&dir.join("bundle.pem"), bundle.as_bytes())
}

/// The directory, made if missing; refused if what is there is a link or not
/// ours. A microVM's agent is root and `/tmp` is the sandbox's too: a link
/// planted there must not steer where root writes.
fn own_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && m.uid() == nix::unistd::geteuid().as_raw() => {}
        Ok(_) => return Err(format!("{} is not a directory this agent owns", dir.display())),
        Err(_) => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?,
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(|e| format!("{}: {e}", dir.display()))
}

/// A new file next to `path` (never following a link), then a rename over it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(err)?;
    f.write_all(bytes).map_err(err)?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n";

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sbx-ca-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Both files, the right modes, the system bundle kept in front of ours,
    /// and the same result on a second call.
    #[test]
    fn writes_the_ca_and_a_bundle_with_the_system_roots_in_it() {
        let d = dir("ok");
        install(&d.join("qafas-ca"), PEM).unwrap();
        install(&d.join("qafas-ca"), PEM).expect("idempotent");
        let ca = std::fs::read_to_string(d.join("qafas-ca/ca.pem")).unwrap();
        let bundle = std::fs::read_to_string(d.join("qafas-ca/bundle.pem")).unwrap();
        assert_eq!(ca, PEM);
        assert!(bundle.ends_with(PEM), "ours is in the bundle");
        if let Some(sys) = SYSTEM_BUNDLES.iter().find_map(|p| std::fs::read_to_string(p).ok()) {
            assert!(bundle.starts_with(sys.trim_end()), "the system roots still verify everything else");
        }
        let mode = |p: &str| std::fs::metadata(d.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode("qafas-ca"), mode("qafas-ca/ca.pem"), mode("qafas-ca/bundle.pem")), (0o755, 0o644, 0o644));
        let left: Vec<_> = std::fs::read_dir(d.join("qafas-ca")).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left.len(), 2, "no temporary file left behind: {left:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_a_certificate_is_taken_and_a_planted_link_is_refused() {
        let d = dir("bad");
        std::fs::create_dir_all(&d).unwrap();
        assert!(install(&d.join("x"), "not a pem").is_err());
        let key = format!("{PEM}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        assert!(install(&d.join("x"), &key).is_err(), "a key is never written where the sandbox reads");
        assert!(!d.join("x").exists());
        // A link where the directory should be: root must not write through it.
        let target = d.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, d.join("link")).unwrap();
        assert!(install(&d.join("link"), PEM).is_err());
        assert!(!target.join("ca.pem").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_native_tier_keeps_its_ca_in_its_own_scratch() {
        // Read from this process's environment, which the shim's is: no
        // SBX_SCRATCH here means a guest.
        if std::env::var_os("SBX_SCRATCH").is_none() {
            assert_eq!(ca_dir(), PathBuf::from(CA_DIR));
        }
    }
}
