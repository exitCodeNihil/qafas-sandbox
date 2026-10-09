//! TLS for the remote path (docs/security.md M31). `SBX_TLS=1` makes the whole
//! API HTTPS + WSS; the certificate is either the operator's
//! (`SBX_TLS_CERT`/`SBX_TLS_KEY`) or one this daemon generates for itself, once,
//! into `$SBX_STATE_DIR/tls`. Generated once and *kept*: the control plane and pi
//! pin the fingerprint, so a new certificate on every restart would mean a new
//! trust decision on every restart.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::config::Config;

pub struct Tls {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// SHA-256 of the leaf DER, lowercase hex, no separators.
    pub fingerprint: String,
}

/// The certificate the API serves: the operator's, or the generated one.
pub fn cert_path(cfg: &Config) -> PathBuf {
    match cfg.tls_cert.is_empty() {
        true => Path::new(&cfg.state_dir).join("tls/cert.pem"),
        false => PathBuf::from(&cfg.tls_cert),
    }
}

/// Reads the configured pair, or generates a self-signed one on first start.
pub fn load_or_generate(cfg: &Config) -> anyhow::Result<Tls> {
    let explicit = !cfg.tls_cert.is_empty() || !cfg.tls_key.is_empty();
    let (cert_path, key_path) = if explicit {
        anyhow::ensure!(
            !cfg.tls_cert.is_empty() && !cfg.tls_key.is_empty(),
            "SBX_TLS_CERT and SBX_TLS_KEY must be set together"
        );
        (PathBuf::from(&cfg.tls_cert), PathBuf::from(&cfg.tls_key))
    } else {
        (cert_path(cfg), Path::new(&cfg.state_dir).join("tls/key.pem"))
    };

    if !cert_path.is_file() || !key_path.is_file() {
        anyhow::ensure!(
            !explicit,
            "SBX_TLS_CERT/SBX_TLS_KEY point at files that do not exist: {} / {}",
            cert_path.display(),
            key_path.display()
        );
        generate(cfg, &cert_path, &key_path)?;
    }

    let cert_pem = std::fs::read(&cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let key_pem = std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let fingerprint = fingerprint(&cert_pem)?;
    tracing::info!(
        cert = %cert_path.display(),
        tls_fingerprint = %fingerprint,
        "TLS enabled; pin this fingerprint",
    );
    Ok(Tls { cert_pem, key_pem, fingerprint })
}

/// The names a client may legitimately dial this daemon by. A pinned client still
/// checks the name, so a certificate with the wrong SAN is a failure to connect,
/// not a warning.
fn san_names(cfg: &Config) -> Vec<String> {
    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    if let Ok(h) = nix::unistd::gethostname() {
        if let Some(h) = h.to_str() {
            names.push(h.to_string());
        }
    }
    if !cfg.listen.ip().is_unspecified() {
        names.push(cfg.listen.ip().to_string());
    }
    // `SBX_PUBLIC_URL` is what the control plane and pi will actually dial.
    if let Some(host) = cfg.public_url.split("//").nth(1) {
        let host = host.split('/').next().unwrap_or("").rsplit_once(':').map_or(host, |(h, _)| h);
        if !host.is_empty() {
            names.push(host.trim_matches(['[', ']']).to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn generate(cfg: &Config, cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    let names = san_names(cfg);
    let ck = rcgen::generate_simple_self_signed(names.clone())?;
    if let Some(dir) = cert_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating the TLS state directory {}", dir.display()))?;
    }
    std::fs::write(cert_path, ck.cert.pem())?;
    write_private(key_path, ck.signing_key.serialize_pem().as_bytes())?;
    tracing::warn!(
        cert = %cert_path.display(),
        sans = ?names,
        "generated a self-signed certificate; clients must pin its fingerprint or trust it as a CA file",
    );
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(bytes)
}

/// SHA-256 over the DER of the first certificate in the PEM: the same bytes
/// `openssl x509 -noout -fingerprint -sha256` hashes, minus the colons.
pub fn fingerprint(cert_pem: &[u8]) -> anyhow::Result<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(cert_pem).context("certificate is not PEM")?;
    let body = text
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(body, _)| body)
        .context("no CERTIFICATE block in the certificate file")?;
    let der = B64.decode(body.split_whitespace().collect::<String>())?;
    Ok(crate::backend::hex(&Sha256::digest(der)))
}

// ------------------------------------------------------------------ client

/// Where the distributions keep the system CA bundle (Debian/Ubuntu, RHEL/Rocky).
const SYSTEM_BUNDLES: [&str; 2] = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"];

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Who an `https://` control plane has to be: a certificate chaining to
/// `ca_file`, else to the system bundle. Neither present leaves no roots, so an
/// https `cp_url` fails to connect while plain http keeps working. A `ca_file`
/// that names nothing usable is a startup error, not an empty trust store.
pub fn client_config(ca_file: &str) -> anyhow::Result<ClientConfig> {
    let pem = match ca_file.is_empty() {
        true => SYSTEM_BUNDLES.iter().find_map(|p| std::fs::read(p).ok()).unwrap_or_default(),
        false => std::fs::read(ca_file).with_context(|| format!("reading ca_file {ca_file}"))?,
    };
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok));
    anyhow::ensure!(ca_file.is_empty() || added > 0, "ca_file {ca_file} holds no usable certificate");
    Ok(ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Trusts exactly one certificate, whatever name it is dialled by: the egress
/// proxy reaching this daemon's own listener at an address its certificate does
/// not list (`host.containers.internal`, or 127.0.0.1 behind an operator's cert).
pub fn pinned_config(cert_pem: &[u8]) -> anyhow::Result<ClientConfig> {
    let cert = CertificateDer::from_pem_slice(cert_pem).context("no certificate to pin")?;
    let p = provider();
    Ok(ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned(cert, p)))
        .with_no_client_auth())
}

#[derive(Debug)]
struct Pinned(CertificateDer<'static>, Arc<CryptoProvider>);

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match end_entity.as_ref() == self.0.as_ref() {
            true => Ok(ServerCertVerified::assertion()),
            false => Err(rustls::Error::General("not the pinned certificate".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.1.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.1.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;

    #[test]
    fn a_ca_file_with_no_certificate_is_an_error_and_an_unset_one_is_not() {
        let dir = std::env::temp_dir().join(format!("sbx-ca-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "not a certificate").unwrap();
        assert!(client_config(empty.to_str().unwrap()).is_err());
        assert!(client_config("/nonexistent/ca.pem").is_err());
        assert!(client_config("").is_ok(), "no ca_file: the system bundle, or no roots at all");

        let ck = rcgen::generate_simple_self_signed(vec!["cp.example".into()]).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, ck.cert.pem()).unwrap();
        assert!(client_config(ca.to_str().unwrap()).is_ok());
        assert!(pinned_config(ck.cert.pem().as_bytes()).is_ok());
        assert!(pinned_config(b"nothing").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Generate → read back → the fingerprint is the SHA-256 of the DER, and it
    /// survives a restart (the second load must not make a new certificate).
    #[test]
    fn self_signed_pair_is_generated_once_and_pins_stably() {
        let dir = std::env::temp_dir().join(format!("sbx-tls-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config::resolve(FileConfig::default());
        cfg.state_dir = dir.to_string_lossy().into_owned();

        let a = load_or_generate(&cfg).expect("first start generates");
        assert_eq!(a.fingerprint.len(), 64, "sha-256 as hex");
        assert!(a.cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        let b = load_or_generate(&cfg).expect("second start reuses");
        assert_eq!(a.fingerprint, b.fingerprint, "a restart must not invalidate the pin");

        // Independently: the fingerprint is over the DER, not the PEM text.
        let der = B64
            .decode(
                std::str::from_utf8(&a.cert_pem)
                    .unwrap()
                    .lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        assert_eq!(a.fingerprint, crate::backend::hex(&Sha256::digest(&der)));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("tls/key.pem")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the private key is not world-readable");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_operator_certificate_is_an_error_not_a_silent_self_signed_one() {
        let mut cfg = Config::resolve(FileConfig::default());
        cfg.tls_cert = "/nonexistent/cert.pem".into();
        cfg.tls_key = "/nonexistent/key.pem".into();
        assert!(load_or_generate(&cfg).is_err());
        cfg.tls_key = String::new();
        assert!(load_or_generate(&cfg).is_err(), "cert without key is a misconfiguration");
    }
}
