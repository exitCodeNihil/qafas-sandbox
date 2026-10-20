//! The per-sandbox agent token must not be readable from `/proc/<pid>/environ`
//! (a sandboxed process shares the agent's uid and reads `/proc/1/environ`), and
//! the agent must still enforce it. `scrub_initial_env` alone only covers kernels
//! that report `env_start`/`env_end` (gVisor reports 0), so the check here is the
//! stronger one: after start-up the variable is not in the block at all, not even
//! overwritten. Spawns the real binary; it binds the fixed agent port, so this is
//! the only test in the crate that does.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One HTTP/1.1 GET over a raw socket; returns the status code.
fn get(path: &str, token: Option<&str>) -> std::io::Result<u16> {
    let mut s = TcpStream::connect(("127.0.0.1", proto::GUEST_AGENT_PORT))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let hdr = token.map(|t| format!("{}: {t}\r\n", proto::HDR_AGENT_TOKEN)).unwrap_or_default();
    write!(s, "GET {path} HTTP/1.1\r\nHost: agent\r\nConnection: close\r\n{hdr}\r\n")?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    out.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("no status line in {out:?}")))
}

#[test]
fn the_token_is_in_no_initial_environment_and_still_enforced() {
    const TOKEN: &str = "secrettoken";
    let dir = std::env::temp_dir().join(format!("sbx-agent-token-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Not PID 1 and not root-booting, so this takes the container path, the one
    // that carries a token.
    let child = Command::new(env!("CARGO_BIN_EXE_guest-agent"))
        .env_clear()
        .env("HOME", &dir)
        .env("SBX_WORKSPACE", &dir)
        .env("SBX_ID", "token-test")
        .env("SBX_AGENT_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn guest-agent");
    let pid = child.id();
    let _agent = Agent(child);

    // /healthz is open; it answers only once the process has re-exec'd and bound.
    let up = Instant::now();
    while get("/healthz", None).ok() != Some(200) {
        assert!(up.elapsed() < Duration::from_secs(20), "guest-agent never answered /healthz (port busy?)");
        std::thread::sleep(Duration::from_millis(50));
    }

    // What a process in the sandbox can read: the initial block, byte for byte.
    let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
    let environ = String::from_utf8_lossy(&environ);
    assert!(!environ.contains(TOKEN), "token value in /proc/{pid}/environ: {environ:?}");
    assert!(!environ.contains("AGENT_TOKEN"), "token name left in /proc/{pid}/environ: {environ:?}");

    // The memfd that carried it across the exec is closed again.
    for e in std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap().flatten() {
        let link = std::fs::read_link(e.path()).unwrap_or_default();
        assert!(!link.to_string_lossy().starts_with("/memfd:"), "memfd still open: {link:?}");
    }

    // Still guarded: no header and a wrong header are refused, the right one is served.
    let stat = format!("/fs/stat?path={}", dir.display());
    assert_eq!(get(&stat, None).unwrap(), 401);
    assert_eq!(get(&stat, Some("wrong")).unwrap(), 401);
    assert_eq!(get(&stat, Some(TOKEN)).unwrap(), 200);
    let _ = std::fs::remove_dir_all(&dir);
}
