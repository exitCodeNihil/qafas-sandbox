//! `qafas doctor --json` is read by installers and provisioning scripts: stdout
//! must be the JSON document and nothing else, whatever `RUST_LOG` says. The
//! daemon's own logs stay on stdout, so only `doctor` moves them to stderr.

use std::process::Command;

#[test]
fn doctor_json_leaves_stdout_to_the_json_document() {
    // A malformed SBX_LISTEN makes config loading log an error, so there is a
    // log line to keep out of stdout on any host, whatever its tiers.
    let out = Command::new(env!("CARGO_BIN_EXE_qafas"))
        .args(["doctor", "--json"])
        .env("RUST_LOG", "info")
        .env("SBX_LISTEN", "not-an-address")
        .env_remove("SBX_LOG_PRETTY")
        .output()
        .expect("run qafas doctor --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The exit code is 1 on a host that serves no tier; the document is printed either way.
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not JSON ({e}):\n{stdout}"));
    assert!(doc["checks"].is_array() && doc["caps"].is_object(), "unexpected document: {doc}");
    // The log line was not lost, it moved.
    assert!(stderr.contains("SBX_LISTEN"), "expected the config log on stderr, got:\n{stderr}");
}
