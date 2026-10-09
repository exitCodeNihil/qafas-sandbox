//! Minimal example: acquire a sandbox, run one command, print output, destroy.
//!
//!     SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev cargo run -p qafas-sandbox --example run_command
//!
//! The current directory is mounted/uploaded as the workspace; `SBX_CWD=` (empty) sends none, or
//! set it to another directory.

use qafas_sandbox::{acquire, AcquireOptions, ExecOptions};

#[tokio::main]
async fn main() -> qafas_sandbox::Result<()> {
    let cwd = match std::env::var("SBX_CWD") {
        Ok(c) if c.is_empty() => None,
        Ok(c) => Some(c),
        Err(_) => std::env::current_dir().ok().map(|d| d.to_string_lossy().into_owned()),
    };
    let sb = acquire(None, cwd.as_deref(), Some("sdk-rust-example"), AcquireOptions::new()).await?;
    println!("sandbox {} ({}/{:?}) workspace={}", sb.id, sb.backend, sb.isolation, sb.workspace_path);
    let result = sb.exec_buffered("uname -a && node -v", &ExecOptions::default()).await;
    sb.destroy().await?;
    let result = result?;
    print!("{}", result.stdout);
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    std::process::exit(result.exit);
}
