//! Live tests against a running qafas worker (`SANDBOX_URL`, `SBX_TOKEN`; default
//! `http://127.0.0.1:7700`). Each test prints a note and returns early when `/healthz` does not
//! answer, so `cargo test` stays green on a machine with no daemon. Never passes a local `cwd`
//! (the worker may be a remote VM that cannot see this filesystem) and always destroys what it creates.
//!
//!     SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev cargo test -p qafas-sandbox --test live -- --nocapture

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use futures_util::StreamExt;
use qafas_sandbox::{AcquireOptions, Error, ExecOptions, Sandbox, Snapshots, Stream};

fn url() -> String {
    std::env::var("SANDBOX_URL").unwrap_or_else(|_| "http://127.0.0.1:7700".into())
}

/// `GET /healthz` answers 200 and a token is set? (A plain blocking probe, so it needs no runtime
/// and no SDK call. Without `SBX_TOKEN` a worker that does answer would only 401 every test.)
fn daemon_up() -> bool {
    if std::env::var("SBX_TOKEN").unwrap_or_default().is_empty() {
        return false;
    }
    let u = url();
    let Some(rest) = u.strip_prefix("http://") else { return u.starts_with("https://") };
    let host = rest.split('/').next().unwrap_or(rest);
    use std::net::ToSocketAddrs;
    let Some(addr) = host.to_socket_addrs().ok().and_then(|mut a| a.next()) else { return false };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = write!(s, "GET /healthz HTTP/1.0\r\nHost: {host}\r\n\r\n");
    let mut head = String::new();
    let _ = s.take(64).read_to_string(&mut head);
    head.starts_with("HTTP/1.") && head.contains(" 200")
}

macro_rules! live {
    () => {
        if !daemon_up() {
            println!("SKIP: no qafas answering at {} or SBX_TOKEN unset (set SANDBOX_URL and SBX_TOKEN)", url());
            return;
        }
    };
}

/// Destroys the sandbox when the test ends, even by a failed assertion.
struct Guard(Sandbox);

impl Drop for Guard {
    fn drop(&mut self) {
        let sb = self.0.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                let _ = rt.block_on(sb.destroy());
            }
        })
        .join();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sandbox_end_to_end() {
    live!();
    let sb = Sandbox::create(
        Some(&url()),
        None,
        Some("sdk-rust-live"),
        AcquireOptions::new().size("mini").label("suite", "sdk-rust").env("QAFAS_LIVE", "yes"),
    )
    .await
    .unwrap();
    let guard = Guard(sb.clone());
    let sb = &guard.0;
    println!("sandbox {} backend={} isolation={:?} workspace={}", sb.id, sb.backend, sb.isolation, sb.workspace_path);
    assert!(sb.id.starts_with("sbx_"));
    assert_eq!(sb.size.as_deref(), Some("mini"));
    assert!(sb.limits.is_some() && sb.create_info.is_some());

    // exec_buffered; the sandbox's env reaches the command
    let r = sb
        .exec_buffered("echo hello; echo $QAFAS_LIVE; pwd", &ExecOptions::new().tool_call_id("tc-live-1"))
        .await
        .unwrap();
    assert_eq!(r.exit, 0, "{r:?}");
    assert!(r.stdout.contains("hello") && r.stdout.contains("yes") && r.stdout.contains(&sb.workspace_path), "{r:?}");

    // streaming exec with on_output
    let mut chunks: Vec<(Stream, String)> = vec![];
    let r = sb
        .exec_with(
            "for i in 1 2 3; do echo line$i; sleep 0.1; done; echo oops >&2; exit 4",
            &ExecOptions::default(),
            |c, s| chunks.push((s, String::from_utf8_lossy(c).into_owned())),
        )
        .await
        .unwrap();
    assert_eq!(r.exit, 4, "{r:?}");
    assert!(r.stdout.contains("line1") && r.stdout.contains("line3") && r.stderr.contains("oops"), "{r:?}");
    assert!(
        chunks.iter().any(|(s, c)| *s == Stream::Stdout && c.contains("line"))
            && chunks.iter().any(|(s, c)| *s == Stream::Stderr && c.contains("oops")),
        "{chunks:?}"
    );
    let r = sb.exec("sleep 5", &ExecOptions::new().timeout(Duration::from_millis(300))).await.unwrap();
    assert!(r.timed_out, "{r:?}");

    // fs
    let ws = sb.workspace_path.clone();
    let f = format!("{ws}/sdk-rust/hello.txt");
    sb.mkdir(&format!("{ws}/sdk-rust")).await.unwrap();
    sb.write_file(&f, "roundtrip-ok").await.unwrap();
    assert_eq!(sb.read_file(&f).await.unwrap(), b"roundtrip-ok");
    let st = sb.stat(&f).await.unwrap();
    assert!(!st.is_dir && st.size == 12, "{st:?}");
    assert!(sb.stat(&format!("{ws}/sdk-rust")).await.unwrap().is_dir);
    assert!(sb.listdir(&format!("{ws}/sdk-rust")).await.unwrap().contains(&"hello.txt".to_string()));
    assert!(matches!(sb.read_file(&format!("{ws}/sdk-rust/nope")).await.unwrap_err(), Error::NotFound(_)));
    assert!(matches!(sb.stat(&format!("{ws}/sdk-rust/nope")).await.unwrap_err(), Error::NotFound(_)));
    assert!(matches!(sb.listdir(&format!("{ws}/sdk-rust/nope")).await.unwrap_err(), Error::NotFound(_)));

    // upload + download of a small directory (and a file), inside the workspace
    let tmp = std::env::temp_dir().join(format!("qafas-sdk-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("src/sub")).unwrap();
    std::fs::write(tmp.join("src/a.txt"), "alpha").unwrap();
    std::fs::write(tmp.join("src/sub/b.txt"), "beta").unwrap();
    std::fs::write(tmp.join("src/.env"), "SECRET=never-uploaded").unwrap();
    let remote_dir = format!("{ws}/sdk-rust/updir");
    sb.upload(tmp.join("src"), &remote_dir, false).await.unwrap();
    let names = sb.listdir(&remote_dir).await.unwrap();
    assert!(
        names.contains(&"a.txt".into()) && names.contains(&"sub".into()) && !names.contains(&".env".into()),
        "{names:?}"
    );
    sb.upload(tmp.join("src/a.txt"), &format!("{ws}/sdk-rust/a-copy.txt"), false).await.unwrap();
    sb.download(&remote_dir, tmp.join("back"), false).await.unwrap();
    assert_eq!(std::fs::read_to_string(tmp.join("back/a.txt")).unwrap(), "alpha");
    assert_eq!(std::fs::read_to_string(tmp.join("back/sub/b.txt")).unwrap(), "beta");
    sb.download(&format!("{ws}/sdk-rust/a-copy.txt"), tmp.join("out/dl/a.txt"), false).await.unwrap();
    assert_eq!(std::fs::read_to_string(tmp.join("out/dl/a.txt")).unwrap(), "alpha");
    // download_tar / unpack_tar
    let tar = sb.download_tar(&remote_dir).await.unwrap();
    qafas_sandbox::unpack_tar(&tar, tmp.join("tar")).unwrap();
    assert_eq!(std::fs::read_to_string(tmp.join("tar/sub/b.txt")).unwrap(), "beta");
    assert!(matches!(sb.upload(&tmp, "/etc/qafas-sdk", false).await.unwrap_err(), Error::Invalid(_)));
    std::fs::remove_dir_all(&tmp).unwrap();

    // processes, info, preview
    assert!(sb.processes().await.unwrap().iter().all(|p| p.is_object()));
    let info = sb.info().await.unwrap();
    assert_eq!(info.id, sb.id);
    assert_eq!(info.pi_session, "sdk-rust-live");
    assert_eq!(info.labels.get("suite").map(String::as_str), Some("sdk-rust"));
    let pv = sb.preview(8080, Some(60)).await.unwrap();
    assert!(pv.url.contains("/preview/") && pv.port == 8080 && !pv.token.is_empty(), "{pv:?}");

    // a session: sync exec, async exec + logs + command
    let s = sb.create_session(None, Some(&ws), &BTreeMap::new()).await.unwrap();
    let c = s.exec("export SDK_VAR=kept; echo sync-out", None).await.unwrap();
    assert_eq!((c.exit, c.stdout.as_deref()), (Some(0), Some("sync-out\n")), "{c:?}");
    let c = s.exec("echo $SDK_VAR", None).await.unwrap();
    assert_eq!(c.stdout.as_deref(), Some("kept\n"), "the shell persists between commands");
    let a = s.exec_async("echo first; sleep 1", None).await.unwrap();
    assert!(!a.command_id.is_empty());
    let mut seen = String::new();
    let done = s.logs(&a.command_id, |c, _| seen.push_str(&String::from_utf8_lossy(c))).await.unwrap();
    // Only stdout is asserted: a session command's trailing stderr can be lost server-side (the
    // guest reads stderr in a separate task and the command can finish first; observed live).
    assert!(seen.contains("first") && done.stdout.as_deref() == Some("first\n"), "{seen:?} {done:?}");
    assert_eq!(done.exit, Some(0), "{done:?}");
    assert_eq!(s.command(&a.command_id).await.unwrap().state, Some(qafas_sandbox::CommandState::Done));
    s.delete().await.unwrap();
    s.delete().await.unwrap();

    // events: at least one frame for this sandbox while a command runs
    let mut events = sb.events().await.unwrap();
    sb.exec_buffered("echo for-events", &ExecOptions::new().tool_call_id("tc-live-events")).await.unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(15), events.next())
        .await
        .expect("no event within 15 s")
        .expect("stream ended")
        .unwrap();
    assert_eq!(ev.sandbox_id, sb.id);
    println!("event: {} {}", ev.r#type.as_str(), ev.tool_call_id);
    drop(events);

    // lifecycle verbs: the vm tier answers 409 (remote tier only); assert the error type
    for res in [sb.stop().await, sb.archive().await] {
        match res {
            Ok(()) => {}
            Err(Error::Http { status, .. }) => assert!(status >= 400),
            Err(e) => panic!("expected an HTTP error, got {e:?}"),
        }
    }

    // destroy twice: the second is a no-op
    sb.destroy().await.unwrap();
    sb.destroy().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshots_list_and_get() {
    live!();
    let snaps = Snapshots::new(&url(), None);
    let all = snaps.list().await.unwrap();
    assert!(all.iter().any(|s| s.name == "base"), "{:?}", all.iter().map(|s| &s.name).collect::<Vec<_>>());
    let base = snaps.get("base").await.unwrap();
    assert_eq!(base.name, "base");
    println!("snapshot base: {:?} kind={}", base.state, base.kind);
    assert!(matches!(snaps.get("no-such-snapshot-sdk-rust").await.unwrap_err(), Error::Http { status: 404, .. }));
    snaps.delete("no-such-snapshot-sdk-rust").await.unwrap();
}
