//! Unit tests against a tiny in-process HTTP server (the Rust twin of the Python tests'
//! `FakeServer`): the v3/v4/v5 surface and the workspace guard, no daemon needed.

use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, service::service_fn, Response};
use hyper_util::rt::TokioIo;

use super::*;
use crate::{CommandState, SandboxState, SnapshotState};

struct Req {
    method: String,
    target: String,
    headers: hyper::HeaderMap,
    body: Vec<u8>,
}

impl Req {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.get(k).map(|v| v.to_str().unwrap())
    }
}

type Reply = (u16, Vec<u8>);
type Handler = Box<dyn Fn(&Req) -> Reply + Send + Sync>;

fn js(status: u16, v: Value) -> Reply {
    (status, if v.is_null() { vec![] } else { v.to_string().into_bytes() })
}

fn fixed(status: u16, v: Value) -> Handler {
    Box::new(move |_| js(status, v.clone()))
}

struct Fake {
    url: String,
    reqs: Arc<Mutex<Vec<Req>>>,
}

impl Fake {
    /// `routes` gets the server's own URL (create replies point back at it).
    async fn start(routes: impl FnOnce(&str) -> Vec<(String, Handler)>) -> Fake {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let routes: Arc<Vec<(String, Handler)>> = Arc::new(routes(&url));
        let reqs: Arc<Mutex<Vec<Req>>> = Arc::default();
        let log = reqs.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (routes, log) = (routes.clone(), log.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |r: hyper::Request<hyper::body::Incoming>| {
                        let (routes, log) = (routes.clone(), log.clone());
                        async move {
                            let (parts, body) = r.into_parts();
                            let req = Req {
                                method: parts.method.to_string(),
                                target: parts.uri.path_and_query().unwrap().to_string(),
                                headers: parts.headers,
                                body: body.collect().await.unwrap().to_bytes().to_vec(),
                            };
                            let key = format!("{} {}", req.method, req.target);
                            let (status, body) = match routes.iter().find(|(k, _)| *k == key) {
                                Some((_, h)) => h(&req),
                                None => (404, b"not found".to_vec()),
                            };
                            log.lock().unwrap().push(req);
                            Ok::<_, std::convert::Infallible>(
                                Response::builder().status(status).body(Full::new(Bytes::from(body))).unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
                });
            }
        });
        Fake { url, reqs }
    }

    /// "METHOD target" of everything seen, minus the healthz probes.
    fn seen(&self) -> Vec<String> {
        self.reqs
            .lock()
            .unwrap()
            .iter()
            .map(|r| format!("{} {}", r.method, r.target))
            .filter(|k| !k.contains("/healthz"))
            .collect()
    }

    fn last(&self, key: &str) -> Value {
        self.reqs.lock().unwrap().iter().rev().find(|r| format!("{} {}", r.method, r.target) == key).unwrap().json()
    }
}

fn route(k: &str, h: Handler) -> (String, Handler) {
    (k.to_owned(), h)
}

fn sb_at(url: &str) -> Sandbox {
    Sandbox::new(format!("{url}/sandboxes/sbx_1/agent"), "tok", "sess", "sbx_1", "b", "/w")
}

fn create_reply(url: &str, id: &str, isolation: &str) -> Value {
    json!({"id": id, "endpoint": format!("{url}/sandboxes/{id}/agent"), "token": "scoped", "backend": "podman",
           "workspace_path": "/w", "expires_at": "later", "isolation": isolation})
}

fn info_json(id: &str) -> Value {
    json!({"id": id, "state": "ready", "backend": "b", "template": "t", "workspace_path": "/w", "pi_session": "s",
           "created_at": "t", "endpoint": "e", "name": "my-box"})
}

fn cp_health() -> (String, Handler) {
    route("GET /healthz", fixed(200, json!({"ok": true}))) // no `backend`: control-plane shape
}

// ---------------------------------------------------------------- v4: runtime naming

#[test]
fn runtime_isolation_mapping() {
    assert_eq!(runtime_to_isolation(Some("process")).unwrap(), Some("native"));
    assert_eq!(runtime_to_isolation(Some("docker")).unwrap(), Some("vm"));
    assert_eq!(runtime_to_isolation(Some("firecracker")).unwrap(), Some("remote"));
    assert_eq!(runtime_to_isolation(Some("auto")).unwrap(), None);
    assert_eq!(runtime_to_isolation(None).unwrap(), None);
    let e = runtime_to_isolation(Some("kubernetes")).unwrap_err();
    assert!(matches!(e, Error::Invalid(_)));
    assert_eq!(e.to_string(), r#"invalid runtime "kubernetes": expected one of auto|process|docker|firecracker"#);
    assert_eq!(isolation_to_runtime(Some("native")), Some("process"));
    assert_eq!(isolation_to_runtime(Some("vm")), Some("docker"));
    assert_eq!(isolation_to_runtime(Some("remote")), Some("firecracker"));
    assert_eq!(isolation_to_runtime(None), None);
    assert_eq!(control_plane_token(Some("key")), "key");
}

#[tokio::test]
async fn acquire_rejects_a_bad_runtime_before_any_request() {
    let e =
        acquire(Some("http://127.0.0.1:1"), None, None, AcquireOptions::new().runtime("kubernetes")).await.unwrap_err();
    // healthz is probed first (like Python), so this is the connect error; the runtime error comes
    // once a server answers.
    assert!(matches!(e, Error::Transport(_)), "{e}");
    let fake = Fake::start(|_| vec![cp_health()]).await;
    let e = acquire(Some(&fake.url), None, None, AcquireOptions::new().runtime("kubernetes")).await.unwrap_err();
    assert!(e.to_string().contains("expected one of auto|process|docker|firecracker"), "{e}");
    assert_eq!(fake.seen(), Vec::<String>::new(), "nothing was created");
}

// ---------------------------------------------------------------- v3: lifecycle, preview, sessions

#[tokio::test]
async fn lifecycle_info_preview() {
    let fake = Fake::start(|url| {
        let u = url.to_owned();
        vec![
            route("POST /sandboxes/sbx_1/stop", fixed(204, Value::Null)),
            route("POST /sandboxes/sbx_1/start", fixed(200, info_json("sbx_1"))),
            route("POST /sandboxes/sbx_1/pause", fixed(204, Value::Null)),
            route("POST /sandboxes/sbx_1/resume", fixed(204, Value::Null)),
            route("POST /sandboxes/sbx_1/archive", fixed(204, Value::Null)),
            route("GET /sandboxes/sbx_1", fixed(200, info_json("sbx_1"))),
            route("POST /sandboxes/sbx_1/preview", Box::new(move |r| {
                js(200, json!({"url": format!("{u}/preview/sbx_1/8080/"), "token": "tok", "port": r.json()["port"], "expires_at": "2026-01-01T00:00:00Z"}))
            })),
        ]
    })
    .await;
    let sb = sb_at(&fake.url);
    sb.stop().await.unwrap();
    assert_eq!(sb.start().await.unwrap().state, SandboxState::Ready);
    sb.pause().await.unwrap();
    sb.resume().await.unwrap();
    sb.archive().await.unwrap();
    assert_eq!(sb.info().await.unwrap().name, "my-box");
    let p = sb.preview(8080, Some(60)).await.unwrap();
    assert_eq!(p.port, 8080);
    assert!(p.url.ends_with("/preview/sbx_1/8080/"));
    assert_eq!(fake.last("POST /sandboxes/sbx_1/preview"), json!({"port": 8080, "ttl_secs": 60}));
}

#[tokio::test]
async fn sessions() {
    let base = "/sandboxes/sbx_1/agent/sessions";
    let fake = Fake::start(|_| {
        vec![
            route(&format!("POST {base}"), fixed(201, json!({"id": "sess_1"}))),
            route(&format!("POST {base}/sess_1/exec"), Box::new(|r| match r.json().get("async") {
                // sync: the reply has no cmd/state/started_at (docs/protocol.md section 3a); async: command_id only
                None => js(200, json!({"command_id": "c1", "exit": 0, "stdout": "hi\n", "stderr": ""})),
                Some(_) => js(202, json!({"command_id": "c2"})),
            })),
            route(&format!("GET {base}/sess_1/commands/c1"), fixed(200, json!({"command_id": "c1", "cmd": "echo hi", "state": "done", "exit": 0, "started_at": "t", "stdout": "hi\n"}))),
            route(&format!("POST {base}/sess_1/commands/c1/input"), fixed(204, Value::Null)),
            route(&format!("DELETE {base}/sess_1"), fixed(204, Value::Null)),
        ]
    })
    .await;
    let sb = sb_at(&fake.url);
    let s = sb.create_session(None, Some("/w"), &BTreeMap::new()).await.unwrap();
    assert_eq!(s.id, "sess_1");
    assert_eq!(fake.last(&format!("POST {base}")), json!({"cwd": "/w"}));
    let c = s.exec("echo hi", Some(500)).await.unwrap();
    assert_eq!((c.exit, c.stdout.as_deref(), c.state), (Some(0), Some("hi\n"), None));
    assert_eq!(fake.last(&format!("POST {base}/sess_1/exec")), json!({"cmd": "echo hi", "timeout_ms": 500}));
    let a = s.exec_async("sleep 1", None).await.unwrap();
    assert_eq!((a.command_id.as_str(), a.exit), ("c2", None));
    assert_eq!(fake.last(&format!("POST {base}/sess_1/exec")), json!({"cmd": "sleep 1", "async": true}));
    let got = s.command("c1").await.unwrap();
    assert_eq!((got.command_id.as_str(), got.state), ("c1", Some(CommandState::Done)));
    s.input("c1", "aGVsbG8=").await.unwrap();
    assert_eq!(fake.last(&format!("POST {base}/sess_1/commands/c1/input")), json!({"data": "aGVsbG8="}));
    s.delete().await.unwrap();
    s.delete().await.unwrap();
}

#[tokio::test]
async fn typed_error_carries_status_and_server_text() {
    let fake = Fake::start(|_| {
        vec![route("POST /sandboxes/sbx_1/stop", fixed(409, json!({"error": "lifecycle needs the remote tier"})))]
    })
    .await;
    let e = sb_at(&fake.url).stop().await.unwrap_err();
    assert!(matches!(&e, Error::Http { status: 409, .. }), "{e:?}");
    assert_eq!(e.to_string(), "HTTP 409: lifecycle needs the remote tier");
}

// ---------------------------------------------------------------- headers, fs, destroy

#[tokio::test]
async fn headers_fs_and_destroy() {
    let fake = Fake::start(|_| {
        vec![
            route(
                "POST /sandboxes/sbx_1/agent/exec",
                fixed(200, json!({"exit": 3, "stdout": "o", "stderr": "e", "duration_ms": 7, "truncated": true})),
            ),
            route(
                "GET /sandboxes/sbx_1/agent/fs/read?path=/w/a%20b/%C3%BC.txt",
                Box::new(|_| (200, b"bytes\x00".to_vec())),
            ),
            route("GET /sandboxes/sbx_1/agent/fs/read?path=/w/missing", fixed(404, json!({"error": "nope"}))),
            route("GET /sandboxes/sbx_1/agent/fs/read?path=/w/boom", fixed(500, json!({"error": "disk"}))),
            route(
                "GET /sandboxes/sbx_1/agent/fs/stat?path=/w/d",
                fixed(200, json!({"is_dir": true, "size": 4096, "mode": 493, "mtime": "t"})),
            ),
            route("GET /sandboxes/sbx_1/agent/fs/list?path=/w/d", fixed(200, json!(["a", "b"]))),
            route("GET /sandboxes/sbx_1/agent/fs/list?path=/w/none", fixed(404, json!({}))),
            route("PUT /sandboxes/sbx_1/agent/fs/write?path=/w/f", fixed(204, Value::Null)),
            route("POST /sandboxes/sbx_1/agent/fs/mkdir", fixed(204, Value::Null)),
            route("GET /sandboxes/sbx_1/processes", fixed(200, json!([{"pid": 1, "argv": ["sh"]}]))),
            route("DELETE /sandboxes/sbx_1", fixed(404, json!({}))),
        ]
    })
    .await;
    let sb = sb_at(&fake.url);
    let o = ExecOptions::new().cwd("/w/sub").env("A", "1").timeout(Duration::from_millis(1500)).tool_call_id("tc1");
    let r = sb.exec_buffered("echo", &o).await.unwrap();
    assert_eq!(
        r,
        ExecResult {
            exit: 3,
            stdout: "o".into(),
            stderr: "e".into(),
            duration_ms: 7,
            truncated: true,
            timed_out: false
        }
    );
    assert_eq!(
        fake.last("POST /sandboxes/sbx_1/agent/exec"),
        json!({"cmd": "echo", "cwd": "/w/sub", "env": {"A": "1"}, "timeout_ms": 1500})
    );
    // no cwd given: the workspace
    sb.exec_buffered("pwd", &ExecOptions::default()).await.unwrap();
    assert_eq!(fake.last("POST /sandboxes/sbx_1/agent/exec"), json!({"cmd": "pwd", "cwd": "/w"}));
    {
        let reqs = fake.reqs.lock().unwrap();
        let h = &reqs[0];
        assert_eq!(h.header("authorization"), Some("Bearer tok"));
        assert_eq!(h.header("x-pi-session"), Some("sess"));
        assert_eq!(h.header("x-tool-call-id"), Some("tc1"));
        assert_eq!(reqs[1].header("x-tool-call-id"), Some(""));
    }

    assert_eq!(sb.read_file("/w/a b/ü.txt").await.unwrap(), b"bytes\x00");
    assert!(matches!(sb.read_file("/w/missing").await.unwrap_err(), Error::NotFound(p) if p == "/w/missing"));
    assert!(matches!(sb.read_file("/w/boom").await.unwrap_err(), Error::Http { status: 500, .. }));
    let st = sb.stat("/w/d").await.unwrap();
    assert!(st.is_dir && st.size == 4096 && st.mode == 493);
    assert_eq!(sb.listdir("/w/d").await.unwrap(), ["a", "b"]);
    assert!(matches!(sb.listdir("/w/none").await.unwrap_err(), Error::NotFound(_)));
    sb.write_file("/w/f", "text").await.unwrap();
    sb.upload_bytes("/w/f", b"raw".to_vec()).await.unwrap();
    sb.mkdir("/w/d").await.unwrap();
    assert_eq!(fake.last("POST /sandboxes/sbx_1/agent/fs/mkdir"), json!({"path": "/w/d"}));
    assert_eq!(sb.processes().await.unwrap()[0]["pid"], 1);

    // destroy sends only Authorization, and a 404 is success (twice is a no-op)
    sb.destroy().await.unwrap();
    sb.delete().await.unwrap();
    let reqs = fake.reqs.lock().unwrap();
    let d = reqs.iter().find(|r| r.method == "DELETE").unwrap();
    assert_eq!(d.header("authorization"), Some("Bearer tok"));
    assert!(d.header("x-pi-session").is_none() && d.header("x-tool-call-id").is_none());
    let w = reqs.iter().find(|r| r.method == "PUT").unwrap();
    assert_eq!(w.body, b"text");
}

#[test]
fn cdp_url_and_roots() {
    let sb = Sandbox::new("https://h:7700/sandboxes/sbx_1/agent", "t", "s", "sbx_1", "b", "/w");
    assert_eq!(sb.cdp_url(), "wss://h:7700/sandboxes/sbx_1/agent/browser/cdp");
    assert_eq!(agent_base(&sb.endpoint), "https://h:7700/sandboxes/sbx_1");
    assert_eq!(qafas_root(&sb.endpoint), "https://h:7700");
    assert_eq!(agent_base("http://h/other"), "http://h/other");
    assert_eq!(qafas_root("http://h/other"), "http://h/other");
}

// ---------------------------------------------------------------- acquire

#[tokio::test]
async fn acquire_serialises_v3_fields_and_snapshot_aliases_template() {
    let fake = Fake::start(|url| {
        let u = url.to_owned();
        vec![cp_health(), route("POST /api/sandboxes", Box::new(move |_| js(201, create_reply(&u, "sbx_1", "vm"))))]
    })
    .await;
    let opts = AcquireOptions::new()
        .name("my-box")
        .label("team", "sdk")
        .env("FOO", "bar")
        .auto_stop_secs(60)
        .auto_archive_secs(120)
        .auto_delete_secs(0)
        .max_age_secs(3600)
        .ttl_secs(9)
        .snapshot("node-base")
        .trust("untrusted")
        .tools(["node@22", "git"])
        .egress_allow(["pypi.org"])
        .api_key("k1");
    let sb = acquire(Some(&fake.url), Some("/tmp"), Some("sess"), opts).await.unwrap();
    assert_eq!((sb.id.as_str(), sb.isolation.as_deref(), sb.runtime()), ("sbx_1", Some("vm"), Some("docker")));
    assert_eq!(
        fake.last("POST /api/sandboxes"),
        json!({"template": "node-base", "pi_session": "sess", "trust": "untrusted", "workspace": {"host_path": "/tmp"},
               "tools": ["node@22", "git"], "egress_allow": ["pypi.org"], "ttl_secs": 9, "name": "my-box",
               "labels": {"team": "sdk"}, "env": {"FOO": "bar"}, "auto_stop_secs": 60, "auto_archive_secs": 120,
               "auto_delete_secs": 0, "max_age_secs": 3600})
    );
    let reqs = fake.reqs.lock().unwrap();
    assert_eq!(reqs[1].header("authorization"), Some("Bearer k1"), "control plane: the api key");
}

#[tokio::test]
async fn acquire_on_a_worker_posts_to_sandboxes_with_the_explicit_token() {
    let fake = Fake::start(|url| {
        let u = url.to_owned();
        vec![
            route("GET /healthz", fixed(200, json!({"ok": true, "backend": "podman", "host_id": "h"}))),
            route("POST /sandboxes", Box::new(move |_| js(201, create_reply(&u, "sbx_w", "vm")))),
        ]
    })
    .await;
    let sb = acquire(Some(&fake.url), None, None, AcquireOptions::new().token("wtok")).await.unwrap();
    assert_eq!(sb.id, "sbx_w");
    assert_eq!(fake.reqs.lock().unwrap()[1].header("authorization"), Some("Bearer wtok"));
    let body = fake.last("POST /sandboxes");
    assert_eq!(body["pi_session"], format!("sbx-rust-{}", std::process::id()));
    assert!(body.get("workspace").is_none());
}

#[tokio::test]
async fn runtime_wins_over_isolation_and_neither_omits_the_key() {
    let fake = Fake::start(|url| {
        let u = url.to_owned();
        vec![
            cp_health(),
            route(
                "POST /api/sandboxes",
                Box::new(move |r| {
                    let iso = r.json().get("isolation").and_then(Value::as_str).map(str::to_owned);
                    js(201, create_reply(&u, "sbx_1", iso.as_deref().unwrap_or("native")))
                }),
            ),
        ]
    })
    .await;
    let sb = Sandbox::create(
        Some(&fake.url),
        Some("/tmp"),
        Some("sess"),
        AcquireOptions::new().runtime("docker").isolation("native"),
    )
    .await
    .unwrap();
    assert_eq!(fake.last("POST /api/sandboxes")["isolation"], "vm");
    assert_eq!((sb.isolation.as_deref(), sb.runtime()), (Some("vm"), Some("docker")));
    let sb = Sandbox::create(Some(&fake.url), Some("/tmp"), Some("sess"), AcquireOptions::new()).await.unwrap();
    assert!(fake.last("POST /api/sandboxes").get("isolation").is_none(), "omitted entirely; qafas resolves auto");
    assert_eq!(sb.runtime(), Some("process"));
    Sandbox::create(Some(&fake.url), None, Some("s"), AcquireOptions::new().runtime("auto")).await.unwrap();
    assert!(fake.last("POST /api/sandboxes").get("isolation").is_none());
    Sandbox::create(Some(&fake.url), None, Some("s"), AcquireOptions::new().isolation("auto")).await.unwrap();
    assert_eq!(fake.last("POST /api/sandboxes")["isolation"], "auto", "an explicit isolation passes through as given");
}

#[tokio::test]
async fn acquire_without_cwd_sends_no_workspace_and_uploads_nothing() {
    let fake = Fake::start(|url| {
        let u = url.to_owned();
        vec![
            cp_health(),
            route("POST /api/sandboxes", Box::new(move |_| js(201, create_reply(&u, "sbx_nocwd", "remote")))),
        ]
    })
    .await;
    let sb = acquire(Some(&fake.url), None, Some("sess"), AcquireOptions::new()).await.unwrap();
    assert_eq!(sb.id, "sbx_nocwd");
    assert!(fake.last("POST /api/sandboxes").get("workspace").is_none());
    assert!(
        !fake.seen().iter().any(|p| p.contains("/fs/tar")),
        "must not upload anything without a cwd: {:?}",
        fake.seen()
    );
}

#[tokio::test]
async fn acquire_destroys_the_sandbox_and_fails_clearly_when_the_upload_fails() {
    let local = std::env::temp_dir().join(format!("qafas-sdk-up-{}", std::process::id()));
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("f.txt"), "x").unwrap();
    let cwd = local.to_str().unwrap().to_owned();
    let tar_key = format!("PUT /sandboxes/sbx_upfail/agent/fs/tar?path={}", quote(&cwd));
    let fake = Fake::start(|url| {
        let u = url.to_owned();
        vec![
            cp_health(),
            route("POST /api/sandboxes", Box::new(move |_| js(201, create_reply(&u, "sbx_upfail", "remote")))),
            route(&tar_key, fixed(413, json!({"error": "body over SBX_MAX_UPLOAD_MB (512 MiB)"}))),
            route("DELETE /sandboxes/sbx_upfail", fixed(204, Value::Null)),
        ]
    })
    .await;
    let e = acquire(Some(&fake.url), Some(&cwd), Some("sess"), AcquireOptions::new()).await.unwrap_err();
    assert!(matches!(e, Error::Upload(_)));
    let m = e.to_string();
    assert!(m.contains("workspace upload failed") && m.contains("413") && m.contains("upload_workspace(false)"), "{m}");
    assert!(
        fake.seen().contains(&"DELETE /sandboxes/sbx_upfail".to_owned()),
        "a failed upload must destroy the sandbox: {:?}",
        fake.seen()
    );

    // upload_workspace(false): the tar is not sent at all
    let n = fake.seen().len();
    let sb = acquire(Some(&fake.url), Some(&cwd), Some("sess"), AcquireOptions::new().upload_workspace(false))
        .await
        .unwrap();
    assert_eq!(sb.isolation.as_deref(), Some("remote"));
    assert_eq!(fake.seen().len(), n + 1, "{:?}", fake.seen());
    std::fs::remove_dir_all(local).unwrap();
}

#[tokio::test]
async fn acquire_sends_size_or_limits_and_echoes_them() {
    let mut info = info_json("sbx_1");
    info["name"] = "sbx_1".into();
    let fake = Fake::start(|url| {
        let u = url.to_owned();
        vec![
            cp_health(),
            route(
                "POST /api/sandboxes",
                Box::new(move |r| {
                    let mut v = create_reply(&u, "sbx_1", "vm");
                    if r.json().get("size").is_some() {
                        v["size"] = "mini".into();
                        v["limits"] = json!({"cpus": 1, "mem_mib": 1024, "disk_mib": 1024, "pids": 256});
                        v["info"] = info.clone();
                    }
                    js(201, v)
                }),
            ),
        ]
    })
    .await;
    let sb = acquire(Some(&fake.url), Some("/tmp"), Some("sess"), AcquireOptions::new().size("mini")).await.unwrap();
    let body = fake.last("POST /api/sandboxes");
    assert_eq!(body["size"], "mini");
    assert!(body.get("limits").is_none());
    assert_eq!(sb.size.as_deref(), Some("mini"));
    assert_eq!(sb.limits, Some(SandboxLimits { cpus: 1.0, mem_mib: 1024, disk_mib: 1024, pids: 256 }));
    // v5.1: CreateSandboxResp.info lands on create_info unchanged (not `info`, the live GET method)
    assert_eq!(
        sb.create_info.as_ref().map(|i| (i.id.as_str(), i.name.as_str(), i.state)),
        Some(("sbx_1", "sbx_1", SandboxState::Ready))
    );

    let l = SandboxLimits { cpus: 0.5, mem_mib: 512, disk_mib: 512, pids: 0 };
    let sb = acquire(Some(&fake.url), Some("/tmp"), Some("sess"), AcquireOptions::new().limits(l)).await.unwrap();
    let body = fake.last("POST /api/sandboxes");
    assert_eq!(
        body["limits"],
        json!({"cpus": 0.5, "mem_mib": 512, "disk_mib": 512}),
        "pids 0 = nearest size, not sent"
    );
    assert!(body.get("size").is_none());
    assert!(sb.size.is_none() && sb.limits.is_none());

    acquire(Some(&fake.url), Some("/tmp"), Some("sess"), AcquireOptions::new()).await.unwrap();
    let body = fake.last("POST /api/sandboxes");
    assert!(body.get("size").is_none() && body.get("limits").is_none());
}

// ---------------------------------------------------------------- upload / download

#[test]
fn workspace_guard() {
    let g = |p: &str, ws: &str, allow| assert_inside_workspace(p, ws, allow);
    assert!(g("/w/repo", "/w/repo", false).is_ok());
    assert!(g("/w/repo/sub/f.txt", "/w/repo", false).is_ok());
    assert!(g("/w/repo/a/../b", "/w/repo", false).is_ok());
    assert!(g("/w/repo/../etc/passwd", "/w/repo", false).is_err());
    assert!(g("/w/repository", "/w/repo", false).is_err(), "a sibling sharing a prefix is outside");
    assert!(g("/etc/passwd", "/w/repo", true).is_ok());
    assert!(g("/etc/passwd", "", false).is_ok(), "no workspace: nothing to guard");
    let e = g("/etc/passwd", "/w/repo", false).unwrap_err();
    assert!(matches!(e, Error::Invalid(_)));
    assert_eq!(e.to_string(), "/etc/passwd is outside the workspace (/w/repo); pass allow_outside(true) to override");
}

#[tokio::test]
async fn upload_and_download_refuse_outside_the_workspace_unless_allowed() {
    let sb = Sandbox::new("http://127.0.0.1:1/sandboxes/sbx_x/agent", "t", "s", "sbx_x", "b", "/workspace/repo");
    assert!(matches!(sb.upload("/does/not/matter", "/etc/passwd", false).await.unwrap_err(), Error::Invalid(_)));
    assert!(matches!(sb.download("/etc/passwd", "/does/not/matter", false).await.unwrap_err(), Error::Invalid(_)));
    // Inside the workspace, or allow_outside, the guard passes and the network is what fails
    // (nothing listens on port 1; a missing local file is an Io error first).
    let e = sb.upload("/does/not/matter", "/workspace/repo/sub/file.txt", false).await.unwrap_err();
    assert!(!matches!(e, Error::Invalid(_)), "{e}");
    let e = sb.download("/etc/passwd", "/does/not/matter", true).await.unwrap_err();
    assert!(matches!(e, Error::Transport(_)), "{e}");
}

#[tokio::test]
async fn upload_and_download_round_trip_against_the_fake() {
    let local = std::env::temp_dir().join(format!("qafas-sdk-rt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&local);
    std::fs::create_dir_all(local.join("sub")).unwrap();
    std::fs::write(local.join("hello.txt"), "hello sandbox").unwrap();
    std::fs::write(local.join("sub/nested.txt"), "nested").unwrap();
    std::fs::write(local.join(".env"), "SECRET=1").unwrap();

    let mut b = tar::Builder::new(Vec::new());
    for (name, body) in [("./hello.txt", "from remote"), ("./sub/nested.txt", "deep")] {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, body.as_bytes()).unwrap();
    }
    let remote_tar = b.into_inner().unwrap();

    let fake = Fake::start(|_| {
        vec![
            route("PUT /sandboxes/sbx_1/agent/fs/write?path=/w/hello.txt", fixed(204, Value::Null)),
            route("PUT /sandboxes/sbx_1/agent/fs/tar?path=/w/dir", fixed(204, Value::Null)),
            route(
                "GET /sandboxes/sbx_1/agent/fs/stat?path=/w/dir",
                fixed(200, json!({"is_dir": true, "size": 0, "mode": 493, "mtime": "t"})),
            ),
            route(
                "GET /sandboxes/sbx_1/agent/fs/stat?path=/w/hello.txt",
                fixed(200, json!({"is_dir": false, "size": 1, "mode": 420, "mtime": "t"})),
            ),
            route("GET /sandboxes/sbx_1/agent/fs/read?path=/w/hello.txt", Box::new(|_| (200, b"remote file".to_vec()))),
            route("GET /sandboxes/sbx_1/agent/fs/tar?path=/w/dir", Box::new(move |_| (200, remote_tar.clone()))),
        ]
    })
    .await;
    let sb = sb_at(&fake.url);
    sb.upload(local.join("hello.txt"), "/w/hello.txt", false).await.unwrap();
    sb.upload(&local, "/w/dir", false).await.unwrap();
    {
        let reqs = fake.reqs.lock().unwrap();
        assert_eq!(reqs[0].body, b"hello sandbox");
        let mut ar = tar::Archive::new(&reqs[1].body[..]);
        let mut names: Vec<String> =
            ar.entries().unwrap().map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["hello.txt", "sub/nested.txt"], "the packer ran: .env stayed home");
    }

    let back = std::env::temp_dir().join(format!("qafas-sdk-back-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&back);
    sb.download("/w/hello.txt", back.join("a/b/hello.txt"), false).await.unwrap();
    assert_eq!(std::fs::read_to_string(back.join("a/b/hello.txt")).unwrap(), "remote file");
    sb.download("/w/dir", back.join("updir"), false).await.unwrap();
    assert_eq!(std::fs::read_to_string(back.join("updir/hello.txt")).unwrap(), "from remote");
    assert_eq!(std::fs::read_to_string(back.join("updir/sub/nested.txt")).unwrap(), "deep");
    std::fs::remove_dir_all(local).unwrap();
    std::fs::remove_dir_all(back).unwrap();
}

// ---------------------------------------------------------------- snapshots

fn snap(name: &str, state: &str) -> Value {
    json!({"name": name, "state": state, "kind": "image", "source": {"image": "node:22-bookworm"}, "created_at": "t"})
}

#[tokio::test]
async fn snapshots_against_the_control_plane() {
    let fake = Fake::start(|_| {
        vec![
            cp_health(),
            route(
                "POST /api/snapshots",
                Box::new(|r| {
                    assert_eq!(r.json(), json!({"name": "img1", "source": {"image": "node:22-bookworm"}}));
                    js(202, json!([snap("img1", "building")])) // the control plane answers a list
                }),
            ),
            route("GET /api/snapshots/img1", fixed(200, snap("img1", "active"))),
            route("DELETE /api/snapshots/img1", fixed(204, Value::Null)),
            route("DELETE /api/snapshots/gone", fixed(404, json!({}))),
            route("GET /api/snapshots", fixed(200, json!([snap("img1", "active")]))),
        ]
    })
    .await;
    let s = snapshots(&fake.url, Some("admintok"));
    let created = s.create("img1", SnapshotSpec::new().image("node:22-bookworm")).await.unwrap();
    assert_eq!((created.name.as_str(), created.state), ("img1", SnapshotState::Building));
    let ready = s.wait_ready("img1", Duration::from_secs(2)).await.unwrap();
    assert_eq!(ready.state, SnapshotState::Active);
    assert_eq!(s.list().await.unwrap().len(), 1);
    s.delete("img1").await.unwrap();
    s.delete("gone").await.unwrap();
    assert_eq!(
        fake.seen(),
        [
            "POST /api/snapshots",
            "GET /api/snapshots/img1",
            "GET /api/snapshots",
            "DELETE /api/snapshots/img1",
            "DELETE /api/snapshots/gone"
        ]
    );
    assert_eq!(fake.reqs.lock().unwrap()[1].header("authorization"), Some("Bearer admintok"));
}

#[tokio::test]
async fn snapshots_warm_fields_and_set_warm() {
    let fake = Fake::start(|_| {
        let mut full = snap("img3", "building");
        full.as_object_mut().unwrap().extend([
            ("warm".to_owned(), json!(2)),
            ("memory_snapshot".to_owned(), json!(false)),
            ("warm_ready".to_owned(), json!(0)),
        ]);
        let mut put = snap("img3", "active");
        put.as_object_mut().unwrap().extend([("warm".to_owned(), json!(5)), ("warm_ready".to_owned(), json!(5))]);
        vec![
            cp_health(),
            route("POST /api/snapshots", fixed(202, json!([full]))),
            route("PUT /api/snapshots/img3", fixed(200, json!([put]))),
        ]
    })
    .await;
    let s = snapshots(&fake.url, Some("admintok"));
    let c =
        s.create("img3", SnapshotSpec::new().image("node:22-bookworm").warm(2).memory_snapshot(false)).await.unwrap();
    assert_eq!((c.warm, c.memory_snapshot), (2, false));
    assert_eq!(
        fake.last("POST /api/snapshots"),
        json!({"name": "img3", "source": {"image": "node:22-bookworm"}, "warm": 2, "memory_snapshot": false})
    );
    let u = s.set_warm("img3", 5).await.unwrap();
    assert_eq!((u.warm, u.warm_ready), (5, 5));
    assert_eq!(fake.last("PUT /api/snapshots/img3"), json!({"warm": 5}));
}

#[tokio::test]
async fn snapshots_accept_the_image_builder_on_a_worker() {
    let fake = Fake::start(|_| {
        vec![
            route("GET /healthz", fixed(200, json!({"ok": true, "backend": "podman", "host_id": "h"}))), // qafas shape
            route("POST /snapshots", fixed(202, snap("img2", "building"))),
        ]
    })
    .await;
    let image = Image::base("node:22-bookworm")
        .run("npm i -g pnpm")
        .pip_install(&["requests"])
        .npm_install(&["typescript"])
        .workdir("/w")
        .env([("K", "v")])
        .copy_text("/etc/motd", "hi");
    snapshots(&fake.url, Some("tok")).create("img2", image.clone()).await.unwrap();
    let df = fake.last("POST /snapshots")["source"]["dockerfile"].as_str().unwrap().to_owned();
    assert_eq!(df, image.to_dockerfile());
    assert!(
        df.starts_with("FROM node:22-bookworm\n")
            && df.contains("RUN pip install --no-cache-dir 'requests'")
            && df.contains("base64 -d > '/etc/motd'")
    );
}

#[tokio::test]
async fn wait_ready_times_out_with_the_documented_message() {
    let fake =
        Fake::start(|_| vec![cp_health(), route("GET /api/snapshots/slow", fixed(200, snap("slow", "building")))])
            .await;
    let e = snapshots(&fake.url, Some("t")).wait_ready("slow", Duration::from_millis(1)).await.unwrap_err();
    assert!(matches!(e, Error::Timeout(_)));
    assert_eq!(e.to_string(), "snapshot slow still building after 0.001s");
}

#[tokio::test]
async fn destroy_is_idempotent_on_a_revoked_token_but_not_on_a_bad_one() {
    let fake = Fake::start(|_| {
        vec![
            route("DELETE /sandboxes/sbx_1", Box::new(|_| (401, b"token revoked with its sandbox".to_vec()))),
            route("DELETE /sandboxes/sbx_2", Box::new(|_| (401, b"bad or missing bearer token".to_vec()))),
        ]
    })
    .await;
    sb_at(&fake.url).destroy().await.unwrap();
    let mut other = sb_at(&fake.url);
    other.endpoint = format!("{}/sandboxes/sbx_2/agent", fake.url);
    assert!(matches!(other.destroy().await.unwrap_err(), Error::Http { status: 401, .. }));
}
