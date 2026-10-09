//! `/fs/*` — thin wrappers over `tokio::fs`, plus tar for workspace sync.
//! Paths are absolute host paths; there is no translation layer (D4).

use std::path::{Component, Path, PathBuf};

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::{Stream, StreamExt};
use proto::{FsStat, MkdirReq};
use serde::Deserialize;
use std::sync::Arc;
use tokio_util::io::{StreamReader, SyncIoBridge};

#[derive(Deserialize)]
pub struct PathQ {
    pub path: String,
}

fn io_err(e: std::io::Error) -> Response {
    let code = match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, e.to_string()).into_response()
}

use crate::rfc3339_millis;

// ------------------------------------------------------------------ handlers

/// Streamed, so reading a file never costs its size in memory. The open is what
/// decides the status code; anything that goes wrong afterwards can only cut the
/// body short, which is what a chunked reply already means to a client.
pub async fn read(Query(q): Query<PathQ>) -> Response {
    match tokio::fs::File::open(&q.path).await {
        Ok(f) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            Body::from_stream(tokio_util::io::ReaderStream::new(f)),
        )
            .into_response(),
        Err(e) => io_err(e),
    }
}

/// What `capped` puts in the io error when the body runs past the cap, so a
/// `413` survives the trip through `tokio::io` and `tar`'s reader.
const TOO_LARGE: &str = "upload over SBX_MAX_UPLOAD_MB";

fn too_large(e: &std::io::Error) -> bool {
    e.to_string().contains(TOO_LARGE)
}

/// v4: the request body as a byte stream, cut off at `SBX_MAX_UPLOAD_MB`.
/// `DefaultBodyLimit` only bites on the buffering extractors (`Bytes`, `Json`),
/// so a handler that streams has to carry the same cap itself.
fn capped(body: Body) -> impl Stream<Item = std::io::Result<Bytes>> {
    let cap = crate::max_upload_bytes();
    let mut seen = 0usize;
    body.into_data_stream().map(move |chunk| {
        let b = chunk.map_err(std::io::Error::other)?;
        seen += b.len();
        if seen > cap {
            return Err(std::io::Error::other(TOO_LARGE));
        }
        Ok(b)
    })
}

/// v4: written as it arrives, so the file's size is not also a memory cost.
pub async fn write(Query(q): Query<PathQ>, body: Body) -> Response {
    if let Some(parent) = Path::new(&q.path).parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return io_err(e);
        }
    }
    let mut f = match tokio::fs::File::create(&q.path).await {
        Ok(f) => f,
        Err(e) => return io_err(e),
    };
    let mut src = StreamReader::new(capped(body));
    match tokio::io::copy(&mut src, &mut f).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if too_large(&e) => (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response(),
        Err(e) => io_err(e),
    }
}

pub async fn stat(Query(q): Query<PathQ>) -> Response {
    use std::os::unix::fs::MetadataExt;
    match tokio::fs::metadata(&q.path).await {
        Ok(m) => Json(FsStat {
            is_dir: m.is_dir(),
            size: m.len(),
            mode: m.mode(),
            mtime: rfc3339_millis(m.mtime() * 1000 + i64::from(m.mtime_nsec() as i32) / 1_000_000),
        })
        .into_response(),
        Err(e) => io_err(e),
    }
}

pub async fn list(Query(q): Query<PathQ>) -> Response {
    let mut rd = match tokio::fs::read_dir(&q.path).await {
        Ok(r) => r,
        Err(e) => return io_err(e),
    };
    let mut names = Vec::new();
    while let Ok(Some(entry)) = rd.next_entry().await {
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Json(names).into_response()
}

pub async fn mkdir(req: MkdirReq) -> Response {
    match tokio::fs::create_dir_all(&req.path).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => io_err(e),
    }
}

// ------------------------------------------------------------------ tar

/// True for entry paths a tar is not allowed to contain: absolute, or escaping
/// the destination with `..`.
pub fn unsafe_entry(p: &Path) -> bool {
    p.components().any(|c| matches!(c, Component::RootDir | Component::ParentDir | Component::Prefix(_)))
}

/// v4: extracted as the bytes arrive. A workspace bigger than the guest's RAM
/// used to be an OOM (the remote tier extracts onto a tmpfs); now the only
/// buffer is `tar`'s. A rejected entry still aborts with `400` and leaves the
/// members already written, as before.
pub async fn tar_put(State(ctx): State<Arc<crate::Ctx>>, Query(q): Query<PathQ>, body: Body) -> Response {
    // A pooled microVM is booted before anyone knows which workspace it will
    // serve; the first tree uploaded into it is that workspace.
    if ctx.rules.workspace_unknown() {
        ctx.rules.set_workspace(&q.path);
    }
    let dest = PathBuf::from(&q.path);
    // Built here, not in the blocking task: it captures the current runtime
    // handle, which a `spawn_blocking` thread does not have.
    let src = SyncIoBridge::new(StreamReader::new(capped(body)));
    let r = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        std::fs::create_dir_all(&dest)?;
        // In a microVM we are PID 1 (root) but commands run as uid 1000: the
        // workspace must belong to the agent (uid 1000, harden::AGENT_UID) or nothing can write to it.
        let chown = unsafe { libc::geteuid() } == 0;
        let give = |p: &std::path::Path| {
            if chown {
                let _ = std::os::unix::fs::lchown(p, Some(1000), Some(1000));
            }
        };
        give(&dest);
        let mut ar = tar::Archive::new(src);
        for entry in ar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.into_owned();
            if unsafe_entry(&path) {
                return Err(std::io::Error::other(format!("unsafe tar entry: {}", path.display())));
            }
            entry.unpack_in(&dest)?;
            // The tar carries files only; unpack_in creates their directories as
            // us (root), and git refuses a repository whose .git we do not own.
            for anc in path.ancestors().filter(|a| !a.as_os_str().is_empty()) {
                give(&dest.join(anc));
            }
        }
        Ok(())
    })
    .await;
    match r {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) if too_large(&e) => (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response(),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Other => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        Ok(Err(e)) => io_err(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Written into the response as it is built, so a `node_modules` tree costs the
/// pipe's buffer rather than its own size in memory. The path is checked first —
/// that is the last point at which a status code can still be chosen — and a
/// failure past it closes the body early, which is a truncated tar to the client
/// and an error in the log.
pub async fn tar_get(Query(q): Query<PathQ>) -> Response {
    let src = PathBuf::from(&q.path);
    if let Err(e) = tokio::fs::metadata(&src).await {
        return io_err(e);
    }
    let (rx, tx) = tokio::io::duplex(64 * 1024);
    // Built out here: `SyncIoBridge` captures the runtime handle, which a
    // `spawn_blocking` thread does not have.
    let sink = SyncIoBridge::new(tx);
    tokio::task::spawn_blocking(move || {
        let mut b = tar::Builder::new(sink);
        b.follow_symlinks(false);
        let r = if src.is_dir() {
            b.append_dir_all(".", &src)
        } else {
            match src.file_name() {
                Some(name) => b.append_path_with_name(&src, name),
                None => Err(std::io::Error::other("bad path")),
            }
        };
        if let Err(e) = r.and_then(|()| b.finish()) {
            tracing::warn!(error = %e, "tar body cut short");
        }
    });
    (
        [(axum::http::header::CONTENT_TYPE, "application/x-tar")],
        Body::from_stream(tokio_util::io::ReaderStream::new(rx)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Peak resident size in KiB, or `None` where the kernel does not say.
    fn peak_rss_kb() -> Option<u64> {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        s.lines().find(|l| l.starts_with("VmHWM:"))?.split_whitespace().nth(1)?.parse().ok()
    }

    /// v4 §2: `PUT /fs/tar` extracts from the stream. 64 MiB of zeros go in and
    /// the process must not grow by 64 MiB doing it — which is exactly what the
    /// old `Bytes` body did on a tmpfs-backed microVM.
    #[tokio::test]
    async fn a_large_tar_is_extracted_as_it_arrives() {
        const BIG: u64 = 64 << 20;
        let root = std::env::temp_dir().join(format!("sbx-fs-stream-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Sparse on the way in; `tar` still writes 64 MiB of zeros into the archive.
        let src = root.join("big.bin");
        std::fs::File::create(&src).unwrap().set_len(BIG).unwrap();
        let archive = root.join("in.tar");
        let mut b = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        b.append_path_with_name(&src, "big.bin").unwrap();
        b.finish().unwrap();
        drop(b);

        let dest = root.join("out");
        let ctx = crate::Ctx::new(
            crate::spawn::Hardened::default(),
            crate::Emitter::null(),
            crate::rules::Rules::guest(&dest.display().to_string(), "/home/agent"),
        );
        let before = peak_rss_kb();
        let file = tokio::fs::File::open(&archive).await.unwrap();
        let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));
        let resp = tar_put(State(ctx), Query(PathQ { path: dest.display().to_string() }), body).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(std::fs::metadata(dest.join("big.bin")).unwrap().len(), BIG);

        // Linux only: macOS has no VmHWM, so there the test still proves the
        // extraction works and says nothing about the memory.
        if let (Some(a), Some(z)) = (before, peak_rss_kb()) {
            let grew = z.saturating_sub(a);
            assert!(grew < 32 * 1024, "peak RSS grew by {grew} KiB extracting a {BIG}-byte tar");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The same cap the buffering extractors had, carried by the streaming one.
    #[tokio::test]
    async fn a_body_over_the_cap_is_413_even_though_nothing_buffers_it() {
        std::env::set_var("SBX_MAX_UPLOAD_MB", "1");
        let path = std::env::temp_dir().join(format!("sbx-fs-cap-{}", std::process::id()));
        let chunks = (0..4).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![0u8; 512 * 1024])));
        let body = Body::from_stream(futures_util::stream::iter(chunks));
        let r = write(Query(PathQ { path: path.display().to_string() }), body).await;
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let _ = std::fs::remove_file(&path);
        std::env::remove_var("SBX_MAX_UPLOAD_MB");
    }

    /// Both read paths stream now. The archive still has to arrive complete and
    /// readable although nothing ever held it whole — and with a payload several
    /// times the pipe's buffer, so the blocking builder and the async reader have
    /// to actually interleave rather than deadlock on a full pipe.
    #[tokio::test]
    async fn reads_are_streamed_and_still_whole() {
        const BIG: usize = 3 << 20;
        let root = std::env::temp_dir().join(format!("sbx-fs-get-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/a.txt"), vec![b'a'; BIG]).unwrap();

        let r = tar_get(Query(PathQ { path: root.display().to_string() })).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 16 << 20).await.unwrap();
        let mut ar = tar::Archive::new(&body[..]);
        let names: Vec<String> =
            ar.entries().unwrap().map(|e| e.unwrap().path().unwrap().display().to_string()).collect();
        assert!(names.iter().any(|n| n.ends_with("sub/a.txt")), "{names:?}");

        let r = read(Query(PathQ { path: root.join("sub/a.txt").display().to_string() })).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(axum::body::to_bytes(r.into_body(), 16 << 20).await.unwrap().len(), BIG);

        // A path that is not there still decides the status code, not the body.
        for path in [root.join("nope"), root.join("nope/deeper")] {
            let p = path.display().to_string();
            assert_eq!(read(Query(PathQ { path: p.clone() })).await.status(), StatusCode::NOT_FOUND);
            assert_eq!(tar_get(Query(PathQ { path: p })).await.status(), StatusCode::NOT_FOUND);
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tar_entry_validation() {
        assert!(unsafe_entry(Path::new("/etc/passwd")));
        assert!(unsafe_entry(Path::new("../escape")));
        assert!(unsafe_entry(Path::new("a/../../b")));
        assert!(!unsafe_entry(Path::new("src/main.rs")));
        assert!(!unsafe_entry(Path::new("./src/main.rs")));
    }
}
