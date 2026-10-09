//! `qafas bench` — exec round trip against a running daemon.
//!
//! Deliberately thin. The real harness is `bench/run.mjs` (WP2): it compares
//! tiers, other products, `npm ci` and browser load times, and writes JSON. This
//! is the one number you want while changing the daemon, without leaving Rust:
//! how long does `POST /exec` take end to end, from outside the process.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use crate::config::Config;
use crate::events::http_client;

async fn call(
    http: &crate::events::HttpClient,
    method: &str,
    url: &str,
    token: &str,
    body: serde_json::Value,
) -> anyhow::Result<(u16, serde_json::Value)> {
    let req = hyper::Request::builder()
        .method(method)
        .uri(url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?;
    let resp = http.request(req).await?;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)))
}

/// Nearest-rank percentile: the smallest sample at or above `p` of the run.
fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

pub async fn run(
    cfg: &Arc<Config>,
    url: &str,
    isolation: &str,
    count: u32,
    workspace: Option<String>,
) -> anyhow::Result<()> {
    let http = http_client();
    let url = url.trim_end_matches('/');
    let workspace = match workspace {
        Some(w) => w,
        None => std::env::current_dir()?.display().to_string(),
    };

    let (status, created) = call(
        &http,
        "POST",
        &format!("{url}/sandboxes"),
        &cfg.token,
        serde_json::json!({
            "template": "base",
            "workspace": {"host_path": workspace},
            "isolation": isolation,
            "pi_session": "qafas-bench",
        }),
    )
    .await?;
    if status != 201 {
        anyhow::bail!("create returned {status}: {created}");
    }
    let id = created["id"].as_str().unwrap_or_default().to_string();
    let tier = created["isolation"].as_str().unwrap_or("?").to_string();
    let endpoint = created["endpoint"].as_str().unwrap_or_default().to_string();
    let token = created["token"].as_str().unwrap_or_default().to_string();
    println!("sandbox {id} on tier {tier} (boot reported by the daemon log)");

    // One warm-up: the first request pays for a fresh connection in the pool.
    let exec = serde_json::json!({"cmd": "true", "cwd": workspace, "timeout_ms": 30000});
    let _ = call(&http, "POST", &format!("{endpoint}/exec"), &token, exec.clone()).await;

    let mut samples: Vec<f64> = Vec::with_capacity(count as usize);
    let overall = Instant::now();
    for _ in 0..count {
        let t = Instant::now();
        let (s, _) = call(&http, "POST", &format!("{endpoint}/exec"), &token, exec.clone()).await?;
        if s != 200 {
            anyhow::bail!("exec returned {s}");
        }
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let wall = overall.elapsed().as_secs_f64();
    samples.sort_by(f64::total_cmp);

    println!("exec `true` x{count} on {tier}");
    println!("  p50 {:.2} ms", pct(&samples, 0.50));
    println!("  p95 {:.2} ms", pct(&samples, 0.95));
    println!("  p99 {:.2} ms", pct(&samples, 0.99));
    println!("  min {:.2} ms   max {:.2} ms", samples[0], samples[samples.len() - 1]);
    println!("  {:.0} exec/s over {wall:.2}s", count as f64 / wall);

    let _ = call(&http, "DELETE", &format!("{url}/sandboxes/{id}"), &cfg.token, serde_json::Value::Null).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn percentiles_pick_the_right_sample() {
        let s: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        assert_eq!(super::pct(&s, 0.50), 50.0);
        assert_eq!(super::pct(&s, 0.95), 95.0);
        assert_eq!(super::pct(&s, 0.99), 99.0);
        assert_eq!(super::pct(&[], 0.5), 0.0, "an empty run must not panic");
        assert_eq!(super::pct(&[7.0], 0.99), 7.0);
    }
}
