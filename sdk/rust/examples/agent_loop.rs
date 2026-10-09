//! A small agent loop: a fake "model" emits tool calls, we execute them in the sandbox, and feed
//! the result back. Swap `fake_model_step` for a real LLM call to make it real (the API key stays
//! on the host; only the commands it chose run in the sandbox).
//!
//!     SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev cargo run -p qafas-sandbox --example agent_loop

use qafas_sandbox::{acquire, AcquireOptions, ExecOptions, Sandbox, Stream};

struct ToolCall {
    tool: &'static str,
    command: &'static str,
}

/// A tiny scripted "plan" standing in for real model output: each step is one tool call.
const PLAN: [ToolCall; 2] = [
    ToolCall { tool: "bash", command: "echo 'agent says hi' && pwd" },
    ToolCall { tool: "bash", command: "ls | head -5" },
];

/// Stand-in for an LLM call: the next tool call, or `None` when done.
fn fake_model_step(step: usize, _last_result: Option<&str>) -> Option<&'static ToolCall> {
    PLAN.get(step)
}

async fn run_tool_call(sb: &Sandbox, call: &ToolCall, tool_call_id: &str) -> qafas_sandbox::Result<String> {
    match call.tool {
        // Streams the output as it is produced (a real agent would forward it to its UI).
        "bash" => {
            let opts = ExecOptions::new().tool_call_id(tool_call_id);
            let r = sb
                .exec_with(call.command, &opts, |chunk, stream| {
                    let tag = if stream == Stream::Stdout { "out" } else { "err" };
                    println!("  [{tag}] {}", String::from_utf8_lossy(chunk).trim_end());
                })
                .await?;
            Ok(r.stdout + &r.stderr)
        }
        other => Err(qafas_sandbox::Error::Invalid(format!("unknown tool: {other}"))),
    }
}

#[tokio::main]
async fn main() -> qafas_sandbox::Result<()> {
    let cwd = match std::env::var("SBX_CWD") {
        Ok(c) if c.is_empty() => None,
        Ok(c) => Some(c),
        Err(_) => std::env::current_dir().ok().map(|d| d.to_string_lossy().into_owned()),
    };
    let sb = acquire(None, cwd.as_deref(), Some("sdk-rust-agent-loop"), AcquireOptions::new()).await?;
    println!("sandbox {} ready, workspace={}\n", sb.id, sb.workspace_path);

    let mut last: Option<String> = None;
    let mut step = 0;
    let outcome = async {
        while let Some(call) = fake_model_step(step, last.as_deref()) {
            println!("[model] tool call: {} {:?}", call.tool, call.command);
            // Every qafas event of this call carries the id, so the dashboard shows it as one span.
            last = Some(run_tool_call(&sb, call, &format!("call-{step}")).await?);
            step += 1;
        }
        Ok::<_, qafas_sandbox::Error>(())
    }
    .await;
    sb.destroy().await?;
    outcome?;
    println!("agent loop finished");
    Ok(())
}
