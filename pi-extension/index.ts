// pi extension entry point. Routes pi's seven built-in tools plus `!`/`!!` (user_bash)
// into the sandbox over qafas/guest-agent, per docs/decisions.md D9 (pi stays on the
// host; only tool execution moves). Modelled on pi's own examples/extensions/gondolin.
import { randomUUID } from "node:crypto";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	createBashTool,
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadTool,
	createWriteTool,
	type GrepToolInput,
} from "@earendil-works/pi-coding-agent";
import { acquire, packWorkspace, parseLimits as sdkParseLimits, unpackTar, validateIsolation, type AcquireOpts, type AcquireResult, type SandboxClient } from "qafas-sandbox";
import { bashOps, editOps, findOps, lsOps, readOps, sandboxGrep, writeOps } from "./ops.ts";
import { BrowserSession, registerBrowserTools } from "./browser.ts";

const CWD = process.cwd();
const DEFAULT_SANDBOX_URL = "http://localhost:7800";
/** `X-Sbx-Client`, so a remote host's logs can tell pi apart from the raw SDK. */
const PI_CLIENT = "pi/0.83";

export default function (pi: ExtensionAPI): void {
	pi.registerFlag("sandbox-url", { description: "Control plane or qafas base URL (default http://localhost:7800)", type: "string" });
	pi.registerFlag("no-sandbox", { description: "Disable sandboxing; run tools on the host", type: "boolean", default: false });
	pi.registerFlag("isolation", {
		description: "Isolation tier: auto|native|vm|remote, or the product-name aliases process|docker|firecracker (default auto; env SBX_ISOLATION)",
		type: "string",
	});
	pi.registerFlag("trust", { description: "Workspace trust: trusted|untrusted (default trusted; env SBX_TRUST)", type: "string" });
	pi.registerFlag("tools", { description: "Comma-separated tools to request, e.g. node@22,rg (env SBX_TOOLS)", type: "string" });
	pi.registerFlag("size", { description: "Sandbox size: micro|mini|medium|high (default medium; env SBX_SIZE)", type: "string" });

	// Correlation id for X-Pi-Session; protocol.md §7 sanctions "pi session id or random
	// uuid per process" — there's no stable session id available at extension-load time.
	// SBX_SESSION_ID lets CI/tests find their session in the control plane; default is one id per pi process.
	const piSession = process.env.SBX_SESSION_ID || randomUUID();

	const local = {
		read: createReadTool(CWD),
		write: createWriteTool(CWD),
		edit: createEditTool(CWD),
		bash: createBashTool(CWD),
		ls: createLsTool(CWD),
		find: createFindTool(CWD),
		grep: createGrepTool(CWD),
	};

	let acquired: AcquireResult | undefined;
	let starting: Promise<AcquireResult> | undefined;
	let browserSession: BrowserSession | undefined;
	let browserSidecar: AcquireResult | undefined;

	const disabled = () => Boolean(pi.getFlag("no-sandbox"));

	// v2: --isolation/--trust/--tools, falling back to SBX_ISOLATION/SBX_TRUST/SBX_TOOLS.
	// v4: --isolation/SBX_ISOLATION accepts auto|native|vm|remote or the product-name
	// aliases process|docker|firecracker (docs/protocol.md §3); validateIsolation checks
	// it and passes the raw string through unchanged — the server normalises the alias.
	// A caller of ensureSandbox() is always the thing that catches this (user_bash never
	// throws: docs/decisions.md D10).
	function acquireOpts(): AcquireOpts {
		const isolation = (pi.getFlag("isolation") as string | undefined) || process.env.SBX_ISOLATION;
		const trust = (pi.getFlag("trust") as string | undefined) || process.env.SBX_TRUST;
		const toolsStr = (pi.getFlag("tools") as string | undefined) || process.env.SBX_TOOLS;
		const size = (pi.getFlag("size") as string | undefined) || process.env.SBX_SIZE;
		return {
			isolation: validateIsolation(isolation),
			trust: trust as AcquireOpts["trust"],
			tools: toolsStr ? toolsStr.split(",").map((t) => t.trim()).filter(Boolean) : undefined,
			client: PI_CLIENT,
			caFingerprint: process.env.SBX_CA_FINGERPRINT,
			size,
			limits: parseLimits(process.env.SBX_LIMITS),
		};
	}

	// SBX_LIMITS only (no --limits flag): the harness sets this, the model never sees it.
	function parseLimits(s: string | undefined): AcquireOpts["limits"] {
		return s ? (sdkParseLimits(s) as unknown as AcquireOpts["limits"]) : undefined;
	}

	// Single in-flight acquire, shared by every tool call and by session_start (which
	// kicks it off early so the boot overlaps with the user typing their first prompt).
	async function ensureSandbox(ctx?: ExtensionContext): Promise<AcquireResult> {
		if (acquired) return acquired;
		starting ??= (async () => {
			const base = (pi.getFlag("sandbox-url") as string | undefined) || process.env.SBX_URL || DEFAULT_SANDBOX_URL;
			ctx?.ui.setStatus("sandbox", ctx.ui.theme?.fg?.("accent", "sandbox: starting") ?? "sandbox: starting");
			const result = await acquire(base, CWD, piSession, acquireOpts());
			if (result.backend === "firecracker") {
				await uploadWorkspace(result);
			}
			acquired = result;
			ctx?.ui.setStatus("sandbox", ctx.ui.theme?.fg?.("accent", `sandbox: ${result.id} (${result.backend})`) ?? `sandbox: ${result.id}`);
			return result;
		})().finally(() => {
			starting = undefined;
		});
		return starting;
	}

	// Builds a tool override that shares the ensureSandbox() connection. Tools are built
	// fresh per call (not once at registration) because the sandbox may not exist yet.
	function route<K extends keyof typeof local>(
		name: K,
		build: (client: SandboxClient, toolCallId: string) => { execute: (typeof local)[K]["execute"] },
	): void {
		const fallback = local[name];
		// design: `local[K]` is a union across all seven tool shapes inside this generic
		// function body, so TS can't verify the spread against one specific TParams here —
		// cast at this one interop boundary rather than duplicating `route` seven times.
		pi.registerTool({
			...fallback,
			async execute(id: string, params: unknown, signal?: AbortSignal, onUpdate?: unknown, ctx?: ExtensionContext) {
				if (disabled()) {
					return (fallback.execute as (...a: unknown[]) => unknown)(id, params, signal, onUpdate, ctx);
				}
				const { client } = await ensureSandbox(ctx);
				return (build(client, id).execute as (...a: unknown[]) => unknown)(id, params, signal, onUpdate);
			},
		} as unknown as Parameters<typeof pi.registerTool>[0]);
	}

	route("read", (c, id) => createReadTool(CWD, { operations: readOps(c, id) }));
	route("write", (c, id) => createWriteTool(CWD, { operations: writeOps(c, id) }));
	route("edit", (c, id) => createEditTool(CWD, { operations: editOps(c, id) }));
	route("ls", (c, id) => createLsTool(CWD, { operations: lsOps(c, id) }));
	route("find", (c, id) => createFindTool(CWD, { operations: findOps(c, id) }));
	route("bash", (c, id) => createBashTool(CWD, { operations: bashOps(c, id) }));

	// grep is the one tool `operations` can't redirect (docs/decisions.md D11): bypass the
	// local tool's execute entirely and shell out to the guest's own ripgrep.
	pi.registerTool({
		...local.grep,
		async execute(id: string, params: GrepToolInput, signal?: AbortSignal, onUpdate?: unknown, ctx?: ExtensionContext) {
			if (disabled()) return (local.grep.execute as (...a: unknown[]) => Promise<unknown>)(id, params, signal, onUpdate, ctx);
			const { client } = await ensureSandbox(ctx);
			return sandboxGrep(client, CWD, params, id);
		},
	} as unknown as Parameters<typeof pi.registerTool>[0]);

	// The browser runs wherever Chromium is. A native sandbox on a host without a
	// headless shell reports `missing_tools: ["chromium"]`; then the browser tools get
	// a sidecar sandbox (the tier policy routes `tools: ["chromium"]` to the VM tier)
	// on the same workspace path, so downloads still land in the same directory.
	registerBrowserTools(pi, async () => {
		if (browserSession) return browserSession;
		const main = await ensureSandbox();
		const hasChromium = Boolean(main.tools?.chromium) && !main.missingTools?.includes("chromium");
		if (main.isolation === "native" && !hasChromium) {
			const base = (pi.getFlag("sandbox-url") as string | undefined) || process.env.SBX_URL || DEFAULT_SANDBOX_URL;
			browserSidecar = await acquire(base, CWD, piSession, { ...acquireOpts(), isolation: undefined, tools: ["chromium"] });
			browserSession = new BrowserSession(browserSidecar.client);
		} else {
			browserSession = new BrowserSession(main.client);
		}
		return browserSession;
	});

	// `!`/`!!` commands bypass the tool registry (docs/decisions.md D9–D11). This handler MUST
	// NEVER throw: pi issue #9068 makes a throwing handler silently fall back to host
	// execution, which would defeat the sandbox entirely (docs/decisions.md D10).
	pi.on("user_bash", async (_event, ctx) => {
		if (disabled()) return;
		try {
			const { client } = await ensureSandbox(ctx);
			return { operations: bashOps(client, "") };
		} catch (err) {
			return {
				result: {
					output: `sandbox unavailable: ${err instanceof Error ? err.message : String(err)}`,
					exitCode: 1,
					cancelled: false,
					truncated: false,
				},
			};
		}
	});

	// Tell the model where it actually is; the cwd string in the default prompt is
	// otherwise misleading (it's true on the host filesystem and, by design D4, also
	// true inside the sandbox — but the model should know a sandbox is there at all).
	pi.on("before_agent_start", async (event, ctx) => {
		if (disabled()) return;
		await ensureSandbox(ctx).catch(() => {}); // best-effort; don't block the turn on this
		const line = `Current working directory: ${CWD}`;
		const replacement = `${line} (sandboxed; host directory mounted at the same path)`;
		return {
			systemPrompt: event.systemPrompt.includes(line)
				? event.systemPrompt.replace(line, replacement)
				: `${event.systemPrompt}\n\n${replacement}`,
		};
	});

	pi.on("session_start", async (_event, ctx) => {
		if (!disabled()) ensureSandbox(ctx).catch(() => {}); // fire-and-forget, overlaps with typing
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		const a = acquired;
		acquired = undefined;
		starting = undefined;
		const bs = browserSession;
		browserSession = undefined;
		await bs?.close().catch(() => {});
		const side = browserSidecar;
		browserSidecar = undefined;
		await side?.client.destroy().catch(() => {});
		if (a) {
			// The remote tier works on an uploaded copy: bring the result back before
			// the VM goes away. `/sandbox pull` does the same by hand; SBX_NO_AUTOPULL=1 opts out.
			if (a.backend === "firecracker" && process.env.SBX_NO_AUTOPULL !== "1") {
				try {
					await unpackTar(await a.client.downloadTar(CWD), CWD);
				} catch (err) {
					ctx.ui.notify(`workspace pull failed: ${err instanceof Error ? err.message : String(err)}`, "error");
				}
			}
			await a.client.destroy().catch(() => {});
			ctx.ui.setStatus("sandbox", undefined);
		}
	});

	pi.registerCommand("sandbox", {
		description: "Sandbox status, or sync/pull the workspace for the firecracker backend (usage: /sandbox [status|sync|pull])",
		async handler(args, ctx) {
			const sub = args.trim() || "status";
			try {
				const result = await ensureSandbox(ctx);
				if (sub === "sync" || sub === "pull") {
					if (result.backend !== "firecracker") {
						ctx.ui.notify(`${sub} is only needed for the firecracker backend (podman shares the host filesystem)`, "info");
						return;
					}
					if (sub === "sync") {
						const { bytes, files } = await uploadWorkspace(result);
						ctx.ui.notify(`workspace synced to sandbox (${files} files, ${Math.round(bytes / 1024)} KiB)`, "info");
					} else {
						await unpackTar(await result.client.downloadTar(CWD), CWD);
						ctx.ui.notify("workspace pulled from sandbox", "info");
					}
					return;
				}
				const toolsLine = result.tools ? Object.entries(result.tools).map(([n, v]) => `${n}@${v}`).join(", ") : "(none reported)";
				const missingLine = result.missingTools?.length ? `\nmissing tools: ${result.missingTools.join(", ")}` : "";
				const sizeLine = result.size ? `\nsize: ${result.size}` : "";
				ctx.ui.notify(
					`sandbox ${result.id} (${result.backend}${result.isolation ? `, ${result.isolation}` : ""})\n` +
						`workspace: ${result.workspacePath}\ntools: ${toolsLine}${missingLine}${sizeLine}`,
					"info",
				);
			} catch (err) {
				ctx.ui.notify(`sandbox unavailable: ${err instanceof Error ? err.message : String(err)}`, "error");
			}
		},
	});
}

/**
 * Uploads the workspace to a remote sandbox, minus build output and credentials
 * (docs/security.md M32; the exclusion list and `.sbxignore` live in the SDK's
 * `packWorkspace`). qafas's proxy logs the PUT as `file.write` with the byte
 * count; the file count is only knowable here, so this adds its own event.
 */
async function uploadWorkspace(result: AcquireResult): Promise<{ bytes: number; files: number }> {
	const { tar, files } = await packWorkspace(CWD);
	await result.client.uploadTar(CWD, tar);
	await result.client.postEvent("file.write", { path: CWD, bytes: tar.length, files }).catch(() => {});
	return { bytes: tar.length, files };
}

