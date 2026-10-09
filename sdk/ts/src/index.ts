// qafas-sandbox: SandboxClient + acquire(), extracted from pi-extension/client.ts so
// the pi extension and the standalone `sbx` CLI (bin/sbx) share one implementation.

// SandboxClient: the pi extension's only way of talking to qafas/guest-agent.
// fetch + Node's global WebSocket (undici-based; verified it forwards a non-standard
// `headers` option to the upgrade request, which is how the scoped token gets there —
// there is no browser here, so we don't need the query-token trick SSE needs).
import { mkdir as fsMkdir, readFile as fsReadFile, stat as fsStat, writeFile as fsWriteFile } from "node:fs/promises";
import { dirname, isAbsolute, relative } from "node:path";
import { Readable } from "node:stream";
import { packWorkspace, packWorkspaceStream, unpackTar } from "./pack.js";
import { trustHost } from "./tls.js";
import { HDR_CLIENT, HDR_PI_SESSION, HDR_TOOL_CALL_ID } from "./types.js";
import type {
	CreatePreviewReq,
	CreateSandboxReq,
	CreateSandboxResp,
	CreateSnapshotReq,
	ExecFrame,
	FsStat,
	Isolation,
	PreviewInfo,
	SandboxInfo,
	SandboxLimits,
	SessionCommand,
	SnapshotInfo,
	SnapshotSource,
	Trust,
	UpdateSnapshotReq,
} from "./types.js";

export { normaliseFingerprint, trustHost } from "./tls.js";
export { DEFAULT_IGNORE, packWorkspace, packWorkspaceStream, unpackTar, validateTar } from "./pack.js";
export type { Packed, PackedStream } from "./pack.js";
export type { TrustOpts } from "./tls.js";
export { Image } from "./image.js";
export type * from "./types.js";

/** `X-Sbx-Client` default: which library is talking, so host logs can attribute a request. SDK minor tracks contract version (v4). */
export const CLIENT_ID = "sdk-ts/0.4";

/**
 * Daytona/E2B-style tier name ↔ this project's `isolation`. Purely a client-side
 * relabelling — never sent on the wire; `acquire()`/`Sandbox.create()` translate it to
 * `isolation` before the request. `"auto"` (or omitted) leaves tier selection to qafas.
 */
export type Runtime = "auto" | "process" | "docker" | "firecracker";
const RUNTIME_VALUES: readonly Runtime[] = ["auto", "process", "docker", "firecracker"];

const RUNTIME_TO_ISOLATION: Record<string, Isolation> = { process: "native", docker: "vm", firecracker: "remote" };
const ISOLATION_TO_RUNTIME: Record<string, Runtime> = { native: "process", vm: "docker", remote: "firecracker" };

/** Throws naming the accepted values on anything but `auto|process|docker|firecracker`. */
export function runtimeToIsolation(runtime?: Runtime): Isolation | undefined {
	if (runtime === undefined) return undefined;
	if (!RUNTIME_VALUES.includes(runtime)) throw new Error(`invalid runtime "${runtime}": expected one of ${RUNTIME_VALUES.join("|")}`);
	return runtime !== "auto" ? RUNTIME_TO_ISOLATION[runtime] : undefined;
}

export function isolationToRuntime(isolation?: string): Runtime | undefined {
	return isolation ? ISOLATION_TO_RUNTIME[isolation] : undefined;
}

/**
 * v4 (docs/protocol.md §3): qafas/the control plane accept the wire values
 * `native|vm|remote` plus the product-name aliases `process|docker|firecracker`,
 * alongside `auto` — the server normalises the alias, so the raw string is passed
 * straight through unchanged. Used by the CLI/MCP-facing `--isolation`/`SBX_ISOLATION`
 * entry points (sbx mcp, the pi extension); throws naming the accepted values otherwise.
 */
export const ISOLATION_VALUES = ["auto", "native", "vm", "remote", "process", "docker", "firecracker"] as const;

export function validateIsolation(value?: string): Isolation | undefined {
	if (value === undefined) return undefined;
	if (!(ISOLATION_VALUES as readonly string[]).includes(value)) {
		throw new Error(`invalid isolation "${value}": expected one of ${ISOLATION_VALUES.join("|")}`);
	}
	return value as Isolation;
}

export interface ExecOpts {
	onData: (data: Buffer) => void;
	signal?: AbortSignal;
	/** Seconds, matching pi's BashOperations.exec contract (not ms). */
	timeout?: number;
	env?: NodeJS.ProcessEnv;
}

/**
 * What of the caller's environment may cross into the sandbox (D6: secrets never
 * enter). Harnesses pass their whole `process.env`; only terminal/locale settings
 * and an explicit opt-in list (`SBX_ENV_PASS=FOO,BAR`) survive. The sandbox owns
 * HOME, PATH, TMPDIR and the proxy variables regardless.
 */
const ENV_ALLOW = new Set(["TERM", "COLORTERM", "LANG", "LANGUAGE", "TZ", "CI", "NO_COLOR", "FORCE_COLOR", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"]);

export function filterEnv(env: NodeJS.ProcessEnv | undefined, pass = process.env.SBX_ENV_PASS): Record<string, string> | undefined {
	if (!env) return undefined;
	const extra = new Set((pass ?? "").split(",").map((s) => s.trim()).filter(Boolean));
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(env)) {
		if (v === undefined) continue;
		if (ENV_ALLOW.has(k) || k.startsWith("LC_") || extra.has(k)) out[k] = v;
	}
	return out;
}

/** Non-2xx response from qafas/control plane, carrying the status and the server's `{error}` text when it sent one. */
export class SandboxApiError extends Error {
	constructor(
		public readonly status: number,
		public readonly body: string,
	) {
		super(`HTTP ${status}: ${extractError(body) ?? body}`);
		this.name = "SandboxApiError";
	}
}

function extractError(body: string): string | undefined {
	try {
		const j: unknown = JSON.parse(body);
		return typeof j === "object" && j !== null && typeof (j as { error?: unknown }).error === "string" ? (j as { error: string }).error : undefined;
	} catch {
		return undefined;
	}
}

async function throwApiError(res: Response): Promise<never> {
	throw new SandboxApiError(res.status, await res.text());
}

/** `GET {baseUrl}/healthz`: qafas's response has a `backend` field, the control plane's doesn't. */
async function detectTarget(baseUrl: string): Promise<{ isQafas: boolean }> {
	const res = await fetch(`${baseUrl}/healthz`);
	if (!res.ok) throw new SandboxApiError(res.status, await res.text());
	const healthz: unknown = await res.json().catch(() => ({}));
	return { isQafas: typeof healthz === "object" && healthz !== null && "backend" in healthz };
}

export class SandboxClient {
	constructor(
		/** e.g. http://127.0.0.1:7700/sandboxes/sbx_xxx/agent */
		public readonly endpoint: string,
		public readonly token: string,
		private readonly piSession: string,
		/** Default cwd for run(); set by acquire() from CreateSandboxResp.workspace_path. */
		public readonly workspacePath?: string,
		/** `X-Sbx-Client`: `pi/0.83`, `sdk-ts/0.3`. Host logs attribute requests by it. */
		private readonly clientId: string = CLIENT_ID,
	) {}

	/** Convenience wrapper over execBuffered: runs `cmd` (defaulting cwd to workspacePath),
	 * returns stdout, and throws on a nonzero exit. For scripts that want a one-liner instead
	 * of checking `.exit` themselves; use execBuffered/exec directly when you need the exit code. */
	async run(cmd: string, opts?: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number; toolCallId?: string }): Promise<string> {
		const cwd = opts?.cwd ?? this.workspacePath;
		if (!cwd) throw new Error("run(): no cwd given and no workspacePath on this client");
		const res = await this.execBuffered(cmd, cwd, opts);
		if (res.exit !== 0) throw new Error(`run() failed (exit ${res.exit}): ${res.stderr || res.stdout}`);
		return res.stdout;
	}

	/** Not private: Session (same module) reuses this to sign its own requests against the same sandbox. */
	headers(toolCallId = ""): Record<string, string> {
		return {
			Authorization: `Bearer ${this.token}`,
			[HDR_PI_SESSION]: this.piSession,
			[HDR_TOOL_CALL_ID]: toolCallId,
			[HDR_CLIENT]: this.clientId,
		};
	}

	// ------------------------------------------------------------------ exec

	/** POST /exec — buffered, for one-shot probes (grep/find helpers, health checks). */
	async execBuffered(
		cmd: string,
		cwd: string,
		opts?: { env?: NodeJS.ProcessEnv; timeoutMs?: number; toolCallId?: string; signal?: AbortSignal },
	): Promise<{ exit: number; stdout: string; stderr: string; duration_ms: number; truncated?: boolean }> {
		const res = await fetch(`${this.endpoint}/exec`, {
			method: "POST",
			headers: { ...this.headers(opts?.toolCallId), "content-type": "application/json" },
			body: JSON.stringify({ cmd, cwd, env: filterEnv(opts?.env), timeout_ms: opts?.timeoutMs }),
			signal: opts?.signal,
		});
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as { exit: number; stdout: string; stderr: string; duration_ms: number; truncated?: boolean };
	}

	/**
	 * GET /exec/ws — streaming exec. Signature matches pi's `BashOperations.exec` so
	 * ops.ts can hand this straight through. MUST throw exactly `new Error("aborted")`
	 * on abort and `new Error(\`timeout:${seconds}\`)` on timeout (docs/protocol.md §2.2).
	 */
	exec(command: string, cwd: string, opts: ExecOpts, toolCallId = ""): Promise<{ exitCode: number | null }> {
		if (opts.signal?.aborted) return Promise.reject(new Error("aborted"));

		const wsUrl = this.endpoint.replace(/^http/, "ws") + "/exec/ws";
		return new Promise((resolve, reject) => {
			// biome-ignore lint: Node's global WebSocket accepts a non-standard `headers` init.
			const ws = new WebSocket(wsUrl, { headers: this.headers(toolCallId) } as unknown as string[]);
			let settled = false;
			let timedOut = false;

			const timer =
				opts.timeout && opts.timeout > 0
					? setTimeout(
							() => {
								timedOut = true;
								ws.close();
							},
							opts.timeout * 1000,
						)
					: undefined;
			const onAbort = () => ws.close();
			opts.signal?.addEventListener("abort", onAbort, { once: true });

			const cleanup = () => {
				if (timer) clearTimeout(timer);
				opts.signal?.removeEventListener("abort", onAbort);
			};
			const fail = (err: Error) => {
				if (settled) return;
				settled = true;
				cleanup();
				reject(err);
			};
			const succeed = (exitCode: number | null) => {
				if (settled) return;
				settled = true;
				cleanup();
				resolve({ exitCode });
			};
			const failFromState = () => {
				if (opts.signal?.aborted) fail(new Error("aborted"));
				else if (timedOut) fail(new Error(`timeout:${opts.timeout}`));
				else fail(new Error("sandbox exec connection closed unexpectedly"));
			};

			ws.addEventListener("open", () => {
				const start: ExecFrame = { type: "start", cmd: command, cwd, env: filterEnv(opts.env) };
				ws.send(JSON.stringify(start));
			});
			ws.addEventListener("message", (ev: MessageEvent) => {
				let frame: ExecFrame;
				try {
					frame = JSON.parse(String(ev.data));
				} catch {
					return;
				}
				if (frame.type === "stdout" || frame.type === "stderr") {
					opts.onData(Buffer.from(frame.data, "base64"));
				} else if (frame.type === "exit") {
					succeed(frame.code);
				}
			});
			ws.addEventListener("error", failFromState);
			ws.addEventListener("close", failFromState);
		});
	}

	// -------------------------------------------------------------------- fs

	async readFile(path: string, toolCallId = ""): Promise<Buffer> {
		const res = await fetch(`${this.endpoint}/fs/read?path=${encodeURIComponent(path)}`, { headers: this.headers(toolCallId) });
		if (res.status === 404) throw enoent(path);
		if (!res.ok) return throwApiError(res);
		return Buffer.from(await res.arrayBuffer());
	}

	async writeFile(path: string, content: string | Buffer, toolCallId = ""): Promise<void> {
		const res = await fetch(`${this.endpoint}/fs/write?path=${encodeURIComponent(path)}`, {
			method: "PUT",
			headers: this.headers(toolCallId),
			body: typeof content === "string" ? content : new Uint8Array(content),
		});
		if (!res.ok) return throwApiError(res);
	}

	/** Alias of writeFile, named for symmetry with readFile/upload/download. */
	uploadBytes(path: string, content: Buffer, toolCallId = ""): Promise<void> {
		return this.writeFile(path, content, toolCallId);
	}

	async mkdir(path: string, toolCallId = ""): Promise<void> {
		const res = await fetch(`${this.endpoint}/fs/mkdir`, {
			method: "POST",
			headers: { ...this.headers(toolCallId), "content-type": "application/json" },
			body: JSON.stringify({ path }),
		});
		if (!res.ok) return throwApiError(res);
	}

	async stat(path: string, toolCallId = ""): Promise<FsStat> {
		const res = await fetch(`${this.endpoint}/fs/stat?path=${encodeURIComponent(path)}`, { headers: this.headers(toolCallId) });
		if (res.status === 404) throw enoent(path);
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as FsStat;
	}

	async list(path: string, toolCallId = ""): Promise<string[]> {
		const res = await fetch(`${this.endpoint}/fs/list?path=${encodeURIComponent(path)}`, { headers: this.headers(toolCallId) });
		if (res.status === 404) throw enoent(path);
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as string[];
	}

	async uploadTar(path: string, tar: Buffer, toolCallId = ""): Promise<void> {
		const res = await fetch(`${this.endpoint}/fs/tar?path=${encodeURIComponent(path)}`, {
			method: "PUT",
			headers: this.headers(toolCallId),
			body: new Uint8Array(tar),
		});
		if (!res.ok) return throwApiError(res);
	}

	/**
	 * Same as `uploadTar` but takes a stream instead of a `Buffer` — used by `upload()`'s
	 * directory case so a large workspace's tar never sits fully in process memory.
	 * `duplex: "half"` is required by Node's fetch whenever the body is a stream.
	 */
	async uploadTarStream(path: string, tar: Readable, toolCallId = ""): Promise<void> {
		const res = await fetch(`${this.endpoint}/fs/tar?path=${encodeURIComponent(path)}`, {
			method: "PUT",
			headers: this.headers(toolCallId),
			body: Readable.toWeb(tar) as ReadableStream<Uint8Array>,
			duplex: "half",
		});
		if (!res.ok) return throwApiError(res);
	}

	async downloadTar(path: string, toolCallId = ""): Promise<Buffer> {
		const res = await fetch(`${this.endpoint}/fs/tar?path=${encodeURIComponent(path)}`, { headers: this.headers(toolCallId) });
		if (!res.ok) return throwApiError(res);
		return Buffer.from(await res.arrayBuffer());
	}

	/**
	 * Uploads a local file or directory to `remotePath`. A directory is packed with the
	 * same rules as a remote-tier workspace upload (`packWorkspace`: `.sbxignore` +
	 * `DEFAULT_IGNORE`) and sent as a tar; a file goes straight through `writeFile`.
	 * Refuses a `remotePath` outside this client's `workspacePath` unless `allowOutside`
	 * is set — qafas/guest-agent already enforce the real boundary server-side, this
	 * is just a client-side foot-gun guard against a typo'd path.
	 */
	async upload(localPath: string, remotePath: string, opts?: { allowOutside?: boolean; toolCallId?: string }): Promise<void> {
		assertInsideWorkspace(remotePath, this.workspacePath, opts?.allowOutside);
		const st = await fsStat(localPath);
		if (st.isDirectory()) {
			const { stream } = await packWorkspaceStream(localPath);
			await this.uploadTarStream(remotePath, stream, opts?.toolCallId);
		} else {
			await this.writeFile(remotePath, await fsReadFile(localPath), opts?.toolCallId);
		}
	}

	/**
	 * Downloads `remotePath` (file or directory) to `localPath`. Mirrors `upload()`'s
	 * boundary guard, on the remote side of the path this time.
	 */
	async download(remotePath: string, localPath: string, opts?: { allowOutside?: boolean; toolCallId?: string }): Promise<void> {
		assertInsideWorkspace(remotePath, this.workspacePath, opts?.allowOutside);
		const st = await this.stat(remotePath, opts?.toolCallId);
		if (st.is_dir) {
			await fsMkdir(localPath, { recursive: true });
			await unpackTar(await this.downloadTar(remotePath, opts?.toolCallId), localPath);
		} else {
			await fsMkdir(dirname(localPath), { recursive: true });
			await fsWriteFile(localPath, await this.readFile(remotePath, opts?.toolCallId));
		}
	}

	/** POST /sandboxes/{id}/events — the pi extension is the source of browser.navigate events. */
	async postEvent(type: string, data: unknown, toolCallId = ""): Promise<void> {
		const res = await fetch(`${qafasBase(this.endpoint)}/events`, {
			method: "POST",
			headers: { ...this.headers(toolCallId), "content-type": "application/json" },
			body: JSON.stringify({ type, data }),
		});
		if (!res.ok) return throwApiError(res);
	}

	/** The guest-agent base URL for /browser/cdp (proxied through qafas's agent route). */
	get cdpUrl(): string {
		return `${this.endpoint.replace(/^http/, "ws")}/browser/cdp`;
	}

	// ------------------------------------------------------------- v3: lifecycle

	/** GET /sandboxes/{id} — current SandboxInfo, including v3 state/timers. */
	async info(toolCallId = ""): Promise<SandboxInfo> {
		const res = await fetch(qafasBase(this.endpoint), { headers: this.headers(toolCallId) });
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as SandboxInfo;
	}

	/** remote tier only; `native`/`vm` answer 409 (docs/protocol.md §3a "Lifecycle"). */
	stop(toolCallId = ""): Promise<void> {
		return this.lifecycle("stop", toolCallId);
	}

	async start(toolCallId = ""): Promise<SandboxInfo> {
		const res = await fetch(`${qafasBase(this.endpoint)}/start`, { method: "POST", headers: this.headers(toolCallId) });
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as SandboxInfo;
	}

	pause(toolCallId = ""): Promise<void> {
		return this.lifecycle("pause", toolCallId);
	}

	resume(toolCallId = ""): Promise<void> {
		return this.lifecycle("resume", toolCallId);
	}

	archive(toolCallId = ""): Promise<void> {
		return this.lifecycle("archive", toolCallId);
	}

	private async lifecycle(verb: "stop" | "pause" | "resume" | "archive", toolCallId: string): Promise<void> {
		const res = await fetch(`${qafasBase(this.endpoint)}/${verb}`, { method: "POST", headers: this.headers(toolCallId) });
		if (!res.ok) return throwApiError(res);
	}

	async destroy(): Promise<void> {
		const res = await fetch(qafasBase(this.endpoint), { method: "DELETE", headers: this.headers() });
		if (!res.ok && res.status !== 404) return throwApiError(res);
	}

	/** Alias of destroy() — the name Daytona/E2B users expect. */
	delete(): Promise<void> {
		return this.destroy();
	}

	// -------------------------------------------------------------- v3: preview

	/** POST /sandboxes/{id}/preview — signed URL for a port inside the sandbox. */
	async preview(port: number, opts?: { ttlSecs?: number; toolCallId?: string }): Promise<PreviewInfo> {
		const body: CreatePreviewReq = { port, ttl_secs: opts?.ttlSecs };
		const res = await fetch(`${qafasBase(this.endpoint)}/preview`, {
			method: "POST",
			headers: { ...this.headers(opts?.toolCallId), "content-type": "application/json" },
			body: JSON.stringify(body),
		});
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as PreviewInfo;
	}

	// ------------------------------------------------------------- v3: sessions

	/** POST /sessions — a persistent shell inside this sandbox, alive until deleted or the sandbox stops. */
	async createSession(opts?: { id?: string; cwd?: string; env?: Record<string, string> }, toolCallId = ""): Promise<Session> {
		const res = await fetch(`${this.endpoint}/sessions`, {
			method: "POST",
			headers: { ...this.headers(toolCallId), "content-type": "application/json" },
			body: JSON.stringify({ id: opts?.id, cwd: opts?.cwd, env: opts?.env }),
		});
		if (!res.ok) return throwApiError(res);
		const { id } = (await res.json()) as { id: string };
		return new Session(this, id);
	}
}

/**
 * `Sandbox.create()`'s handle: a `SandboxClient` (every exec/fs/lifecycle/session call
 * unchanged) plus the identifying fields a Daytona/E2B-style caller expects on the handle
 * itself. Built by `acquire()` — `create()` just calls it and returns the client, so there
 * is exactly one code path for "make me a sandbox".
 */
export class Sandbox extends SandboxClient {
	constructor(
		endpoint: string,
		token: string,
		piSession: string,
		public readonly id: string,
		public readonly backend: string,
		public readonly isolation: string | undefined,
		workspacePath: string,
		clientId?: string,
	) {
		super(endpoint, token, piSession, workspacePath, clientId);
	}

	/** The tier qafas actually picked, relabelled to the `runtime` naming (derived from `isolation`). */
	get runtime(): Runtime | undefined {
		return isolationToRuntime(this.isolation);
	}

	static async create(baseUrl: string, cwd: string | undefined, piSession: string, opts: AcquireOpts = {}): Promise<Sandbox> {
		const result = await acquire(baseUrl, cwd, piSession, opts);
		return result.client as Sandbox;
	}
}

/** Refuses a remote path outside `workspacePath` unless `allowOutside` — qafas/guest-agent
 * enforce the real boundary; this only catches an obvious typo before a wasted round trip. */
function assertInsideWorkspace(remotePath: string, workspacePath: string | undefined, allowOutside: boolean | undefined): void {
	if (allowOutside || !workspacePath) return;
	const rel = relative(workspacePath, remotePath);
	if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) return;
	throw new Error(`${remotePath} is outside the workspace (${workspacePath}); pass { allowOutside: true } to override`);
}

/** A persistent shell inside a sandbox (docs/protocol.md §3a "Sessions"). Reached through the
 * owning SandboxClient's endpoint/token, so it never needs its own auth. */
export class Session {
	constructor(
		private readonly sb: SandboxClient,
		public readonly id: string,
	) {}

	/** POST /sessions/{id}/exec. Sync (default): resolves with exit/stdout/stderr. Async: resolves
	 * with just `command_id`; poll `command()` or stream `logs()`. Only one command runs at a time. */
	async exec(cmd: string, opts?: { async?: boolean; timeoutMs?: number; toolCallId?: string }): Promise<SessionCommand> {
		const res = await fetch(`${this.sb.endpoint}/sessions/${this.id}/exec`, {
			method: "POST",
			headers: { ...this.sb.headers(opts?.toolCallId), "content-type": "application/json" },
			body: JSON.stringify({ cmd, async: opts?.async, timeout_ms: opts?.timeoutMs }),
		});
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as SessionCommand;
	}

	/** GET /sessions/{id}/commands/{cid} — includes stdout/stderr (capped like /exec). */
	async command(cid: string, toolCallId = ""): Promise<SessionCommand> {
		const res = await fetch(`${this.sb.endpoint}/sessions/${this.id}/commands/${cid}`, { headers: this.sb.headers(toolCallId) });
		if (!res.ok) return throwApiError(res);
		return (await res.json()) as SessionCommand;
	}

	/** POST .../commands/{cid}/input — bytes to the shell's stdin while `cid` is the running command. */
	async input(cid: string, data: string, toolCallId = ""): Promise<void> {
		const res = await fetch(`${this.sb.endpoint}/sessions/${this.id}/commands/${cid}/input`, {
			method: "POST",
			headers: { ...this.sb.headers(toolCallId), "content-type": "application/json" },
			body: JSON.stringify({ data }),
		});
		if (!res.ok) return throwApiError(res);
	}

	/** GET .../commands/{cid}/logs/ws — replays buffered output then streams live until `exit`. */
	logs(cid: string, onOutput: (data: Buffer, stream: "stdout" | "stderr") => void, toolCallId = ""): Promise<{ exitCode: number | null }> {
		const wsUrl = `${this.sb.endpoint.replace(/^http/, "ws")}/sessions/${this.id}/commands/${cid}/logs/ws`;
		return new Promise((resolve, reject) => {
			// biome-ignore lint: see SandboxClient.exec — same non-standard `headers` init.
			const ws = new WebSocket(wsUrl, { headers: this.sb.headers(toolCallId) } as unknown as string[]);
			let settled = false;
			const succeed = (exitCode: number | null) => {
				if (settled) return;
				settled = true;
				resolve({ exitCode });
			};
			const fail = (err: Error) => {
				if (settled) return;
				settled = true;
				reject(err);
			};
			ws.addEventListener("message", (ev: MessageEvent) => {
				let frame: ExecFrame;
				try {
					frame = JSON.parse(String(ev.data));
				} catch {
					return;
				}
				if (frame.type === "stdout" || frame.type === "stderr") onOutput(Buffer.from(frame.data, "base64"), frame.type);
				else if (frame.type === "exit") succeed(frame.code);
			});
			ws.addEventListener("error", () => fail(new Error("session logs socket error")));
			ws.addEventListener("close", () => fail(new Error("session logs socket closed unexpectedly")));
		});
	}

	/** DELETE /sessions/{id} — kills the shell's process group. */
	async delete(toolCallId = ""): Promise<void> {
		const res = await fetch(`${this.sb.endpoint}/sessions/${this.id}`, { method: "DELETE", headers: this.sb.headers(toolCallId) });
		if (!res.ok && res.status !== 404) return throwApiError(res);
	}
}

function enoent(path: string): NodeJS.ErrnoException {
	const err = new Error(`ENOENT: no such file or directory, '${path}'`) as NodeJS.ErrnoException;
	err.code = "ENOENT";
	return err;
}

/** Strips the trailing "/agent" so callers can hit the qafas-level /sandboxes/{id}/* routes. */
function qafasBase(endpoint: string): string {
	return endpoint.replace(/\/agent$/, "");
}

export interface AcquireResult {
	client: SandboxClient;
	id: string;
	backend: string;
	workspacePath: string;
	isolation?: string; // v2: tier qafas actually selected
	tools?: Record<string, string>; // v2
	missingTools?: string[]; // v2
	size?: string; // v5: name or "custom"
	limits?: SandboxLimits; // v5: ceilings actually applied
	info?: SandboxInfo; // v5.1: the daemon's record right after create
}

/** v2/v3 request knobs, on top of the required cwd/piSession. */
export interface AcquireOpts {
	/** Control-plane API key (§4b); default `SBX_API_KEY`, then `SBX_ADMIN_TOKEN`. */
	apiKey?: string;
	/** Omitted along with `runtime` → the request carries no `isolation` field at all;
	 * the control plane resolves `auto` Firecracker-first (docs/decisions.md D25). */
	isolation?: Isolation;
	/** v4: `"process"|"docker"|"firecracker"` (Daytona/E2B naming) mapping to `isolation`
	 * `native|vm|remote`; `"auto"`/omitted leaves `isolation` as given. Wins over `isolation`
	 * when both are set. */
	runtime?: Runtime;
	trust?: Trust;
	tools?: string[];
	egressAllow?: string[];
	ttlSecs?: number;
	template?: string;
	/** v3: alias for `template` — the snapshot name to build the sandbox from. */
	snapshot?: string;
	/** v3: unique among the host's live sandboxes; the id is used when absent. */
	name?: string;
	/** v3: opaque tags, no server-side meaning. */
	labels?: Record<string, string>;
	/** v3: added to every exec in this sandbox; `PROTECTED_ENV` names are dropped server-side. */
	env?: Record<string, string>;
	/** v3: `ready` with no activity this long → stop (remote tier only). */
	autoStopSecs?: number;
	/** v3: `stopped` this long → archive. */
	autoArchiveSecs?: number;
	/** v3: 0 = ephemeral (destroy the moment it stops); n = stopped/archived n seconds → destroy. */
	autoDeleteSecs?: number;
	/** v3: wall clock from creation, any state → destroy. */
	maxAgeSecs?: number;
	/** `X-Sbx-Client` for every request this sandbox's client makes. */
	client?: string;
	/** v5 (§3a "v5 sizes and limits"): named size, from the harness/API, never the model.
	 * Omitted along with `limits` → the daemon defaults to `medium`. */
	size?: string;
	/** v5: custom ceilings; mutually exclusive with `size` (both → 400). */
	limits?: SandboxLimits;
	/**
	 * Only applies when `cwd` is given. A microVM has no bind mount: when the resolved
	 * tier is `remote`, the cwd is sent as a tar (minus build output and credentials,
	 * see `packWorkspace`) before acquire() returns. Default true; pass false to ship
	 * it yourself. Omitting `cwd` already sends no workspace and uploads nothing.
	 */
	uploadWorkspace?: boolean;
	/**
	 * Pin the sandbox host's certificate. Normally unnecessary: the control plane
	 * returns the fingerprint it pinned at host registration and it is used
	 * automatically. Set this to pin a qafas dialled directly.
	 */
	caFingerprint?: string;
	/** PEM CA bundle to verify with; defaults to `$SBX_CA_FILE`. */
	caFile?: string;
}

/**
 * Acquire a sandbox for cwd. `baseUrl` may point at the control plane (:7800) or, for
 * local/dev use, straight at qafas (:7700) — detected by the shape of GET /healthz
 * (qafas's QafasHealthz has a `backend` field; the control plane's doesn't).
 * pi never mints tokens; it only carries the one it's handed back.
 */
/** The bearer for the control plane: an API key identifies the application (§4b);
 * the admin token is the root credential and the fallback. */
export function controlPlaneToken(apiKey?: string): string {
	return apiKey ?? process.env.SBX_API_KEY ?? process.env.SBX_ADMIN_TOKEN ?? "";
}

export async function acquire(baseUrl: string, cwd: string | undefined, piSession: string, opts: AcquireOpts = {}): Promise<AcquireResult> {
	// The control plane (or a directly dialled qafas) has to be trusted before
	// the first request, not after it.
	await trustHost(baseUrl, { caFingerprint: opts.caFingerprint, caFile: opts.caFile });
	const { isQafas } = await detectTarget(baseUrl);

	const req: CreateSandboxReq = {
		template: opts.snapshot ?? opts.template ?? "base",
		// Workspace is optional on every tier (docs/protocol.md §3a): omitting cwd gets
		// the sandbox its own /home/agent rather than mounting or uploading anything.
		workspace: cwd ? { host_path: cwd } : undefined,
		pi_session: piSession,
		isolation: runtimeToIsolation(opts.runtime) ?? opts.isolation,
		trust: opts.trust,
		tools: opts.tools,
		egress_allow: opts.egressAllow,
		ttl_secs: opts.ttlSecs,
		name: opts.name,
		labels: opts.labels,
		env: opts.env,
		auto_stop_secs: opts.autoStopSecs,
		auto_archive_secs: opts.autoArchiveSecs,
		auto_delete_secs: opts.autoDeleteSecs,
		max_age_secs: opts.maxAgeSecs,
		size: opts.size,
		limits: opts.limits,
	};
	const url = isQafas ? `${baseUrl}/sandboxes` : `${baseUrl}/api/sandboxes`;
	const token = isQafas ? (process.env.SBX_TOKEN ?? "") : controlPlaneToken(opts.apiKey);

	const res = await fetch(url, {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "content-type": "application/json", [HDR_CLIENT]: opts.client ?? CLIENT_ID },
		body: JSON.stringify(req),
	});
	if (!res.ok) throw new SandboxApiError(res.status, await res.text());
	const resp = (await res.json()) as CreateSandboxResp;

	// The sandbox may live on a different host than the control plane, with its own
	// certificate. `tls_fingerprint` is the pin the control plane verified at registration.
	await trustHost(resp.endpoint, { caFingerprint: opts.caFingerprint ?? resp.tls_fingerprint, caFile: opts.caFile });

	const client = new Sandbox(resp.endpoint, resp.token, piSession, resp.id, resp.backend, resp.isolation, resp.workspace_path, opts.client ?? CLIENT_ID);
	// Only when the caller actually passed a cwd: no cwd means no workspace was sent
	// above, so there is nothing here to upload either. A microVM has no bind mount, so a
	// `remote` tier sandbox needs this tar to see cwd's contents at all.
	if (cwd && resp.isolation === "remote" && opts.uploadWorkspace !== false) {
		try {
			const { tar } = await packWorkspace(cwd);
			await client.uploadTar(cwd, tar);
		} catch (err) {
			// Don't leak a running sandbox the caller has no handle to (defect 3).
			await client.destroy().catch(() => {});
			const detail = err instanceof Error ? err.message : String(err);
			throw new Error(`workspace upload failed (${detail}): pass uploadWorkspace:false or a smaller directory (.sbxignore)`);
		}
	}

	return {
		client,
		id: resp.id,
		backend: resp.backend,
		workspacePath: resp.workspace_path,
		isolation: resp.isolation,
		tools: resp.tools,
		missingTools: resp.missing_tools,
		size: resp.size,
		limits: resp.limits,
		info: resp.info,
	};
}

/** "cpus=1,mem_mib=1024,disk_mib=512,pids=256" -> {cpus,mem_mib,disk_mib,pids?}, numbers.
 * Shared by the CLI, the MCP server and the pi extension's SBX_LIMITS parsing. */
export function parseLimits(s: string): Record<string, number> {
	const out: Record<string, number> = {};
	for (const pair of s.split(",")) {
		const [k, v] = pair.split("=");
		if (k && v !== undefined) out[k.trim()] = Number(v);
	}
	return out;
}

/**
 * Acquire a sandbox, run `fn` against its client, and always destroy it afterward —
 * including when `fn` throws. Prefer this over bare `acquire()` for scripts/examples that
 * don't need the sandbox to outlive one block.
 */
export async function withSandbox<T>(
	baseUrl: string,
	cwd: string | undefined,
	piSession: string,
	fn: (client: SandboxClient, acquired: AcquireResult) => Promise<T>,
	opts: AcquireOpts = {},
): Promise<T> {
	const result = await acquire(baseUrl, cwd, piSession, opts);
	try {
		return await fn(result.client, result);
	} finally {
		await result.client.destroy().catch(() => {});
	}
}

// -------------------------------------------------------------- v3: snapshots

export interface SnapshotCreateOpts {
	name: string;
	image?: string;
	/** A raw Dockerfile string, or an `Image` builder (its `.toDockerfile()` is called for you). */
	dockerfile?: string | { toDockerfile(): string };
	sandboxId?: string;
	/** v4: sandboxes the pool keeps restored and ready for this template. Default 0. */
	warm?: number;
	/** v4: capture memory + state after the first boot so every create is a restore.
	 * Default true; Firecracker hosts only, ignored elsewhere. */
	memorySnapshot?: boolean;
}

export interface SnapshotsAPI {
	create(opts: SnapshotCreateOpts): Promise<SnapshotInfo>;
	list(): Promise<SnapshotInfo[]>;
	get(name: string): Promise<SnapshotInfo>;
	delete(name: string): Promise<void>;
	/** Polls `get(name)` until `state` leaves `"building"` or `timeoutMs` elapses. */
	waitReady(name: string, timeoutMs?: number): Promise<SnapshotInfo>;
	/** v4 `PUT /snapshots/{name}` `{"warm": n}` — sets the pool's warm target live. */
	setWarm(name: string, n: number): Promise<SnapshotInfo>;
}

/**
 * Snapshots (named images a sandbox can be created from) are top-level, not tied to any
 * one acquired sandbox — `baseUrl` gets the same qafas-vs-control-plane detection as
 * `acquire()`. `token` defaults to `SBX_TOKEN`/`SBX_ADMIN_TOKEN` the same way.
 */
export function snapshots(baseUrl: string, token?: string, client: string = CLIENT_ID): SnapshotsAPI {
	async function rootAndHeaders(): Promise<{ root: string; headers: Record<string, string> }> {
		const { isQafas } = await detectTarget(baseUrl);
		const tok = token ?? (isQafas ? (process.env.SBX_TOKEN ?? "") : controlPlaneToken());
		return {
			root: isQafas ? `${baseUrl}/snapshots` : `${baseUrl}/api/snapshots`,
			headers: { Authorization: `Bearer ${tok}`, [HDR_CLIENT]: client, "content-type": "application/json" },
		};
	}

	const api: SnapshotsAPI = {
		async create(opts) {
			const source: SnapshotSource = {};
			if (opts.image) source.image = opts.image;
			if (opts.dockerfile) source.dockerfile = typeof opts.dockerfile === "string" ? opts.dockerfile : opts.dockerfile.toDockerfile();
			if (opts.sandboxId) source.sandbox_id = opts.sandboxId;
			const body: CreateSnapshotReq = { name: opts.name, source };
			if (opts.warm !== undefined) body.warm = opts.warm;
			if (opts.memorySnapshot !== undefined) body.memory_snapshot = opts.memorySnapshot;
			const { root, headers } = await rootAndHeaders();
			const res = await fetch(root, { method: "POST", headers, body: JSON.stringify(body) });
			if (!res.ok) return throwApiError(res);
			const parsed: unknown = await res.json();
			// The control plane fans a create out to every vm/remote host: 202 [SnapshotInfo]; qafas: 202 SnapshotInfo.
			return (Array.isArray(parsed) ? parsed[0] : parsed) as SnapshotInfo;
		},
		async list() {
			const { root, headers } = await rootAndHeaders();
			const res = await fetch(root, { headers });
			if (!res.ok) return throwApiError(res);
			return (await res.json()) as SnapshotInfo[];
		},
		async get(name) {
			const { root, headers } = await rootAndHeaders();
			const res = await fetch(`${root}/${encodeURIComponent(name)}`, { headers });
			if (!res.ok) return throwApiError(res);
			return (await res.json()) as SnapshotInfo;
		},
		async delete(name) {
			const { root, headers } = await rootAndHeaders();
			const res = await fetch(`${root}/${encodeURIComponent(name)}`, { method: "DELETE", headers });
			if (!res.ok && res.status !== 404) return throwApiError(res);
		},
		async setWarm(name, n) {
			const body: UpdateSnapshotReq = { warm: n };
			const { root, headers } = await rootAndHeaders();
			const res = await fetch(`${root}/${encodeURIComponent(name)}`, { method: "PUT", headers, body: JSON.stringify(body) });
			if (!res.ok) return throwApiError(res);
			const parsed: unknown = await res.json();
			// The control plane fans a PUT out to every host that has the snapshot: 200 [SnapshotInfo]; qafas: 200 SnapshotInfo.
			return (Array.isArray(parsed) ? parsed[0] : parsed) as SnapshotInfo;
		},
		async waitReady(name, timeoutMs = 120_000) {
			const deadline = Date.now() + timeoutMs;
			for (;;) {
				const info = await api.get(name);
				if (info.state !== "building") return info;
				if (Date.now() > deadline) throw new Error(`snapshot ${name} still building after ${timeoutMs}ms`);
				await new Promise((r) => setTimeout(r, 1000));
			}
		},
	};
	return api;
}
