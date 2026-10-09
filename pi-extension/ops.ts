// Sandbox-backed `operations` for pi's built-in read/write/edit/ls/find/bash tools
// (docs/decisions.md D4: identical absolute paths, so there is no host<->guest
// translation to do — operations receive paths already resolved against `cwd` by pi's
// own path-utils, per docs/decisions.md D9–D11, and hand them to the sandbox unchanged).
//
// grep is the one exception (D11): `GrepOperations` can't redirect grep.js's spawn, so
// it's re-implemented here as a guest `rg` shellout, reusing pi's own truncation helpers
// so the result looks exactly like the built-in tool's.
import path from "node:path";
import {
	DEFAULT_MAX_BYTES,
	formatSize,
	truncateHead,
	truncateLine,
	type BashOperations,
	type EditOperations,
	type FindOperations,
	type GrepToolDetails,
	type GrepToolInput,
	type LsOperations,
	type ReadOperations,
	type WriteOperations,
} from "@earendil-works/pi-coding-agent";
import type { SandboxClient } from "qafas-sandbox";

const IMAGE_MIME: Record<string, string> = {
	".png": "image/png",
	".jpg": "image/jpeg",
	".jpeg": "image/jpeg",
	".gif": "image/gif",
	".webp": "image/webp",
};

export function readOps(sb: SandboxClient, toolCallId: string): ReadOperations {
	return {
		readFile: (p) => sb.readFile(p, toolCallId),
		access: async (p) => {
			await sb.stat(p, toolCallId);
		},
		detectImageMimeType: async (p) => IMAGE_MIME[path.posix.extname(p).toLowerCase()] ?? null,
	};
}

export function writeOps(sb: SandboxClient, toolCallId: string): WriteOperations {
	return {
		writeFile: (p, c) => sb.writeFile(p, c, toolCallId),
		mkdir: (d) => sb.mkdir(d, toolCallId),
	};
}

export function editOps(sb: SandboxClient, toolCallId: string): EditOperations {
	return {
		readFile: (p) => sb.readFile(p, toolCallId),
		writeFile: (p, c) => sb.writeFile(p, c, toolCallId),
		access: async (p) => {
			await sb.stat(p, toolCallId);
		},
	};
}

export function lsOps(sb: SandboxClient, toolCallId: string): LsOperations {
	return {
		exists: async (p) => {
			try {
				await sb.stat(p, toolCallId);
				return true;
			} catch {
				return false;
			}
		},
		stat: async (p) => {
			const s = await sb.stat(p, toolCallId);
			return { isDirectory: () => s.is_dir };
		},
		readdir: (p) => sb.list(p, toolCallId),
	};
}

// find: run the guest's own `fd`/`find` over exec, never walk the tree over the wire.
export function findOps(sb: SandboxClient, toolCallId: string): FindOperations {
	return {
		exists: async (p) => {
			try {
				await sb.stat(p, toolCallId);
				return true;
			} catch {
				return false;
			}
		},
		glob: async (pattern, cwd, { limit }) => {
			const cmd =
				`command -v fd >/dev/null 2>&1 && fd --glob --hidden --exclude .git --exclude node_modules ${q(pattern)} ${q(cwd)} ` +
				`|| find ${q(cwd)} -name ${q(pattern)} -not -path '*/.git/*' -not -path '*/node_modules/*'`;
			const { stdout } = await sb.execBuffered(cmd, cwd, { toolCallId });
			return stdout.split("\n").filter(Boolean).slice(0, limit);
		},
	};
}

export function bashOps(sb: SandboxClient, toolCallId: string): BashOperations {
	return {
		// guest-agent's own exec.rs runs `bash -lc <cmd>`; we just forward the raw command.
		exec: (command, cwd, opts) => sb.exec(command, cwd, opts, toolCallId),
	};
}

// grep: createGrepTool always spawns a HOST rg (grep.js:144) regardless of `operations`.
// Shell out to the guest's ripgrep instead and reformat with pi's own truncation helpers
// so the result is indistinguishable from the built-in tool's (docs/decisions.md D11).
export async function sandboxGrep(
	sb: SandboxClient,
	cwd: string,
	p: GrepToolInput,
	toolCallId: string,
): Promise<{ content: { type: "text"; text: string }[]; details: GrepToolDetails | undefined }> {
	const root = p.path ? path.resolve(cwd, stripAtPrefix(p.path)) : cwd;
	const limit = Math.max(1, p.limit ?? 100);
	const args = [
		"rg",
		"--line-number",
		"--with-filename",
		"--color=never",
		...(p.ignoreCase ? ["-i"] : []),
		...(p.literal ? ["-F"] : []),
		...(p.context ? ["-C", String(p.context)] : []),
		...(p.glob ? ["--glob", p.glob] : []),
		"--max-count",
		String(limit),
		"--",
		p.pattern,
		root,
	];
	const cmd = args.map(q).join(" ");
	const { stdout, stderr, exit } = await sb.execBuffered(cmd, cwd, { toolCallId });
	// rg's own convention: exit 1 = no matches (not an error), exit >1 = real failure.
	if (exit === 1 && !stdout.trim()) {
		return { content: [{ type: "text", text: "No matches found" }], details: undefined };
	}
	if (exit !== 0 && exit !== 1) {
		return { content: [{ type: "text", text: `grep failed (exit ${exit}): ${stderr || stdout}` }], details: undefined };
	}

	const details: GrepToolDetails = {};
	const notices: string[] = [];
	let linesTruncated = false;
	const lines = stdout
		.split("\n")
		.filter(Boolean)
		.slice(0, limit)
		.map((l) => {
			const t = truncateLine(l);
			if (t.wasTruncated) linesTruncated = true;
			return t.text;
		});
	const trunc = truncateHead(lines.join("\n"), { maxLines: Number.MAX_SAFE_INTEGER });
	let output = trunc.content;
	if (linesTruncated) {
		details.linesTruncated = true;
		notices.push("long lines truncated");
	}
	if (trunc.truncated) {
		details.truncation = trunc;
		notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
	}
	if (notices.length) output += `\n\n[${notices.join(". ")}]`;
	return {
		content: [{ type: "text", text: output || "No matches found" }],
		details: Object.keys(details).length ? details : undefined,
	};
}

function q(s: string): string {
	return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Mirrors pi's own path-utils stripAtPrefix for raw strings that
 * bypass pi's pre-resolution (grep's `path` param, find's glob `pattern`/`cwd`). */
export function stripAtPrefix(p: string): string {
	return p.startsWith("@") ? p.slice(1) : p;
}
