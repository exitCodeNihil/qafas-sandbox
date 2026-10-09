// Packing a workspace for a remote sandbox (docs/security.md M32).
//
// Only the remote tier copies the workspace; the local tiers share it. What
// crosses the wire is therefore worth minimising, both for the upload and
// because a credential that never leaves the host cannot leak from the sandbox.
// Git history *is* sent (`.git/objects` included): agents rebase, bisect and log.
//
// The list below is the floor. A workspace can exclude more with `.sbxignore` in
// its root: one glob per line, `#` comments, `!` to un-exclude, a trailing `/`
// for directories only, a `/` anywhere to anchor to the workspace root.

import { spawn } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Readable } from "node:stream";

/** Never uploaded. Build output and caches (big, reproducible) then secrets (small, catastrophic). */
export const DEFAULT_IGNORE = [
	"node_modules",
	".venv",
	"venv",
	"__pycache__",
	"target",
	"dist",
	"build",
	".next",
	".cache",
	"*.log",
	".env",
	".env.*",
	"!.env.example",
	"*.pem",
	"*.key",
	"id_rsa*",
	".aws",
	".ssh",
	".gnupg",
	".netrc",
	".npmrc",
	".pypirc",
	"credentials*",
	"secrets*",
];

interface Rule {
	re: RegExp;
	dirOnly: boolean;
	anchored: boolean;
	negate: boolean;
}

function compile(line: string): Rule | undefined {
	let p = line.trim();
	if (!p || p.startsWith("#")) return undefined;
	const negate = p.startsWith("!");
	if (negate) p = p.slice(1);
	const dirOnly = p.endsWith("/");
	if (dirOnly) p = p.slice(0, -1);
	const anchored = p.includes("/"); // a `/` anywhere anchors to the workspace root
	if (p.startsWith("/")) p = p.slice(1);
	if (!p) return undefined;
	const re = new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]")}$`);
	return { re, dirOnly, anchored, negate };
}

export function compileIgnore(lines: string[]): Rule[] {
	return lines.map(compile).filter((r): r is Rule => r !== undefined);
}

/** Last matching rule wins, so `!.env.example` survives `.env.*`. */
export function isIgnored(rules: Rule[], relPath: string, isDir: boolean): boolean {
	const name = relPath.slice(relPath.lastIndexOf("/") + 1);
	let ignored = false;
	for (const r of rules) {
		if (r.dirOnly && !isDir) continue;
		if (r.re.test(r.anchored ? relPath : name)) ignored = !r.negate;
	}
	return ignored;
}

/** Every path under `root` that survives the rules, relative to `root`, sorted by discovery. */
export async function listWorkspace(root: string, rules: Rule[]): Promise<string[]> {
	const out: string[] = [];
	const walk = async (rel: string): Promise<void> => {
		const entries = await readdir(rel ? join(root, rel) : root, { withFileTypes: true });
		for (const e of entries) {
			const path = rel ? `${rel}/${e.name}` : e.name;
			const isDir = e.isDirectory();
			if (isIgnored(rules, path, isDir)) continue;
			if (isDir) await walk(path);
			else out.push(path);
		}
	};
	await walk("");
	return out;
}

export interface Packed {
	tar: Buffer;
	files: number;
}

/**
 * Tars `cwd` minus everything the rules exclude.
 *
 * design: shells out to the host's own `tar` rather than adding a JS tar
 * dependency; the file list goes in on stdin (NUL separated) so no filename can
 * be misread as an option. Swap for the `tar` npm package if this ever has to
 * run somewhere without a `tar` binary on PATH.
 */
export async function packWorkspace(cwd: string, extraIgnore: string[] = []): Promise<Packed> {
	const sbxignore = await readFile(join(cwd, ".sbxignore"), "utf8").catch(() => "");
	const rules = compileIgnore([...DEFAULT_IGNORE, ...sbxignore.split("\n"), ...extraIgnore]);
	const files = await listWorkspace(cwd, rules);
	const tar = await runTar(cwd, files);
	return { tar, files: files.length };
}

export interface PackedStream {
	/** `tar`'s stdout; the caller must read it to the end (e.g. as a fetch body) before
	 * the underlying process is done — nothing here buffers it. */
	stream: Readable;
	files: number;
}

/**
 * Streaming counterpart to `packWorkspace`: same ignore rules and file list, but hands
 * back `tar`'s stdout directly instead of collecting it into a `Buffer` — for
 * `upload()`'s directory case, so a multi-GiB workspace never sits fully in memory.
 */
export async function packWorkspaceStream(cwd: string, extraIgnore: string[] = []): Promise<PackedStream> {
	const sbxignore = await readFile(join(cwd, ".sbxignore"), "utf8").catch(() => "");
	const rules = compileIgnore([...DEFAULT_IGNORE, ...sbxignore.split("\n"), ...extraIgnore]);
	const files = await listWorkspace(cwd, rules);
	const child = spawn("tar", ["-cf", "-", "-C", cwd, "--null", "-T", "-"]);
	const errs: Buffer[] = [];
	child.stderr.on("data", (d: Buffer) => errs.push(d));
	child.on("close", (code) => {
		if (code !== 0) child.stdout.destroy(new Error(`tar exit ${code}: ${Buffer.concat(errs).toString().trim()}`));
	});
	child.stdin.on("error", () => {}); // a reader that aborts early closes stdin's pipe; runTar's buffered path has no analogous consumer to abort early
	child.stdin.end(files.length ? `${files.join("\0")}\0` : "");
	return { stream: child.stdout, files: files.length };
}

const TAR_BLOCK = 512;

/** typeflag -> what it is, for members `validateTar` refuses outright: links (can point
 * anywhere on the host filesystem), device/FIFO nodes, and GNU/PAX extended headers
 * (long names, long links, per-entry/global attributes) we don't parse and so can't
 * trust the following entries' names/sizes against. */
const UNSAFE_TAR_TYPEFLAGS: Record<string, string> = {
	"1": "hard link",
	"2": "symlink",
	"3": "character device",
	"4": "block device",
	"6": "FIFO",
	L: "GNU long-name header",
	K: "GNU long-link header",
	x: "PAX extended header",
	g: "PAX global header",
};

function tarField(header: Buffer, offset: number, length: number): string {
	const raw = header.subarray(offset, offset + length);
	const nul = raw.indexOf(0);
	return (nul === -1 ? raw : raw.subarray(0, nul)).toString("utf8");
}

/** Octal ASCII only (the format `packWorkspace`/qafas produce); base-256 GNU size
 * encoding (files >= 8 GiB) isn't handled — reject rather than misparse. */
function tarSize(header: Buffer): number {
	const raw = header.subarray(124, 124 + 12);
	if (raw[0] & 0x80) throw new Error("refusing to extract tar: base-256 size field not supported");
	const s = raw.toString("ascii").replace(/\0.*$/, "").trim();
	return s ? Number.parseInt(s, 8) : 0;
}

/**
 * Walks a tar's 512-byte headers (no extraction, just enough parsing to check every
 * member) and throws if any member is absolute, escapes the destination via a `..`
 * segment, or is a link/device/FIFO/extended-header type. Mirrors the checks
 * sdk/python's `unpack_tar` gets from the stdlib `tarfile` `data` filter — qafas/
 * guest-agent already enforce the real workspace boundary server-side, this guards
 * against a compromised or misbehaving host handing back a hostile archive.
 */
export function validateTar(tar: Buffer): void {
	let pos = 0;
	while (pos + TAR_BLOCK <= tar.length) {
		const header = tar.subarray(pos, pos + TAR_BLOCK);
		if (header.every((b) => b === 0)) break; // end-of-archive marker
		const typeflag = String.fromCharCode(header[156]);
		const unsafe = UNSAFE_TAR_TYPEFLAGS[typeflag];
		if (unsafe) throw new Error(`refusing to extract tar: member is a ${unsafe}`);
		const prefix = tarField(header, 345, 155); // ustar prefix, joined with name for long paths
		const name = tarField(header, 0, 100);
		const full = prefix ? `${prefix}/${name}` : name;
		if (full.startsWith("/") || full.split("/").includes("..")) {
			throw new Error(`refusing to extract tar member outside the destination: ${full}`);
		}
		pos += TAR_BLOCK + Math.ceil(tarSize(header) / TAR_BLOCK) * TAR_BLOCK;
	}
}

/**
 * Extracts a tar stream (as produced by `packWorkspace`/`downloadTar`) into `destDir`,
 * after `validateTar` refuses anything unsafe. Mirrors pi-extension/index.ts's local
 * `unpackTar`; kept here so `client.download()` and any other consumer share one
 * implementation instead of copy-pasting the spawn.
 */
export function unpackTar(tar: Buffer, destDir: string): Promise<void> {
	return new Promise((resolve, reject) => {
		try {
			validateTar(tar);
		} catch (err) {
			reject(err);
			return;
		}
		const child = spawn("tar", ["-xf", "-", "-C", destDir, "--no-same-owner", "--no-same-permissions"]);
		const errs: Buffer[] = [];
		child.stderr.on("data", (d: Buffer) => errs.push(d));
		child.on("error", reject);
		child.on("close", (code) =>
			code === 0 ? resolve() : reject(new Error(`tar extract exit ${code}: ${Buffer.concat(errs).toString().trim()}`)),
		);
		child.stdin.on("error", reject);
		child.stdin.end(tar);
	});
}

function runTar(cwd: string, files: string[]): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const child = spawn("tar", ["-cf", "-", "-C", cwd, "--null", "-T", "-"]);
		const chunks: Buffer[] = [];
		const errs: Buffer[] = [];
		child.stdout.on("data", (d: Buffer) => chunks.push(d));
		child.stderr.on("data", (d: Buffer) => errs.push(d));
		child.on("error", reject);
		child.on("close", (code) =>
			code === 0
				? resolve(Buffer.concat(chunks))
				: reject(new Error(`tar exit ${code}: ${Buffer.concat(errs).toString().trim()}`)),
		);
		child.stdin.on("error", reject);
		child.stdin.end(files.length ? `${files.join("\0")}\0` : "");
	});
}
