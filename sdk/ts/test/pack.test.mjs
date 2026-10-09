import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { packWorkspace, unpackTar, validateTar } from "../dist/index.js";

// The one thing this must never do is upload a credential. Build a workspace with
// the usual offenders and assert on the actual archive members.
test("the workspace tar carries source and git history, never secrets or build output", async () => {
	const root = await mkdtemp(join(tmpdir(), "sbx-pack-"));
	const write = async (rel, body = "x") => {
		const p = join(root, rel);
		await mkdir(join(p, ".."), { recursive: true });
		await writeFile(p, body);
	};
	await write("src/main.ts");
	await write(".git/objects/ab/cdef");
	await write(".git/config");
	await write(".env", "OPENAI_API_KEY=sk-live");
	await write(".env.production", "x");
	await write(".env.example", "OPENAI_API_KEY=");
	await write("node_modules/left-pad/index.js");
	await write("dist/bundle.js");
	await write("deploy/server.key");
	await write("deploy/tls.pem");
	await write(".ssh/id_rsa");
	await write("credentials.json");
	await write("debug.log");
	await write("notes/keep.md");
	await write("notes/draft.md");
	await write(".sbxignore", "# local additions\nnotes/draft.md\n");

	const { tar, files } = await packWorkspace(root);
	const members = execFileSync("tar", ["-tf", "-"], { input: tar })
		.toString()
		.split("\n")
		.filter(Boolean)
		.sort();

	assert.deepEqual(members, [
		".env.example",
		".git/config",
		".git/objects/ab/cdef",
		".sbxignore",
		"notes/keep.md",
		"src/main.ts",
	]);
	assert.equal(files, members.length, "the reported file count is what was archived");
	assert.ok(tar.length > 0);
});

// A crafted 512-byte ustar header for one member, checksum computed for real (tar itself
// would reject a bad one, though validateTar/unpackTar never gets that far for these).
function tarHeader({ name, typeflag, linkname = "", size = 0 }) {
	const buf = Buffer.alloc(512);
	buf.write(name, 0, "utf8");
	buf.write("0000644\0", 100, "ascii");
	buf.write("0000000\0", 108, "ascii");
	buf.write("0000000\0", 116, "ascii");
	buf.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "ascii");
	buf.write("00000000000\0", 136, "ascii");
	buf.fill(0x20, 148, 156); // chksum field: spaces while summing
	buf[156] = typeflag.charCodeAt(0);
	buf.write(linkname, 157, "utf8");
	buf.write("ustar\0", 257, "ascii");
	buf.write("00", 263, "ascii");
	let sum = 0;
	for (const b of buf) sum += b;
	buf.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
	return buf;
}

test("validateTar refuses a symlink member, and unpackTar never spawns tar on it", async () => {
	const tar = tarHeader({ name: "evil-link", typeflag: "2", linkname: "/etc/passwd" });
	assert.throws(() => validateTar(tar), /symlink/);

	const dest = await mkdtemp(join(tmpdir(), "sbx-unpack-"));
	await assert.rejects(() => unpackTar(tar, dest), /symlink/);
});

test("validateTar refuses a hard link, a device node, and a path that escapes the destination", () => {
	assert.throws(() => validateTar(tarHeader({ name: "hard", typeflag: "1", linkname: "etc/passwd" })), /hard link/);
	assert.throws(() => validateTar(tarHeader({ name: "dev", typeflag: "3" })), /character device/);
	assert.throws(() => validateTar(tarHeader({ name: "../../etc/passwd", typeflag: "0" })), /outside the destination/);
	assert.throws(() => validateTar(tarHeader({ name: "/etc/passwd", typeflag: "0" })), /outside the destination/);
});

test("validateTar accepts an ordinary regular-file member", () => {
	assert.doesNotThrow(() => validateTar(tarHeader({ name: "src/main.ts", typeflag: "0" })));
});
