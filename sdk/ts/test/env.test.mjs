import { test } from "node:test";
import assert from "node:assert/strict";
import { filterEnv } from "../dist/index.js";

test("host secrets never cross into the sandbox", () => {
	const out = filterEnv({ ANTHROPIC_API_KEY: "sk", AWS_SECRET_ACCESS_KEY: "x", GITHUB_TOKEN: "t", TMPDIR: "/host/tmp", HOME: "/Users/me", TERM: "xterm", LC_ALL: "C", MYVAR: "1" }, "MYVAR");
	assert.deepEqual(out, { TERM: "xterm", LC_ALL: "C", MYVAR: "1" });
	assert.equal(filterEnv(undefined), undefined);
});
