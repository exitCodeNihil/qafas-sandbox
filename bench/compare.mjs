#!/usr/bin/env node
// bench/compare.mjs a.json b.json — prints per-metric deltas (b vs a) as a markdown table.
import fs from "node:fs";

const [, , aPath, bPath] = process.argv;
if (!aPath || !bPath) {
	console.error("usage: bench/compare.mjs <a.json> <b.json>");
	process.exit(2);
}
const a = JSON.parse(fs.readFileSync(aPath, "utf8"));
const b = JSON.parse(fs.readFileSync(bPath, "utf8"));

function flatten(obj, prefix = "", out = {}) {
	for (const [k, v] of Object.entries(obj)) {
		const key = prefix ? `${prefix}.${k}` : k;
		if (v && typeof v === "object" && !Array.isArray(v)) flatten(v, key, out);
		else out[key] = v;
	}
	return out;
}

const flatA = flatten(a.cases ?? a);
const flatB = flatten(b.cases ?? b);
const keys = [...new Set([...Object.keys(flatA), ...Object.keys(flatB)])].sort();

console.log(`comparing ${a.backend ?? aPath} (a) vs ${b.backend ?? bPath} (b)\n`);
console.log(`| metric | a | b | delta | delta % |`);
console.log(`|---|---|---|---|---|`);
for (const k of keys) {
	const av = flatA[k];
	const bv = flatB[k];
	if (typeof av === "number" && typeof bv === "number") {
		const delta = bv - av;
		const pct = av !== 0 ? ((delta / av) * 100).toFixed(1) : "n/a";
		console.log(`| ${k} | ${av.toFixed(2)} | ${bv.toFixed(2)} | ${delta >= 0 ? "+" : ""}${delta.toFixed(2)} | ${pct}% |`);
	} else {
		console.log(`| ${k} | ${av ?? "-"} | ${bv ?? "-"} | - | - |`);
	}
}
