// Trusting a remote qafas over TLS (docs/security.md M31).
//
// Node's fetch and its global WebSocket are both undici, and neither takes a
// per-request agent or CA. What they do honour is the process default CA set, so
// `trustHost` adds what this process should trust to that set:
//
//   * `SBX_CA_FILE` — a CA bundle, for a real (internal) PKI;
//   * `caFingerprint` — the SHA-256 of the certificate qafas generated for
//     itself, which the control plane hands back with the sandbox. The
//     certificate is fetched once, checked against the pin, and only then
//     trusted, so a wrong certificate fails before a single request is sent.
//
// `NODE_EXTRA_CA_CERTS=/path/ca.pem` does the same thing for the CA-file case
// without any code, and is the right answer when you can set it at launch.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { connect, getCACertificates, setDefaultCACertificates } from "node:tls";

/** Hosts already trusted in this process, so a per-tool-call acquire costs nothing. */
const trusted = new Set<string>();

export interface TrustOpts {
	/** SHA-256 of the DER of the certificate the host must present. Colons and case ignored. */
	caFingerprint?: string;
	/** PEM bundle to trust. Defaults to `$SBX_CA_FILE`. */
	caFile?: string;
}

/** Normalises `AB:CD:…` (openssl) and `abcd…` (qafas) to the same string. */
export function normaliseFingerprint(fp: string): string {
	return fp.replace(/[:\s]/g, "").toLowerCase();
}

/**
 * Makes `url`'s certificate verifiable by this process. A no-op for http:// and
 * for a host already trusted. Throws when a pinned host presents anything else,
 * which is the one failure that must not be recoverable.
 */
export async function trustHost(url: string, opts: TrustOpts = {}): Promise<void> {
	const u = new URL(url);
	if (u.protocol !== "https:") return;
	const caFile = opts.caFile ?? process.env.SBX_CA_FILE;
	const pin = opts.caFingerprint ? normaliseFingerprint(opts.caFingerprint) : undefined;
	if (!caFile && !pin) return; // system roots, nothing to add
	const key = `${u.host}|${pin ?? ""}|${caFile ?? ""}`;
	if (trusted.has(key)) return;

	const extra: string[] = [];
	if (caFile) extra.push(await readFile(caFile, "utf8"));
	if (pin) {
		const der = await peerCertificate(u);
		const got = createHash("sha256").update(der).digest("hex");
		if (got !== pin) throw new Error(`sandbox host ${u.host} presented certificate ${got}, expected ${pin}`);
		extra.push(pem(der));
	}
	setDefaultCACertificates([...getCACertificates(), ...extra]);
	trusted.add(key);
}

/** The leaf certificate the host presents, DER. Verification is deliberately off: the pin is the verification. */
function peerCertificate(u: URL): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const socket = connect(
			{
				host: u.hostname,
				port: Number(u.port || 443),
				servername: isIP(u.hostname) ? undefined : u.hostname,
				rejectUnauthorized: false,
			},
			() => {
				const cert = socket.getPeerCertificate();
				socket.destroy();
				if (!cert?.raw) reject(new Error(`no certificate from ${u.host}`));
				else resolve(cert.raw);
			},
		);
		socket.setTimeout(10_000, () => socket.destroy(new Error(`TLS handshake with ${u.host} timed out`)));
		socket.on("error", reject);
	});
}

function pem(der: Buffer): string {
	const b64 = der.toString("base64").replace(/(.{64})/g, "$1\n");
	return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}
