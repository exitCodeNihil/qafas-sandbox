// Declarative Dockerfile builder for `snapshots.create({ dockerfile })` (docs/protocol.md
// §3a "Snapshots"). design: string concatenation, not a Dockerfile AST — a snapshot
// build is a one-shot `podman build`/rootfs step server-side, there is nothing here that
// needs parsing back.

/** Single-quotes `s` for a POSIX shell, escaping embedded quotes. */
function shQuote(s: string): string {
	return `'${s.replace(/'/g, `'\\''`)}'`;
}

export class Image {
	private readonly lines: string[] = [];

	private constructor(base: string) {
		this.lines.push(`FROM ${base}`);
	}

	/** Starts a new builder from a base image, e.g. `Image.base("node:22-bookworm")`. */
	static base(image: string): Image {
		return new Image(image);
	}

	run(cmd: string): this {
		this.lines.push(`RUN ${cmd}`);
		return this;
	}

	workdir(dir: string): this {
		this.lines.push(`WORKDIR ${dir}`);
		return this;
	}

	env(vars: Record<string, string>): this {
		for (const [k, v] of Object.entries(vars)) this.lines.push(`ENV ${k}=${JSON.stringify(v)}`);
		return this;
	}

	pipInstall(pkgs: string[]): this {
		if (pkgs.length) this.lines.push(`RUN pip install --no-cache-dir ${pkgs.map(shQuote).join(" ")}`);
		return this;
	}

	npmInstall(pkgs: string[]): this {
		if (pkgs.length) this.lines.push(`RUN npm install -g ${pkgs.map(shQuote).join(" ")}`);
		return this;
	}

	/**
	 * Writes `content` to `destPath` in the image. A Dockerfile `COPY` needs a build
	 * context file that doesn't exist here, so this embeds the content as base64 and
	 * decodes it in a `RUN` step instead.
	 */
	copyText(destPath: string, content: string): this {
		const b64 = Buffer.from(content, "utf8").toString("base64");
		this.lines.push(`RUN mkdir -p "$(dirname ${shQuote(destPath)})" && echo ${shQuote(b64)} | base64 -d > ${shQuote(destPath)}`);
		return this;
	}

	toDockerfile(): string {
		return `${this.lines.join("\n")}\n`;
	}

	toString(): string {
		return this.toDockerfile();
	}
}
