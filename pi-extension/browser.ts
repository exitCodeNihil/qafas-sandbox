// Browser tools: one Chromium process per sandbox (guest-agent launches it lazily on
// first CDP connect), one context per pi session (docs/decisions.md D12). Snapshots use
// `page.ariaSnapshot({mode:"ai"})`, the public form of the former `_snapshotForAI` (D13).
import { chromium, type Browser, type BrowserContext, type Page } from "playwright-core";
import { Type } from "typebox";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { SandboxClient } from "qafas-sandbox";

export class BrowserSession {
	private browser: Browser | undefined;
	private context: BrowserContext | undefined;
	private page: Page | undefined;

	constructor(private readonly sb: SandboxClient) {}

	private async ensurePage(): Promise<Page> {
		if (this.page && !this.page.isClosed()) return this.page;
		if (!this.browser) {
			this.browser = await chromium.connectOverCDP(this.sb.cdpUrl, {
				headers: { Authorization: `Bearer ${this.sb.token}` },
			});
		}
		this.context = this.browser.contexts()[0] ?? (await this.browser.newContext());
		this.page = this.context.pages()[0] ?? (await this.context.newPage());
		return this.page;
	}

	async navigate(url: string, toolCallId = ""): Promise<void> {
		const page = await this.ensurePage();
		// Log the intent before the load so denied navigations are audited too.
		await this.sb.postEvent("browser.navigate", { url }, toolCallId).catch(() => {});
		await page.goto(url, { waitUntil: "domcontentloaded" });
	}

	async snapshot(): Promise<string> {
		const page = await this.ensurePage();
		// Playwright 1.63 made the old private `_snapshotForAI` public as `mode: "ai"`
		// (D13): refs come back as `[ref=e12]` and resolve via `aria-ref=e12` locators.
		return page.ariaSnapshot({ mode: "ai" });
	}

	async click(ref: string): Promise<void> {
		const page = await this.ensurePage();
		await page.locator(`aria-ref=${ref}`).click();
	}

	async type(ref: string, text: string, submit?: boolean): Promise<void> {
		const page = await this.ensurePage();
		const locator = page.locator(`aria-ref=${ref}`);
		await locator.fill(text);
		if (submit) await locator.press("Enter");
	}

	async screenshot(): Promise<Buffer> {
		const page = await this.ensurePage();
		return page.screenshot({ type: "png" });
	}

	async back(): Promise<void> {
		const page = await this.ensurePage();
		await page.goBack();
	}

	async close(): Promise<void> {
		const browser = this.browser;
		this.browser = undefined;
		this.context = undefined;
		this.page = undefined;
		if (!browser) return;
		// Best-effort: sandbox teardown reaps the Chromium process regardless, so a stuck
		// close() (e.g. a wedged CDP connection) must not hang the caller — wait up to 2s
		// and log whichever way it went rather than swallowing the outcome silently.
		const timeout = new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 2000));
		const outcome = await Promise.race([browser.close().then(() => "closed" as const), timeout]).catch(() => "error" as const);
		if (outcome !== "closed") console.error(`browser session: close() ${outcome === "timeout" ? "timed out after 2s" : "failed"}, leaving teardown to the sandbox`);
	}
}

/** Registers the six browser_* tools. getSession() must lazily connect (session_start
 * already kicked off sandbox acquisition; the CDP connect itself happens on first use). */
export function registerBrowserTools(pi: ExtensionAPI, getSession: () => Promise<BrowserSession>): void {
	pi.registerTool({
		name: "browser_navigate",
		label: "Browser: Navigate",
		description: "Navigate the sandboxed browser to a URL.",
		promptSnippet: "browser_navigate({url}) - navigate the sandboxed browser to a URL",
		parameters: Type.Object({ url: Type.String({ description: "URL to open" }) }),
		async execute(id, params) {
			const session = await getSession();
			await session.navigate(params.url, id);
			return { content: [{ type: "text", text: `Navigated to ${params.url}` }], details: undefined };
		},
	});

	pi.registerTool({
		name: "browser_snapshot",
		label: "Browser: Snapshot",
		description: "Take an accessibility snapshot of the current page, returning element refs usable by browser_click and browser_type.",
		promptSnippet: "browser_snapshot({}) - accessibility snapshot with element refs (e12-style)",
		parameters: Type.Object({}),
		async execute() {
			const session = await getSession();
			const text = await session.snapshot();
			return { content: [{ type: "text", text }], details: undefined };
		},
	});

	pi.registerTool({
		name: "browser_click",
		label: "Browser: Click",
		description: "Click an element by the ref returned from browser_snapshot.",
		promptSnippet: "browser_click({ref}) - click an element from browser_snapshot",
		parameters: Type.Object({ ref: Type.String({ description: "Element ref from browser_snapshot, e.g. e12" }) }),
		async execute(_id, params) {
			const session = await getSession();
			await session.click(params.ref);
			return { content: [{ type: "text", text: `Clicked ${params.ref}` }], details: undefined };
		},
	});

	pi.registerTool({
		name: "browser_type",
		label: "Browser: Type",
		description: "Type text into an element by its browser_snapshot ref, optionally submitting with Enter.",
		promptSnippet: "browser_type({ref,text,submit?}) - type into an element from browser_snapshot",
		parameters: Type.Object({
			ref: Type.String({ description: "Element ref from browser_snapshot" }),
			text: Type.String(),
			submit: Type.Optional(Type.Boolean({ description: "Press Enter after typing" })),
		}),
		async execute(_id, params) {
			const session = await getSession();
			await session.type(params.ref, params.text, params.submit);
			return { content: [{ type: "text", text: `Typed into ${params.ref}` }], details: undefined };
		},
	});

	pi.registerTool({
		name: "browser_screenshot",
		label: "Browser: Screenshot",
		description: "Take a screenshot of the current page.",
		promptSnippet: "browser_screenshot({}) - screenshot the current page",
		parameters: Type.Object({}),
		async execute() {
			const session = await getSession();
			const png = await session.screenshot();
			return {
				content: [{ type: "image", data: png.toString("base64"), mimeType: "image/png" }],
				details: undefined,
			};
		},
	});

	pi.registerTool({
		name: "browser_back",
		label: "Browser: Back",
		description: "Navigate the sandboxed browser back one page in history.",
		promptSnippet: "browser_back({}) - go back one page",
		parameters: Type.Object({}),
		async execute() {
			const session = await getSession();
			await session.back();
			return { content: [{ type: "text", text: "Went back" }], details: undefined };
		},
	});
}
