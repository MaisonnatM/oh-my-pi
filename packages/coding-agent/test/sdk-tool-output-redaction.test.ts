import { describe, expect, it } from "bun:test";
import { type } from "@oh-my-pi/omptype";
import type { AgentEvent } from "@oh-my-pi/pi-agent-core";
import type { ToolResultMessage } from "@oh-my-pi/pi-ai";
import { getBundledModel } from "@oh-my-pi/pi-catalog/models";
import { ModelRegistry } from "@oh-my-pi/pi-coding-agent/config/model-registry";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ToolDefinition } from "@oh-my-pi/pi-coding-agent/extensibility/extensions";
import { createAgentSession } from "@oh-my-pi/pi-coding-agent/sdk";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent/session/agent-session";
import { AuthStorage } from "@oh-my-pi/pi-coding-agent/session/auth-storage";
import { SessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";
import { TempDir } from "@oh-my-pi/pi-utils";

const TOKEN = `ghp_${"aB1".repeat(12)}`;
const PASSWORD = "synthetic opaque password 47";
const FIXTURE = `GITHUB_TOKEN=${TOKEN}\nDATABASE_PASSWORD="${PASSWORD}"\nPUBLIC_LABEL=visible\n`;

interface ScriptedToolCall {
	name: string;
	arguments: Record<string, unknown> | ((request: string) => Record<string, unknown>);
}

interface SessionCapture {
	requests: string[];
	events: string[];
	transcript: string;
	toolResults: ToolResultMessage[];
}

async function runSession(
	tempDir: TempDir,
	calls: ScriptedToolCall[],
	options: { secretsEnabled?: false; customTools?: ToolDefinition[]; finalText?: () => string } = {},
): Promise<SessionCapture> {
	const baseModel = getBundledModel("venice", "deepseek-v4-1-flash");
	const requests: string[] = [];
	const events: string[] = [];
	let finalText = "Synthetic sequence complete.";
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		async fetch(request) {
			requests.push(await request.text());
			const index = requests.length - 1;
			const call = calls[index];
			if (!call) finalText = options.finalText?.() ?? finalText;
			const delta = call
				? {
						tool_calls: [
							{
								index: 0,
								id: `call-${index}`,
								type: "function",
								function: {
									name: call.name,
									arguments: JSON.stringify(
										typeof call.arguments === "function" ? call.arguments(requests[index]!) : call.arguments,
									),
								},
							},
						],
					}
				: { content: finalText };
			const chunk = {
				id: `redaction-${index}`,
				object: "chat.completion.chunk",
				created: 0,
				model: baseModel.id,
				choices: [{ index: 0, delta, finish_reason: call ? "tool_calls" : "stop" }],
				usage: { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 },
			};
			return new Response(`data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`, {
				headers: { "content-type": "text/event-stream" },
			});
		},
	});
	let authStorage: AuthStorage | undefined;
	let session: AgentSession | undefined;
	try {
		authStorage = await AuthStorage.create(tempDir.join("auth.db"));
		authStorage.keys.setRuntime(baseModel.provider, "synthetic-local-key");
		const sessionManager = SessionManager.create(tempDir.path(), tempDir.join("sessions"));
		({ session } = await createAgentSession({
			cwd: tempDir.path(),
			agentDir: tempDir.path(),
			sessionManager,
			authStorage,
			getApiKey: () => "synthetic-local-key",
			modelRegistry: new ModelRegistry(authStorage, tempDir.join("models.yml")),
			settings: Settings.isolated({
				"compaction.enabled": false,
				"read.summarize.enabled": false,
				...(options.secretsEnabled === false ? { "secrets.enabled": false } : {}),
			}),
			model: { ...baseModel, baseUrl: `${server.url}v1` },
			disableExtensionDiscovery: true,
			skills: [],
			contextFiles: [],
			promptTemplates: [],
			slashCommands: [],
			enableMCP: false,
			enableLsp: false,
			skipPythonPreflight: true,
			cacheWarming: false,
			toolNames: [...new Set(calls.map(call => call.name))],
			restrictToolNames: true,
			allowRestrictedCustomTools: true,
			customTools: options.customTools,
			taskDepth: 1,
			agentId: "SubAgent",
		}));
		session.subscribe(event => events.push(JSON.stringify(event)));
		await session.sendUserMessage("Run the synthetic fixture tool sequence.");
		expect(session.messages.at(-1)).toMatchObject({
			role: "assistant",
			content: [{ type: "text", text: finalText }],
		});
		const sessionFile = sessionManager.getSessionFile();
		if (!sessionFile) throw new Error("Expected a persisted SDK session.");
		await session.dispose();
		session = undefined;
		const transcript = await Bun.file(sessionFile).text();
		const persisted = await SessionManager.open(sessionFile);
		const toolResults = persisted
			.getEntries()
			.flatMap(entry => (entry.type === "message" && entry.message.role === "toolResult" ? [entry.message] : []));
		expect(requests).toHaveLength(calls.length + 1);
		expect(toolResults.map(result => result.toolName)).toEqual(calls.map(call => call.name));
		return { requests, events, transcript, toolResults };
	} finally {
		try {
			await session?.dispose();
		} finally {
			authStorage?.close();
			await server.stop(true);
		}
	}
}

function expectProtected(capture: SessionCapture, secrets: string[]): void {
	for (const published of [...capture.requests, ...capture.events, capture.transcript]) {
		for (const secret of secrets) expect(published).not.toContain(secret);
	}
}

describe("SDK credential tool-output publication", () => {
	it("protects default read, grep and split shell output before model requests, events and JSONL", async () => {
		using tempDir = TempDir.createSync("@pi-sdk-tool-output-redaction-");
		await Bun.write(tempDir.join("fixture.env"), FIXTURE);
		const capture = await runSession(tempDir, [
			{ name: "read", arguments: { path: "fixture.env:raw" } },
			{ name: "grep", arguments: { pattern: "TOKEN|PASSWORD|PUBLIC_LABEL", path: "fixture.env" } },
			{
				name: "bash",
				arguments: {
					command:
						'while IFS= read -r line; do printf "%s" "$' +
						'{line%%=*}="; sleep 0.05; printf "%s\\n" "$' +
						'{line#*=}"; done < fixture.env',
					timeout: 10,
				},
			},
		]);

		expectProtected(capture, [TOKEN, PASSWORD]);
		expect(capture.toolResults.map(result => result.isError)).toEqual([false, false, false]);
		for (const result of capture.toolResults) {
			const text = JSON.stringify(result.content);
			expect(text).toContain("PUBLIC_LABEL=visible");
		}
		for (const request of capture.requests.slice(1)) {
			expect(request).toContain("PUBLIC_LABEL=visible");
		}
		expect(capture.events.join("\n")).toContain("PUBLIC_LABEL=visible");
		expect(capture.transcript).toContain("PUBLIC_LABEL=visible");
		expect(await Bun.file(tempDir.join("fixture.env")).text()).toBe(FIXTURE);
	}, 30_000);

	it("restores a read placeholder only for the actual write, keeping tool calls and final prose masked publicly", async () => {
		using tempDir = TempDir.createSync("@pi-sdk-tool-placeholder-write-");
		await Bun.write(tempDir.join("source.txt"), `DATABASE_PASSWORD="${PASSWORD}"\nPUBLIC_LABEL=visible\n`);
		let placeholder = "";
		const capture = await runSession(
			tempDir,
			[
				{ name: "read", arguments: { path: "source.txt:raw" } },
				{
					name: "write",
					arguments(request) {
						const body: { messages: { role: string; content?: string }[] } = JSON.parse(request);
						const result = body.messages.findLast(message => message.role === "tool");
						const match = result?.content?.match(/\$\$[^$\r\n]+\$\$/);
						if (!match) throw new Error("Protected read did not return a reversible placeholder.");
						placeholder = match[0];
						return {
							path: "destination.txt",
							content: `DATABASE_PASSWORD="${placeholder}"\nPUBLIC_LABEL=copied\n`,
						};
					},
				},
			],
			{ finalText: () => `Copied ${placeholder}.` },
		);

		expect(await Bun.file(tempDir.join("destination.txt")).text()).toBe(
			`DATABASE_PASSWORD="${PASSWORD}"\nPUBLIC_LABEL=copied\n`,
		);
		expectProtected(capture, [PASSWORD]);
		expect(capture.toolResults.map(result => result.isError)).toEqual([false, false]);
		expect(capture.requests[2]).toContain(placeholder);
		const toolCalls = capture.events.flatMap(serialized => {
			const event: AgentEvent = JSON.parse(serialized);
			return event.type === "message_end" && event.message.role === "assistant"
				? event.message.content.flatMap(block => (block.type === "toolCall" ? [block] : []))
				: [];
		});
		expect(toolCalls.find(call => call.name === "write")?.arguments).toEqual({
			path: "destination.txt",
			content: `DATABASE_PASSWORD="${placeholder}"\nPUBLIC_LABEL=copied\n`,
		});
		expect(capture.transcript).toContain(placeholder);
		const finalMessage = capture.events
			.map((serialized): AgentEvent => JSON.parse(serialized))
			.filter(event => event.type === "message_end" && event.message.role === "assistant")
			.at(-1);
		expect(finalMessage).toMatchObject({
			type: "message_end",
			message: { role: "assistant", content: [{ type: "text", text: `Copied ${placeholder}.` }] },
		});
		expect(capture.transcript).toContain(`Copied ${placeholder}.`);
		expect(await Bun.file(tempDir.join("source.txt")).text()).toBe(
			`DATABASE_PASSWORD="${PASSWORD}"\nPUBLIC_LABEL=visible\n`,
		);
	}, 30_000);

	it("allows unrelated placeholder-shaped literals in actual file and shell execution", async () => {
		using tempDir = TempDir.createSync("@pi-sdk-tool-placeholder-literal-");
		const literal = "$$ABCD$$";
		const capture = await runSession(tempDir, [
			{ name: "write", arguments: { path: "literal.txt", content: `literal=${literal}\n` } },
			{ name: "bash", arguments: { command: "printf '%s\\n' '$$ABCD$$'", timeout: 10 } },
		]);

		expect(capture.toolResults.map(result => result.isError)).toEqual([false, false]);
		expect(await Bun.file(tempDir.join("literal.txt")).text()).toBe(`literal=${literal}\n`);
		expect(JSON.stringify(capture.toolResults[1].content)).toContain(literal);
		expect(capture.requests[2]).toContain(literal);
	}, 30_000);

	it("protects nested custom metadata and thrown errors while retaining their public structure", async () => {
		using tempDir = TempDir.createSync("@pi-sdk-tool-metadata-redaction-");
		const shortPassword = "x7!";
		const metadataTool: ToolDefinition = {
			name: "fixture_metadata",
			label: "Fixture metadata",
			description: "Return synthetic fixture metadata.",
			parameters: type({}),
			async execute() {
				return {
					content: [{ type: "text", text: "Metadata ready. PUBLIC_LABEL=visible" }],
					details: { label: "visible", nested: { password: shortPassword, [TOKEN]: "public-key-label" } },
					providerMetadata: {
						type: "computer",
						screenshot: { type: "computer_screenshot", file_id: "synthetic-screenshot" },
						acknowledgedSafetyChecks: [{ id: "fixture-check", code: "synthetic-review", message: FIXTURE }],
					},
				};
			},
		};
		const errorTool: ToolDefinition = {
			name: "fixture_error",
			label: "Fixture error",
			description: "Throw a synthetic credential-bearing failure.",
			parameters: type({}),
			async execute() {
				throw new Error(`Synthetic backend rejected the fixture.\n${FIXTURE}`);
			},
		};
		const capture = await runSession(
			tempDir,
			[
				{ name: metadataTool.name, arguments: {} },
				{ name: errorTool.name, arguments: {} },
			],
			{ customTools: [metadataTool, errorTool] },
		);

		expectProtected(capture, [TOKEN, PASSWORD, shortPassword]);
		expect(capture.toolResults.map(result => result.isError)).toEqual([false, true]);
		expect(capture.toolResults[0]).toMatchObject({
			details: { label: "visible", nested: { password: expect.any(String) } },
			providerMetadata: {
				type: "computer",
				screenshot: { type: "computer_screenshot", file_id: "synthetic-screenshot" },
				acknowledgedSafetyChecks: [{ id: "fixture-check", code: "synthetic-review", message: expect.any(String) }],
			},
		});
		expect(JSON.stringify(capture.toolResults[0].details)).toContain("public-key-label");
		expect(capture.requests[1]).toContain("Metadata ready. PUBLIC_LABEL=visible");
		expect(capture.requests[2]).toContain("Synthetic backend rejected the fixture.");
		expect(JSON.stringify(capture.toolResults[1].content)).toContain("Synthetic backend rejected the fixture.");
	}, 30_000);

	it("honors an explicit opt-out for future model requests, public events and persisted tool results", async () => {
		using tempDir = TempDir.createSync("@pi-sdk-tool-output-opt-out-");
		await Bun.write(tempDir.join("fixture.env"), FIXTURE);
		const capture = await runSession(tempDir, [{ name: "read", arguments: { path: "fixture.env:raw" } }], {
			secretsEnabled: false,
		});

		expect(capture.toolResults[0].isError).toBe(false);
		for (const published of [capture.requests[1], capture.events.join("\n"), capture.transcript]) {
			expect(published).toContain(TOKEN);
			expect(published).toContain(PASSWORD);
			expect(published).toContain("PUBLIC_LABEL=visible");
		}
		expect(JSON.stringify(capture.toolResults[0].content)).toContain(PASSWORD);
		expect(await Bun.file(tempDir.join("fixture.env")).text()).toBe(FIXTURE);
	}, 30_000);
});
