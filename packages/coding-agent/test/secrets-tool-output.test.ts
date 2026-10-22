import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { type } from "@oh-my-pi/omptype";
import {
	Agent,
	type AgentEvent,
	type AgentTool,
	type AgentToolContext,
	type AgentToolResult,
} from "@oh-my-pi/pi-agent-core";
import { createMockModel } from "@oh-my-pi/pi-ai/providers/mock";
import { ShellArgsSchema } from "@oh-my-pi/pi-catalog/discovery/cursor-proto";
import { create } from "@oh-my-pi/pi-catalog/discovery/protobuf";
import { ModelRegistry } from "../src/config/model-registry";
import { Settings } from "../src/config/settings";
import { CursorExecHandlers } from "../src/cursor";
import { EditTool } from "../src/edit";
import { cfgEditMode } from "../src/edit/settings";
import {
	CredentialToolOutputBoundary,
	SecretObfuscator,
	builtinCredentialSecretEntries,
	deobfuscateToolArguments,
} from "../src/secrets";
import type { AuthStorage } from "../src/session/auth-storage";
import { SessionManager } from "../src/session/session-manager";
import { StreamRedactor } from "../src/stream/redactor";
import { type ToolSession } from "../src/tools";
import { BashTool } from "../src/tools/bash";
import { GrepTool } from "../src/tools/grep";
import { buildInMemoryMultiRangeResult, buildInMemoryTextResult } from "../src/tools/read-format";
import { postProcessToolResult } from "../src/tools/output-meta";
import { ReadTool } from "../src/tools/read";
import { createInMemoryAuthStorage } from "./helpers/agent-session-setup";

const KEY = "synthetic-test-placeholder-key-987654321";
const PASSWORD = "opaque local password 98231";
const TOKEN = `ghp_${"A1b2C3d4".repeat(5)}`;
const directories: string[] = [];
const authStorages: AuthStorage[] = [];

function policy(): { obfuscator: SecretObfuscator; boundary: CredentialToolOutputBoundary } {
	const obfuscator = new SecretObfuscator(builtinCredentialSecretEntries(), KEY);
	return { obfuscator, boundary: new CredentialToolOutputBoundary(() => obfuscator) };
}

function text(result: AgentToolResult<unknown>): string {
	return result.content.flatMap(block => (block.type === "text" ? [block.text] : [])).join("\n");
}

async function fixture(boundary: CredentialToolOutputBoundary): Promise<ToolSession> {
	const cwd = await fs.mkdtemp(path.join(os.tmpdir(), "credential-output-"));
	directories.push(cwd);
	return {
		cwd,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({
			"read.summarize.enabled": false,
			"tools.outputMaxColumns": 64,
			"tools.approvalMode": "yolo",
		}),
		toolOutputBoundary: boundary,
		allocateOutputArtifact: async () => ({ id: "synthetic-output", path: path.join(cwd, "capture.txt") }),
	};
}

function toolContext(boundary: CredentialToolOutputBoundary): AgentToolContext {
	const auth = createInMemoryAuthStorage();
	authStorages.push(auth);
	return {
		sessionManager: SessionManager.inMemory(),
		modelRegistry: new ModelRegistry(auth),
		model: undefined,
		isIdle: () => true,
		hasQueuedMessages: () => false,
		abort: () => {},
		toolOutputBoundary: boundary,
	};
}

afterEach(async () => {
	for (const auth of authStorages.splice(0)) auth.close();
	await Promise.all(directories.splice(0).map(directory => fs.rm(directory, { recursive: true, force: true })));
});

describe("credential publication boundary", () => {
	it("discovers complete-envelope values before masking text, metadata keys, and short sensitive fields", () => {
		const { boundary, obfuscator } = policy();
		const raw = {
			content: [{ type: "text" as const, text: `copy ${PASSWORD}; ${TOKEN}; benign text` }],
			details: {
				nested: { password: PASSWORD, apiKey: "x" },
				copy: PASSWORD,
				[TOKEN]: "metadata",
				unrelated: "example text",
			},
		};
		const safe = boundary.result(raw);
		expect(JSON.stringify(safe)).not.toContain(PASSWORD);
		expect(JSON.stringify(safe)).not.toContain(TOKEN);
		if (!safe.details) throw new Error("Protected result lost its metadata");
		expect(safe.details.unrelated).toBe("example text");
		expect(safe.details.nested.apiKey).not.toBe("x");
		expect(obfuscator.deobfuscate(safe.details.nested.apiKey)).toBe("x");
		expect(obfuscator.deobfuscate(safe.details.nested.password)).toBe(PASSWORD);
		expect(raw.details.nested.password).toBe(PASSWORD);
	});

	it("masks quoted assignments, headers, connection passwords, and escaped JSON without hiding ordinary identifiers", () => {
		const { boundary, obfuscator } = policy();
		const input = `DATABASE_PASSWORD="${PASSWORD}"\npassword: 'short p'\n{"api_key":"escaped\\"quote"}\nAuthorization: Basic YWJjOmRlZg==\nBearer bearer.opaque.value\npostgres://user:connection-password@localhost/db\ntoken_expiry_seconds=3600`;
		const safe = boundary.text(input);
		for (const secret of [
			PASSWORD,
			"short p",
			'escaped\\"quote',
			"YWJjOmRlZg==",
			"bearer.opaque.value",
			"connection-password",
		]) {
			expect(safe).not.toContain(secret);
		}
		expect(safe).toContain("DATABASE_PASSWORD=");
		expect(safe).toContain("token_expiry_seconds=3600");
		expect(obfuscator.deobfuscate(safe)).toBe(input);
	});

	it("preserves source expressions and ambiguous metadata labels rather than treating field names as credentials", () => {
		const { boundary } = policy();
		const source = [
			"record(key: string): void",
			"function accept(token: Token, password: string, key: string | number) {}",
			"const callback = (key: K) => key;",
			"const sortKey = item.id; const nextPageToken = cursorToken;",
			"<li key={item.id}>entry</li>",
			"sorted(xs, key=lambda x: x.id)",
			'{"private":true,"primary_key":true,"token":{"type":"string"}}',
			`key: \${{ runner.os }}`,
			"PRIVATE=true",
		].join("\n");
		const raw = {
			content: [{ type: "text" as const, text: source }],
			details: { key: "sortKey", token: "string", private: true, pass: "x", auth: "issuer", passwordType: "string" },
		};
		expect(boundary.text(source)).toBe(source);
		expect(boundary.result(raw)).toEqual(raw);
		expect(boundary.arguments(raw.details)).toEqual(raw.details);
		const stream = new StreamRedactor([], []);
		expect(
			source
				.split("\n")
				.map(row => stream.redactRow(row))
				.join("\n"),
		).toBe(source);
	});

	it("masks short strong literals and dotenv values without requiring ambiguous identifier labels to be secret", () => {
		const { boundary, obfuscator } = policy();
		const source =
			'password: "p"\n{"api_key":"x"}\nDATABASE_PASSWORD=q\nTOKEN="opaque-token-value"\nSOME_KEY="quoted opaque value"\nOAUTH="opaque-oauth-value"\nkey: "sortKey"\ntoken: "string"\n';
		const safe = boundary.text(source);
		expect(safe).not.toContain('password: "p"');
		expect(safe).not.toContain('{"api_key":"x"}');
		expect(safe).not.toContain("DATABASE_PASSWORD=q");
		for (const secret of ["opaque-token-value", "quoted opaque value", "opaque-oauth-value"])
			expect(safe).not.toContain(secret);
		expect(safe).toContain('key: "sortKey"');
		expect(safe).toContain('token: "string"');
		expect(obfuscator.deobfuscate(safe)).toBe(source);
		const raw = {
			password: "p",
			api_key: "x",
			credential: "q",
			key: "sortKey",
			token: "string",
			oauth: "opaque-oauth-value",
		};
		const args = boundary.arguments(raw);
		expect(args.password).not.toBe("p");
		expect(args.api_key).not.toBe("x");
		expect(args.credential).not.toBe("q");
		expect(args.key).toBe("sortKey");
		expect(args.token).toBe("string");
		expect(args.oauth).not.toBe("opaque-oauth-value");
		expect(obfuscator.deobfuscate(JSON.stringify(args))).toBe(JSON.stringify(raw));
	});

	it("protects embedded opaque credential assignments in publication and terminal output without hiding expressions", () => {
		const { boundary, obfuscator } = policy();
		const source = [
			"prefix API_KEY=abcd1234 suffix",
			"prefix DATABASE_PASSWORD=efgh5678 suffix",
			"prefix password=ijkl9012 suffix",
			"prefix AUTH_TOKEN=mnop3456 suffix",
			"record(API_KEY: Type1234, password: string)",
			"prefix API_KEY=client.currentKey suffix",
			`prefix API_KEY=\${configuredKey} suffix`,
			"prefix API_KEY=resolveKey() suffix",
		].join("\n");
		const safe = boundary.result({ content: [{ type: "text", text: source }], details: { marker: "visible" } });
		for (const value of ["abcd1234", "efgh5678", "ijkl9012", "mnop3456"])
			expect(JSON.stringify(safe)).not.toContain(value);
		for (const expression of [
			"record(API_KEY: Type1234, password: string)",
			"API_KEY=client.currentKey",
			`API_KEY=\${configuredKey}`,
			"API_KEY=resolveKey()",
		]) {
			expect(text(safe)).toContain(expression);
		}
		expect(safe.details?.marker).toBe("visible");
		expect(obfuscator.deobfuscate(text(safe))).toBe(source);
		const stream = new StreamRedactor([], []);
		expect(
			source
				.split("\n")
				.map(row => stream.redactRow(row))
				.join("\n"),
		).toBe(
			[
				"prefix API_KEY=•••••• suffix",
				"prefix DATABASE_PASSWORD=•••••• suffix",
				"prefix password=•••••• suffix",
				"prefix AUTH_TOKEN=•••••• suffix",
				"record(API_KEY: Type1234, password: string)",
				"prefix API_KEY=client.currentKey suffix",
				`prefix API_KEY=\${configuredKey} suffix`,
				"prefix API_KEY=resolveKey() suffix",
			].join("\n"),
		);
	});

	it("protects generic alphanumeric and numeric string credentials in literal and nested metadata contexts", () => {
		const { boundary, obfuscator } = policy();
		const token = "Abc123def456ghi789";
		const key = "12345678";
		const numericToken = "87654321";
		const source = `{"token":"${token}","key":"${key}","oauth":"${numericToken}","private":true}\nTOKEN=12345678\n`;
		const literal = policy();
		const literalSafe = literal.boundary.text(source);
		for (const value of [token, key, numericToken]) expect(literalSafe).not.toContain(value);
		expect(literalSafe).toContain('"private":true');
		expect(literal.obfuscator.deobfuscate(literalSafe)).toBe(source);
		const raw = {
			content: [{ type: "text" as const, text: "visible result" }],
			details: { nested: { token, key, oauth: numericToken, private: true }, marker: "visible" },
		};
		const safe = boundary.result(raw);
		for (const value of [token, key, numericToken]) {
			expect(JSON.stringify(safe)).not.toContain(value);
		}
		expect(text(safe)).toBe("visible result");
		expect(safe.details?.nested.private).toBe(true);
		expect(safe.details?.marker).toBe("visible");
		expect(obfuscator.deobfuscate(JSON.stringify(safe))).toBe(JSON.stringify(raw));
		const standalone = policy();
		const dotenv = standalone.boundary.text("TOKEN=12345678");
		expect(dotenv).not.toContain("12345678");
		expect(standalone.obfuscator.deobfuscate(dotenv)).toBe("TOKEN=12345678");
	});

	it("keeps protected source readable and reversible without changing file bytes", async () => {
		const { boundary, obfuscator } = policy();
		const session = await fixture(boundary);
		const source =
			'function record(key: string, token: Token) {}\nconst item = <li key={row.id} />;\nPASSWORD="opaque source password"\nbenign marker\n';
		const file = path.join(session.cwd, "source.tsx");
		await Bun.write(file, source);
		const result = await new ReadTool(session).execute("read-source", { path: "source.tsx:raw" });
		expect(text(result)).toContain("function record(key: string, token: Token) {}");
		expect(text(result)).toContain("const item = <li key={row.id} />;");
		expect(text(result)).not.toContain("opaque source password");
		expect(obfuscator.deobfuscate(text(result))).toContain(source.trimEnd());
		expect(await Bun.file(file).text()).toBe(source);
	});

	it("discovers multiline credentials before every single-range and multi-range read projection", async () => {
		for (const variant of ["file-single", "file-multi", "memory-single", "memory-multi"]) {
			const { boundary, obfuscator } = policy();
			const session = await fixture(boundary);
			const source =
				'PASSWORD="first source line\nopaque interior password line\nlast source line"\nbenign marker\n';
			const file = path.join(session.cwd, "multiline.txt");
			await Bun.write(file, source);
			const options = { entityLabel: "file", raw: true, immutable: true };
			const ranges = [
				{ startLine: 2, endLine: 2 },
				{ startLine: 4, endLine: 4 },
			];
			const result =
				variant === "memory-single"
					? await buildInMemoryTextResult(session, source, 2, 1, options)
					: variant === "memory-multi"
						? await buildInMemoryMultiRangeResult(session, source, ranges, options)
						: await new ReadTool(session).execute("read-ranges", {
								path: variant === "file-single" ? "multiline.txt:2:raw" : "multiline.txt:2,4:raw",
							});
			expect(text(result)).not.toContain("opaque interior password line");
			expect(obfuscator.deobfuscate(text(result))).toContain("opaque interior password line");
			if (variant.endsWith("multi")) expect(text(result)).toContain("benign marker");
			expect(await Bun.file(file).text()).toBe(source);
		}
	});

	it("protects opaque key, private, and oauth assignments in tool and terminal output without preloaded secrets", () => {
		const { boundary, obfuscator } = policy();
		const input =
			'SOME_KEY="opaque key value"\nPRIVATE=opaque-private-value\nOAUTH=opaque-oauth-value\ntoken_expiry_seconds=3600';
		const safe = boundary.text(input);
		for (const secret of ["opaque key value", "opaque-private-value", "opaque-oauth-value"]) {
			expect(safe).not.toContain(secret);
		}
		expect(safe).toContain("token_expiry_seconds=3600");
		expect(obfuscator.deobfuscate(safe)).toBe(input);
		const stream = new StreamRedactor([], []);
		expect(
			input
				.split("\n")
				.map(row => stream.redactRow(row))
				.join("\n"),
		).toBe('SOME_KEY="••••••"\nPRIVATE=••••••\nOAUTH=••••••\ntoken_expiry_seconds=3600');
	});

	it("discovers complete source credentials and masks later fragments reversibly", () => {
		const { boundary, obfuscator } = policy();
		const source = 'PASSWORD="first source line\nopaque interior password line\nlast source line"';
		boundary.discover(source);
		const safe = boundary.text("opaque interior password line");
		expect(safe).not.toBe("opaque interior password line");
		expect(obfuscator.deobfuscate(safe)).toBe("opaque interior password line");
		expect(boundary.text("ordinary source line")).toBe("ordinary source line");
	});

	it("masks known credentials in argument type and mimeType fields", () => {
		const { boundary, obfuscator } = policy();
		boundary.discover(`PASSWORD="${PASSWORD}"`);
		const safe = boundary.arguments({
			type: PASSWORD,
			mimeType: PASSWORD,
			nested: { type: PASSWORD },
			ordinary: "visible",
		});
		expect(JSON.stringify(safe)).not.toContain(PASSWORD);
		expect(obfuscator.deobfuscate(JSON.stringify(safe))).toBe(
			JSON.stringify({ type: PASSWORD, mimeType: PASSWORD, nested: { type: PASSWORD }, ordinary: "visible" }),
		);
	});

	it("exempts image bytes only at the content transport location, including reused metadata objects", () => {
		const { boundary, obfuscator } = policy();
		const image = { type: "image" as const, mimeType: "image/png", data: TOKEN };
		const raw = {
			content: [image, { type: "text" as const, text: "benign result" }],
			details: { image, nested: { type: "image", data: `PASSWORD="${PASSWORD}"` }, content: [image] },
			providerMetadata: {
				type: "computer" as const,
				screenshot: { type: "computer_screenshot" as const, file_id: "synthetic-screenshot" },
				acknowledgedSafetyChecks: [
					{ id: "synthetic-check", image: { type: "image", data: `PASSWORD="${PASSWORD}"` } },
				],
			},
		};
		const safe = boundary.result(raw);
		expect(safe.content).toEqual(raw.content);
		expect(JSON.stringify(safe.details)).not.toContain(TOKEN);
		expect(JSON.stringify(safe.details)).not.toContain(PASSWORD);
		expect(JSON.stringify(safe.providerMetadata)).not.toContain(PASSWORD);
		expect(obfuscator.deobfuscate(JSON.stringify(safe.details))).toBe(JSON.stringify(raw.details));
		expect(obfuscator.deobfuscate(JSON.stringify(safe.providerMetadata))).toBe(JSON.stringify(raw.providerMetadata));
		expect(text(safe)).toBe("benign result");
	});

	it("keeps binary image transport untouched and honors a live explicit opt-out", () => {
		const { boundary, obfuscator } = policy();
		const image = { type: "image" as const, mimeType: "image/png", data: TOKEN };
		const safe = boundary.result({
			content: [image, { type: "text", text: TOKEN }],
			details: { password: PASSWORD },
		});
		expect(safe.content[0]).toEqual(image);
		expect(text(safe)).not.toContain(TOKEN);
		obfuscator.setObfuscating(false);
		expect(boundary.result({ content: [{ type: "text", text: PASSWORD }], details: { password: PASSWORD } })).toEqual(
			{ content: [{ type: "text", text: PASSWORD }], details: { password: PASSWORD } },
		);
	});

	it("guards hook replacements and hook errors before events, retained history, and the next model turn", async () => {
		for (const throws of [false, true]) {
			const { boundary, obfuscator } = policy();
			const actualPaths: string[] = [];
			const masked = boundary.arguments({ password: PASSWORD }).password;
			if (typeof masked !== "string") throw new Error("Missing protected argument");
			const schema = type({ path: "string" });
			const tool: AgentTool<typeof schema> = {
				name: "fixture",
				label: "Fixture",
				description: "Synthetic data",
				parameters: schema,
				async execute(_id, args, _signal, update, context) {
					actualPaths.push(args.path);
					update?.({ content: [{ type: "text", text: `PASSWORD=${PASSWORD.slice(0, 8)}` }], details: {} });
					update?.({ content: [{ type: "text", text: `PASSWORD="${PASSWORD}"` }], details: {} });
					context?.addAdditionalContext?.(`password="${PASSWORD}"`);
					return { content: [{ type: "text", text: "before hook" }], details: {} };
				},
			};
			let providerContext = "";
			const mock = createMockModel({
				responses: [
					{ content: [{ type: "toolCall", id: "fixture-1", name: "fixture", arguments: { path: masked } }] },
					context => {
						providerContext = JSON.stringify(context.messages);
						return { content: ["done"] };
					},
				],
			});
			const events: AgentEvent[] = [];
			const hostContext = toolContext(boundary);
			const agent = new Agent({
				initialState: { model: mock.model, tools: [tool], systemPrompt: ["Synthetic test"] },
				streamFn: mock.stream,
				toolOutputBoundary: boundary,
				transformToolCallArguments: args => deobfuscateToolArguments(obfuscator, args),
				getToolContext: call => ({ ...hostContext, addAdditionalContext: call?.addAdditionalContext }),
				afterToolCall: async () => {
					if (throws) throw new Error(`PASSWORD="${PASSWORD}"`);
					return { content: [{ type: "text", text: `password="${PASSWORD}"` }], details: { password: PASSWORD } };
				},
			});
			agent.subscribe(event => events.push(event));
			await agent.prompt("run fixture");
			expect(actualPaths).toEqual([PASSWORD]);
			expect(providerContext).toContain("toolResult");
			expect(providerContext).not.toContain(PASSWORD);
			expect(JSON.stringify(events)).not.toContain(PASSWORD);
			expect(JSON.stringify(events)).not.toContain(PASSWORD.slice(0, 8));
			expect(events.filter(event => event.type === "tool_execution_update")).toEqual([]);
			const result = agent.state.messages.find(message => message.role === "toolResult");
			expect(result?.role === "toolResult" && result.isError).toBe(throws);
			expect(JSON.stringify(agent.state.messages)).not.toContain(PASSWORD);
			expect(JSON.stringify(agent.state.messages)).toContain("done");
		}
	});

	it("protects speculative and synthetic blocked results at the same final publication boundary", async () => {
		for (const blocked of [false, true]) {
			const { boundary } = policy();
			const schema = type({ path: "string" });
			const tool: AgentTool<typeof schema> = {
				name: "read_fixture",
				label: "Read fixture",
				description: "Synthetic read",
				parameters: schema,
				speculation: {
					finalized: {
						assess: ({ args }) => ({
							eligible: true,
							effect: {
								kind: "local_read",
								resources: [{ scheme: "file", path: String(args.path), access: "read" }],
							},
						}),
						async execute() {
							return {
								kind: "result",
								isError: false,
								result: { content: [{ type: "text", text: `PASSWORD="${PASSWORD}"\nspeculative marker` }] },
							};
						},
					},
				},
				async execute() {
					throw new Error("Unexpected ordinary execution");
				},
			};
			const mock = createMockModel({
				responses: [
					{
						content: [
							{ type: "toolCall", id: "spec", name: "read_fixture", arguments: { path: "/tmp/synthetic" } },
						],
					},
					{ content: ["done"] },
				],
			});
			const events: AgentEvent[] = [];
			const agent = new Agent({
				initialState: { model: mock.model, tools: [tool], systemPrompt: ["Synthetic test"] },
				streamFn: mock.stream,
				toolOutputBoundary: boundary,
				speculativeToolExecution: {
					enabled: true,
					host: { authorize: () => ({ allowed: true, deferBeforeToolCall: true }) },
				},
				beforeToolCall: () =>
					blocked ? { block: true, reason: `PASSWORD="${PASSWORD}"\nblocked marker` } : undefined,
			});
			agent.subscribe(event => events.push(event));
			await agent.prompt("run fixture");
			expect(JSON.stringify([events, agent.state.messages])).not.toContain(PASSWORD);
			const result = agent.state.messages.find(message => message.role === "toolResult");
			expect(result?.role === "toolResult" && result.isError).toBe(blocked);
			expect(JSON.stringify(result)).toContain(blocked ? "blocked marker" : "speculative marker");
		}
	});

	it("protects detached external events before state retention", () => {
		const { boundary } = policy();
		const agent = new Agent({ toolOutputBoundary: boundary });
		const events: AgentEvent[] = [];
		agent.subscribe(event => events.push(event));
		agent.emitExternalEvent({
			type: "tool_execution_update",
			toolCallId: "late",
			toolName: "bash",
			args: {},
			partialResult: { content: [{ type: "text", text: PASSWORD.slice(0, 9) }] },
		});
		agent.emitExternalEvent({
			type: "tool_execution_end",
			toolCallId: "late",
			toolName: "bash",
			result: { content: [{ type: "text", text: `PASSWORD="${PASSWORD}"` }] },
		});
		agent.emitExternalEvent({
			type: "message_end",
			message: {
				role: "toolResult",
				toolCallId: "late",
				toolName: "bash",
				content: [{ type: "text", text: `password="${PASSWORD}"` }],
				isError: false,
				timestamp: 0,
			},
		});
		expect(events.map(event => event.type)).toEqual(["tool_execution_end", "message_end"]);
		expect(JSON.stringify(events)).not.toContain(PASSWORD);
		expect(JSON.stringify(agent.state.messages)).not.toContain(PASSWORD);
		expect(agent.state.messages[0]?.role).toBe("toolResult");
	});

	it("withholds split Cursor stdout and protects direct returns as well as completion events", async () => {
		const { boundary } = policy();
		const schema = type({ command: "string", "cwd?": "string", "timeout?": "number" });
		const tool: AgentTool<typeof schema> = {
			name: "bash",
			label: "Bash",
			description: "Synthetic stream",
			parameters: schema,
			async execute(_id, _args, _signal, update) {
				update?.({ content: [{ type: "text", text: `PASSWORD="${PASSWORD.slice(0, 10)}` }] });
				update?.({ content: [{ type: "text", text: `PASSWORD="${PASSWORD}"\nbenign` }] });
				return {
					content: [{ type: "text", text: `PASSWORD="${PASSWORD}"\nbenign` }],
					details: { password: PASSWORD },
				};
			},
		};
		const events: AgentEvent[] = [];
		const stdout: string[] = [];
		const handlers = new CursorExecHandlers({
			cwd: "/tmp",
			tools: new Map([["bash", tool]]),
			toolOutputBoundary: boundary,
			emitEvent: event => events.push(event),
		});
		const result = await handlers.shellStream(
			create(ShellArgsSchema, { toolCallId: "cursor-shell", command: "synthetic" }),
			{ onStdout: chunk => stdout.push(chunk), onStderr: () => {} },
		);
		expect(stdout).toHaveLength(1);
		expect(stdout[0]).toContain("benign");
		expect(JSON.stringify([events, stdout, result])).not.toContain(PASSWORD);
		expect(events.map(event => event.type)).toEqual(["tool_execution_start", "tool_execution_end"]);
	});

	it("redacts full read lines before columns and omits incomplete native grep windows", async () => {
		const { boundary } = policy();
		const session = await fixture(boundary);
		const value = `needle-opaque-fragment-${"q".repeat(16000)}`;
		const source = `DATABASE_PASSWORD=${value}\nbenign=visible\n`;
		await Bun.write(path.join(session.cwd, "fixture.txt"), source);
		const read = await new ReadTool(session).execute("read", { path: "fixture.txt" });
		expect(text(read)).not.toContain("needle-opaque-fragment");
		expect(text(read)).toContain("benign=visible");
		const grep = await new GrepTool(session).execute("grep", { pattern: "q{12}", path: "fixture.txt" });
		expect(text(grep)).not.toContain("q".repeat(12));
		expect(text(grep)).toContain("Incomplete source line omitted");
		expect(await Bun.file(path.join(session.cwd, "fixture.txt")).text()).toBe(source);
	});

	it("protects fresh standalone grep selections inside PEM and multiline quoted credentials", async () => {
		for (const hashLines of [true, false]) {
			const { boundary, obfuscator } = policy();
			const session = await fixture(boundary);
			cfgEditMode.set(session.settings, hashLines ? "hashline" : "replace");
			const pemBody = "c3ludGhldGljLXBlbS1pbnRlcmlvci1tYXRlcmlhbA==";
			const passwordBody = "opaque interior password needle";
			const source = `-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY-----\nPASSWORD="first password line\n${passwordBody}\nlast password line"\nbenign needle marker\n`;
			const file = path.join(session.cwd, "multiline.txt");
			await Bun.write(file, source);
			const result = await new GrepTool(session, { context: 0 }).execute("grep", {
				pattern: "c3ludGhldGlj|needle",
				path: "multiline.txt",
			});
			const rendered = JSON.stringify(result);
			expect(rendered).not.toContain(pemBody);
			expect(rendered).not.toContain(passwordBody);
			expect(text(result)).toContain("benign needle marker");
			expect(obfuscator.deobfuscate(text(result))).toContain(pemBody);
			expect(obfuscator.deobfuscate(text(result))).toContain(passwordBody);
			expect(await Bun.file(file).text()).toBe(source);
		}
	});

	it("keeps grep credential bodies out of fresh session events, history, and provider requests", async () => {
		const { boundary } = policy();
		const session = await fixture(boundary);
		const pemBody = "c2Vzc2lvbi1wZW0taW50ZXJpb3ItbWF0ZXJpYWw=";
		const passwordBody = "session interior password needle";
		await Bun.write(
			path.join(session.cwd, "session.txt"),
			`-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY-----\nPASSWORD="first\n${passwordBody}\nlast"\nbenign needle marker\n`,
		);
		let providerContext = "";
		const mock = createMockModel({
			responses: [
				{
					content: [
						{
							type: "toolCall",
							id: "grep-session",
							name: "grep",
							arguments: { pattern: "c2Vzc2lvbi|needle", path: "session.txt" },
						},
					],
				},
				context => {
					providerContext = JSON.stringify(context.messages);
					return { content: ["done"] };
				},
			],
		});
		const events: AgentEvent[] = [];
		const agent = new Agent({
			initialState: {
				model: mock.model,
				tools: [new GrepTool(session, { context: 0 })],
				systemPrompt: ["Synthetic test"],
			},
			streamFn: mock.stream,
			toolOutputBoundary: boundary,
		});
		agent.subscribe(event => events.push(event));
		await agent.prompt("search synthetic multiline source");
		for (const published of [providerContext, JSON.stringify(events), JSON.stringify(agent.state.messages)]) {
			expect(published).not.toContain(pemBody);
			expect(published).not.toContain(passwordBody);
			expect(published).toContain("benign needle marker");
		}
	});

	it("omits grep text when bounded discovery cannot establish complete source context", async () => {
		const { boundary } = policy();
		const session = await fixture(boundary);
		const source = `opaque-body-needle\n${"ordinary padding\n".repeat(270000)}`;
		await Bun.write(path.join(session.cwd, "large.txt"), source);
		const result = await new GrepTool(session, { context: 0 }).execute("grep", {
			pattern: "opaque-body-needle",
			path: "large.txt",
		});
		expect(text(result)).toContain("Source context unavailable; line omitted");
		expect(JSON.stringify(result)).not.toContain("opaque-body-needle");
		expect(result.details?.matchCount).toBe(1);
	});

	it("protects complete shell capture and generic spill projections before byte or column cuts", async () => {
		const { boundary } = policy();
		const session = await fixture(boundary);
		const password = `shell-fragment-${"z".repeat(9000)}`;
		await Bun.write(path.join(session.cwd, "fixture.txt"), `PASSWORD=${password}\nbenign line\n`);
		const shell = await new BashTool(session).execute("bash", { command: "cat fixture.txt", timeout: 5 });
		expect(text(shell)).not.toContain("shell-fragment");
		expect(text(shell)).toContain("benign line");
		const processed = await postProcessToolResult(
			{ content: [{ type: "text", text: `PASSWORD=${password}\nbenign line\n` }] },
			"fixture",
			toolContext(boundary),
		);
		expect(text(processed)).not.toContain("shell-fragment");
		expect(text(processed)).toContain("benign line");
	});

	it("restores a returned placeholder for edits, refuses it after restart, then restores it after a fresh read", async () => {
		const first = policy();
		const session = await fixture(first.boundary);
		const file = path.join(session.cwd, "editable.txt");
		await Bun.write(file, `DATABASE_PASSWORD="${PASSWORD}"\nbenign=old\n`);
		const read = first.boundary.result(await new ReadTool(session).execute("read", { path: "editable.txt:raw" }));
		const placeholder = text(read).match(/\$\$[A-Z0-9_]+(?::[ULCM])?\$\$/)?.[0];
		if (!placeholder) throw new Error("Protected read did not return a reversible placeholder");
		const liveArgs = deobfuscateToolArguments(first.obfuscator, {
			path: file,
			old_string: `DATABASE_PASSWORD="${placeholder}"`,
			new_string: `DATABASE_PASSWORD="${placeholder}"\nadded=live`,
		});
		await new EditTool(session, "replace").execute("edit-live", {
			path: String(liveArgs.path),
			old_string: String(liveArgs.old_string),
			new_string: String(liveArgs.new_string),
		});
		expect(await Bun.file(file).text()).toBe(`DATABASE_PASSWORD="${PASSWORD}"\nadded=live\nbenign=old\n`);
		const restarted = policy();
		expect(() => deobfuscateToolArguments(restarted.obfuscator, { new_string: placeholder })).toThrow(
			"Re-read its source",
		);
		expect(await Bun.file(file).text()).not.toContain(placeholder);
		session.toolOutputBoundary = restarted.boundary;
		const reread = restarted.boundary.result(
			await new ReadTool(session).execute("reread", { path: "editable.txt:raw" }),
		);
		expect(text(reread)).toContain(placeholder);
		const args = deobfuscateToolArguments(restarted.obfuscator, {
			path: file,
			old_string: `DATABASE_PASSWORD="${placeholder}"`,
			new_string: `DATABASE_PASSWORD="${placeholder}"\nadded=restart`,
		});
		await new EditTool(session, "replace").execute("edit-restart", {
			path: String(args.path),
			old_string: String(args.old_string),
			new_string: String(args.new_string),
		});
		expect(await Bun.file(file).text()).toBe(
			`DATABASE_PASSWORD="${PASSWORD}"\nadded=restart\nadded=live\nbenign=old\n`,
		);
	});
});
