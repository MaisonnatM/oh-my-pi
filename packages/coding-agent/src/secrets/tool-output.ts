import type { AgentToolResult, ToolOutputBoundary } from "@oh-my-pi/pi-agent-core";
import type { JsonValue, SecretObfuscator } from "./obfuscator";
import { credentialValueSpans, isCredentialFieldValue } from "./patterns";
import { PLACEHOLDER_RE, SecretValueSet } from "./placeholder";
import { collectJsonRegexSecretValues } from "./placeholder-scan";

/** One session registry owns both publication masking and execution restoration. */
export class CredentialToolOutputBoundary implements ToolOutputBoundary {
	constructor(private readonly getObfuscator: () => SecretObfuscator | undefined) {}

	get enabled(): boolean {
		return this.getObfuscator()?.obfuscates() === true;
	}

	discover(text: string): void {
		const obfuscator = this.getObfuscator();
		if (!obfuscator?.obfuscates()) return;
		obfuscator.batch(() => this.#discover(text, obfuscator));
	}

	text(text: string): string {
		return this.#protect(text) as string;
	}

	arguments(args: Record<string, unknown>): Record<string, unknown> {
		return this.#protect(args as JsonValue) as Record<string, unknown>;
	}

	result<T>(result: AgentToolResult<T>): AgentToolResult<T> {
		return this.#protect(result as unknown as JsonValue, true) as unknown as AgentToolResult<T>;
	}

	#discover(
		value: JsonValue,
		obfuscator: SecretObfuscator,
		resultEnvelope = false,
	): { shared: SecretValueSet; exactValues: Set<string> } {
		const shared = new SecretValueSet();
		const exactValues = new Set<string>();
		const remember = (secret: string): void => {
			if (!secret || secret.match(PLACEHOLDER_RE)?.[0] === secret) return;
			exactValues.add(secret);
			obfuscator.obfuscateCredentialValue(secret);
			if (secret.includes("\n")) {
				for (const line of secret.split("\n")) {
					if (line) obfuscator.obfuscateCredentialValue(line);
				}
			}
		};
		const discover = (node: JsonValue, field?: string, transport?: "result" | "content" | "image"): void => {
			if (typeof node === "string") {
				if (field && isCredentialFieldValue(field, node) && node.match(PLACEHOLDER_RE)?.[0] !== node) {
					remember(node);
				}
				for (const span of credentialValueSpans(node)) {
					remember(node.slice(span.start, span.end));
				}
				for (const secret of collectJsonRegexSecretValues(obfuscator, node)) {
					shared.add(secret);
					if (secret.includes("\n")) remember(secret);
				}
			} else if (Array.isArray(node)) {
				for (const entry of node)
					discover(
						entry,
						field,
						transport === "content" &&
							entry &&
							typeof entry === "object" &&
							!Array.isArray(entry) &&
							entry.type === "image"
							? "image"
							: undefined,
					);
			} else if (node && typeof node === "object") {
				for (const [key, entry] of Object.entries(node)) {
					if (entry === undefined) continue;
					if (transport === "image" && key === "data") continue;
					discover(key);
					discover(entry, key, transport === "result" && key === "content" ? "content" : undefined);
				}
			}
		};
		discover(value, undefined, resultEnvelope ? "result" : undefined);
		return { shared, exactValues };
	}

	#protect(value: JsonValue, resultEnvelope = false): JsonValue {
		const obfuscator = this.getObfuscator();
		if (!obfuscator?.obfuscates()) return value;
		return obfuscator.batch(() => {
			const { shared, exactValues } = this.#discover(value, obfuscator, resultEnvelope);
			const text = (input: string, field?: string): string => {
				if (
					(exactValues.has(input) || (field && isCredentialFieldValue(field, input))) &&
					input &&
					input.match(PLACEHOLDER_RE)?.[0] !== input
				) {
					return obfuscator.obfuscateCredentialValue(input);
				}
				let output = "";
				let cursor = 0;
				for (const span of credentialValueSpans(input)) {
					if (span.start < cursor) continue;
					output += input.slice(cursor, span.start);
					output += obfuscator.obfuscateCredentialValue(input.slice(span.start, span.end));
					cursor = span.end;
				}
				return obfuscator.obfuscate(output + input.slice(cursor), shared);
			};
			const walk = (
				node: JsonValue,
				field?: string,
				metadata = false,
				transport?: "result" | "content" | "block" | "image",
			): JsonValue => {
				if (typeof node === "string") return text(node, field);
				if (Array.isArray(node))
					return node.map(entry =>
						walk(
							entry,
							field,
							metadata,
							transport === "content"
								? entry && typeof entry === "object" && !Array.isArray(entry) && entry.type === "image"
									? "image"
									: "block"
								: undefined,
						),
					);
				if (!node || typeof node !== "object") return node;
				const output: { [key: string]: JsonValue } = {};
				for (const [key, entry] of Object.entries(node)) {
					if (entry === undefined) continue;
					const safeKey = metadata ? text(key) : key;
					if (Object.hasOwn(output, safeKey)) return "[Credential-bearing metadata keys collided; omitted]";
					Object.defineProperty(output, safeKey, {
						value:
							(transport === "image" && key === "data") ||
							((transport === "image" || transport === "block") && (key === "type" || key === "mimeType"))
								? entry
								: walk(
										entry,
										key,
										metadata || key === "details" || key === "providerMetadata",
										transport === "result" && key === "content" ? "content" : undefined,
									),
						enumerable: true,
						writable: true,
						configurable: true,
					});
				}
				return output;
			};
			return walk(value, undefined, false, resultEnvelope ? "result" : undefined);
		});
	}
}
