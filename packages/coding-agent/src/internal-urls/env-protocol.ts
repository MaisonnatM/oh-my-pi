import envDoc from "../prompts/internal-urls/env.md" with { type: "text" };
import type { InternalResource, InternalUrl, ProtocolHandler, SchemeSpec } from "./types";

type Environment = Readonly<Record<string, string | undefined>>;

type EnvironmentInspection = string[] | { name: string; state: "missing" | "empty" | "set" };

function inspectEnvironment(environment: Environment, name: string | undefined): EnvironmentInspection {
	if (name === undefined) {
		return Object.keys(environment)
			.filter(key => environment[key] !== undefined)
			.sort();
	}
	const value = Object.hasOwn(environment, name) ? environment[name] : undefined;
	return { name, state: value === undefined ? "missing" : value === "" ? "empty" : "set" };
}

export class EnvProtocolHandler implements ProtocolHandler {
	readonly scheme = "env";
	readonly spec: SchemeSpec = {
		backing: "virtual",
		selectors: "none",
		immutable: true,
	};

	readonly #environment: Environment;

	constructor(environment: Environment = process.env) {
		this.#environment = environment;
	}

	promptDoc(): string {
		return envDoc.trim();
	}

	async resolve(url: InternalUrl): Promise<InternalResource> {
		const input = url.rawHref ?? url.href;
		const match = /^env:\/\/([a-z_][a-z0-9_]*)?$/i.exec(input);
		if (!match || match[0] !== input) {
			throw new Error(
				"Invalid env:// URL. Use env:// or env://NAME with a name matching [A-Za-z_][A-Za-z0-9_]*. Paths, queries, and fragments are not supported.",
			);
		}
		return {
			url: `env://${match[1] ?? ""}`,
			content: JSON.stringify(inspectEnvironment(this.#environment, match[1])),
			contentType: "application/json",
		};
	}
}
