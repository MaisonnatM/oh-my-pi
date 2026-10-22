import { describe, expect, it } from "bun:test";
import { EnvProtocolHandler } from "@oh-my-pi/pi-coding-agent/internal-urls/env-protocol";
import { InternalUrlRouter } from "@oh-my-pi/pi-coding-agent/internal-urls/router";

function environmentRouter(environment: Readonly<Record<string, string | undefined>>): InternalUrlRouter {
	const router = new InternalUrlRouter();
	router.register(new EnvProtocolHandler(environment));
	return router;
}

describe("env://", () => {
	it("lists sorted names without exposing values anywhere in the resource", async () => {
		const router = environmentRouter({
			ZEBRA: "synthetic-zebra-credential-7d8f",
			ALPHA: "synthetic-alpha-credential-4a1b",
			EMPTY: "",
			ABSENT: undefined,
		});

		const resource = await router.resolve("env://");

		expect(JSON.parse(resource.content)).toEqual(["ALPHA", "EMPTY", "ZEBRA"]);
		expect(resource.contentType).toBe("application/json");
		expect(JSON.stringify(resource)).not.toContain("synthetic-zebra-credential-7d8f");
		expect(JSON.stringify(resource)).not.toContain("synthetic-alpha-credential-4a1b");
	});

	it("returns an empty names list when the injected environment is empty", async () => {
		const resource = await environmentRouter({}).resolve("env://");

		expect(JSON.parse(resource.content)).toEqual([]);
	});

	it("distinguishes missing, empty, and set without any value-derived fields", async () => {
		const router = environmentRouter({ EMPTY: "", TOKEN: "synthetic-secret-with-private-content-f38a" });

		for (const [name, state] of [
			["MISSING", "missing"],
			["EMPTY", "empty"],
			["TOKEN", "set"],
			["constructor", "missing"],
		]) {
			const resource = await router.resolve(`env://${name}`);

			expect(JSON.parse(resource.content)).toEqual({ name, state });
			expect(JSON.stringify(resource)).not.toContain("synthetic-secret-with-private-content-f38a");
		}
	});

	it("preserves the case of environment names", async () => {
		const router = environmentRouter({ MixedCase: "synthetic-mixed-case-secret", MIXEDCASE: "" });

		expect(JSON.parse((await router.resolve("env://MixedCase")).content)).toEqual({
			name: "MixedCase",
			state: "set",
		});
		expect(JSON.parse((await router.resolve("env://MIXEDCASE")).content)).toEqual({
			name: "MIXEDCASE",
			state: "empty",
		});
	});

	it.each([
		["a name starting with a digit", "env://1TOKEN"],
		["a name containing punctuation", "env://API-TOKEN"],
		["an encoded name", "env://%54OKEN"],
		["a path", "env://TOKEN/extra"],
		["a normalized traversal path", "env://TOKEN/extra/.."],
		["a query", "env://TOKEN?value=synthetic-query-secret-a3b4"],
		["a fragment", "env://TOKEN#synthetic-fragment-secret-c5d6"],
		["a selector", "env://TOKEN:raw"],
		["a shell expression", "env://$(printenv)"],
		["trailing whitespace", "env://TOKEN\n"],
	])("rejects %s without reflecting unvalidated input", async (_description, input) => {
		const router = environmentRouter({ TOKEN: "synthetic-unexposed-token" });

		await expect(router.resolve(input)).rejects.toThrow(
			/^Invalid env:\/\/ URL\. Use env:\/\/ or env:\/\/NAME with a name matching \[A-Za-z_\]\[A-Za-z0-9_\]\*\. Paths, queries, and fragments are not supported\.$/,
		);
	});

	it("denies writes at the router gate and execution without changing state", async () => {
		const router = environmentRouter({ TOKEN: "synthetic-read-only-secret" });

		expect(router.writeTier("env://TOKEN", "replacement", undefined)).toEqual({
			tier: "write",
			policy: "deny",
			reason: "env:// URLs are read-only",
		});
		expect(router.fileWritable("env://TOKEN")).toBe(false);
		await expect(router.write("env://TOKEN", "replacement")).rejects.toThrow("env:// URLs are read-only for write");
		expect(JSON.parse((await router.resolve("env://TOKEN")).content)).toEqual({ name: "TOKEN", state: "set" });
	});
});
