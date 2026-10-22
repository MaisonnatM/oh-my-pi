import { PLACEHOLDER_RE } from "./placeholder";

import { SENSITIVE_TOKEN_RE } from "@oh-my-pi/pi-ai/providers/transform-messages";

export interface CredentialPattern {
	/** Model-visible friendly label for reversible placeholders. */
	name: string;
	source: string;
	flags?: string;
	/**
	 * Literal substrings at least one of which every match of `source`
	 * contains. The obfuscator skips the regex over text containing none of
	 * them (`includes` beats a lookbehind regex by orders of magnitude, and the
	 * whole provider context is scanned on every request). Must be exhaustive
	 * for the pattern's alternatives; a pattern without this field is always
	 * scanned. Case-insensitive patterns are matched case-insensitively.
	 */
	literalPrefixes?: readonly string[];
}

const B = "(?<![A-Za-z0-9_-])"; // left boundary
const E = "(?![A-Za-z0-9_-])"; // right boundary

// Standard PEM private-key block: five dashes, BEGIN, optional algorithm label,
// PRIVATE KEY, five dashes, lazy body, matching END armor line.
const PEM_PRIVATE_KEY_SOURCE = "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----";

export interface CredentialPrefixRule {
	/** Regex source matching the fixed provider prefix. */
	readonly source: string;
	/** `token` redacts from the prefix through non-whitespace; the special modes preserve their introducer semantics. */
	readonly mode: "token" | "line" | "bearer-token";
}

/**
 * Credential introducers which are sensitive before a complete high-entropy token
 * has been typed. Stream redaction deliberately applies these without the normal
 * length or entropy gates.
 */
export const CREDENTIAL_PREFIX_RULES: readonly CredentialPrefixRule[] = [
	{ source: "sk-ant-", mode: "token" },
	{ source: "sk-proj-", mode: "token" },
	{ source: "sk-", mode: "token" },
	{ source: "gh[opusr]_", mode: "token" },
	{ source: "github_pat_", mode: "token" },
	{ source: "glpat-", mode: "token" },
	{ source: "xox[abprs]-", mode: "token" },
	{ source: "AKIA", mode: "token" },
	{ source: "ASIA", mode: "token" },
	{ source: "AIza", mode: "token" },
	{ source: "npm_", mode: "token" },
	{ source: "hf_", mode: "token" },
	{ source: "whsec_", mode: "token" },
	{ source: "rk_live_", mode: "token" },
	{ source: "sk_live_", mode: "token" },
	{ source: "sk_test_", mode: "token" },
	{ source: "eyJ", mode: "token" },
	{ source: "-----BEGIN", mode: "line" },
	{ source: "Bearer ", mode: "bearer-token" },
];

/** Anchored vendor-prefix credential shapes. No generic keyword/entropy rules: a coding agent must still be able to read identifiers like `token_expiry_seconds`. */
export const CREDENTIAL_PATTERNS: readonly CredentialPattern[] = [
	{
		name: "Credential",
		source: SENSITIVE_TOKEN_RE.source,
		flags: "i",
		literalPrefixes: ["gho_", "ghp_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "sk-"],
	},
	{ name: "AWSAccessKey", source: `${B}(?:AKIA|ASIA)[A-Z0-9]{16}${E}`, literalPrefixes: ["AKIA", "ASIA"] },
	{ name: "GoogleAPIKey", source: `${B}AIza[A-Za-z0-9_-]{30,}${E}`, literalPrefixes: ["AIza"] },
	{
		name: "SlackToken",
		source: `${B}xox[abprs]-[A-Za-z0-9-]{10,}${E}`,
		literalPrefixes: ["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"],
	},
	{ name: "NpmToken", source: `${B}npm_[A-Za-z0-9]{30,}${E}`, literalPrefixes: ["npm_"] },
	{
		name: "StripeKey",
		source: `${B}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}${E}`,
		literalPrefixes: ["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
	},
	{ name: "StripeWebhookSecret", source: `${B}whsec_[A-Za-z0-9]{20,}${E}`, literalPrefixes: ["whsec_"] },
	{ name: "HuggingFaceToken", source: `${B}hf_[A-Za-z0-9]{30,}${E}`, literalPrefixes: ["hf_"] },
	{ name: "SendGridKey", source: `${B}SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}${E}`, literalPrefixes: ["SG."] },
	{
		name: "JWT",
		source: `${B}eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}${E}`,
		literalPrefixes: ["eyJ"],
	},
	{
		name: "BearerToken",
		source: `(?<=\\bBearer )[A-Za-z0-9._~+/=-]{20,}${E}`,
		flags: "i",
		literalPrefixes: ["Bearer "],
	},
	{ name: "PrivateKey", source: PEM_PRIVATE_KEY_SOURCE, literalPrefixes: ["-----BEGIN "] },
];

export interface CredentialValueSpan {
	start: number;
	end: number;
}

const STRONG_CREDENTIAL_FIELD_RE =
	/(?:^|[_-])(?:password|passwd|api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?key|credentials?)$/i;
const AMBIGUOUS_CREDENTIAL_FIELD_RE = /(?:^|[_-])(?:pass|secret|token|key|private|oauth|authorization|auth)$/i;
const ASSIGNMENT_RE =
	/["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*([=:])\s*("(?:\\.|[^"\\])*"|'(?:''|\\.|[^'\\])*'|[^\s"',;}\]]+)/g;
const AUTHORIZATION_RE = /\b(?:Basic|Bearer)[ \t]+([A-Za-z0-9._~+/=-]+)/gi;
const CONNECTION_URL_RE = /[a-z][a-z0-9+.-]*:\/\/[^/:@?#\s]*:([^/?#@\s]+)@/gi;
const SOURCE_REFERENCE_RE = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/;
const JSON_PRIMITIVE_RE = /^(?:true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)$/;

function credentialField(name: string): "strong" | "ambiguous" | undefined {
	const normalized = name.replace(/([a-z])([A-Z])/g, "$1_$2");
	if (STRONG_CREDENTIAL_FIELD_RE.test(normalized)) return "strong";
	if (AMBIGUOUS_CREDENTIAL_FIELD_RE.test(normalized)) return "ambiguous";
	return undefined;
}

function opaqueCredentialValue(value: string): boolean {
	return value.length >= 8 && !/[{}[\]()<>`$\\]/.test(value) && !/(?:^|\s)[=:+*/?&|](?:\s|$)/.test(value);
}

/** Structured string fields have literal values, unlike expressions in source text. */
export function isCredentialFieldValue(name: string, value: string): boolean {
	const field = credentialField(name);
	return value.length > 0 && (field === "strong" || (field === "ambiguous" && opaqueCredentialValue(value)));
}

/** Complete value spans, shared by tool publication and terminal-row redaction. */
export function credentialValueSpans(text: string): CredentialValueSpan[] {
	const spans: CredentialValueSpan[] = [];
	ASSIGNMENT_RE.lastIndex = 0;
	for (let match = ASSIGNMENT_RE.exec(text); match; match = ASSIGNMENT_RE.exec(text)) {
		const name = match[1]!;
		const field = credentialField(name);
		if (!field) continue;
		const raw = match[3]!;
		const quoted = raw.startsWith('"') || raw.startsWith("'");
		const value = quoted ? raw.slice(1, -1) : raw;
		if (!value || value.match(PLACEHOLDER_RE)?.[0] === value) continue;
		if (quoted) {
			if (!isCredentialFieldValue(name, value)) continue;
		} else {
			if (/^(?:true|false|null)$/.test(value) || /[{}[\]()<>`$\\]/.test(value)) continue;
			const lineStart = text.lastIndexOf("\n", match.index - 1) + 1;
			const lineEnd = text.indexOf("\n", match.index + match[0].length);
			const dotenv =
				match[2] === "=" &&
				/^[A-Z][A-Z0-9_]*$/.test(name) &&
				/^[ \t]*(?:export[ \t]+)?$/.test(text.slice(lineStart, match.index)) &&
				/^[ \t\r]*(?:#[^\r\n]*)?$/.test(
					text.slice(match.index + match[0].length, lineEnd < 0 ? text.length : lineEnd),
				);
			const opaqueAssignment =
				match[2] === "=" &&
				(field === "strong" || /^[A-Z][A-Z0-9_]*$/.test(name)) &&
				/[A-Za-z]/.test(value) &&
				/\d/.test(value);
			if (
				!dotenv &&
				((SOURCE_REFERENCE_RE.test(value) && !opaqueAssignment) ||
					JSON_PRIMITIVE_RE.test(value) ||
					!opaqueCredentialValue(value) ||
					!/^[A-Za-z0-9_-]+$/.test(value))
			)
				continue;
		}
		const start = match.index + match[0].lastIndexOf(raw) + (quoted ? 1 : 0);
		spans.push({ start, end: start + value.length });
	}
	for (const pattern of [AUTHORIZATION_RE, CONNECTION_URL_RE]) {
		pattern.lastIndex = 0;
		for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
			const value = match[1]!;
			if (value.match(PLACEHOLDER_RE)?.[0] === value) continue;
			const start = match.index + match[0].lastIndexOf(value);
			spans.push({ start, end: start + value.length });
		}
	}
	return spans.sort((a, b) => a.start - b.start || b.end - a.end);
}
