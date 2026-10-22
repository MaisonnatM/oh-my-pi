import type { ToolOutputBoundary } from "@oh-my-pi/pi-agent-core";
import type { EditStore, GrepMatch } from "@oh-my-pi/pi-natives";
import { DEFAULT_MAX_COLUMN } from "@oh-my-pi/pi-tui/tools/streaming-output";
import type { InternalUrlFilesystem } from "../internal-urls/url-filesystem";
import { resolveSearchResultPath } from "./path-utils";

interface GrepProtectionOptions {
	boundary: ToolOutputBoundary;
	matchesByFile: ReadonlyMap<string, GrepMatch[]>;
	hashContexts: ReadonlyMap<string, { tag: string; path: string }>;
	archiveDisplayMap: ReadonlyMap<string, string>;
	searchPath: string;
	filesystem: InternalUrlFilesystem;
	editStore: EditStore;
	maxSourceBytes: number;
}

const sourceDecoder = new TextDecoder("utf-8", { fatal: true });

export async function protectGrepMatches({
	boundary,
	matchesByFile,
	hashContexts,
	archiveDisplayMap,
	searchPath,
	filesystem,
	editStore,
	maxSourceBytes,
}: GrepProtectionOptions): Promise<Map<string, Set<number>>> {
	const omittedLinesByFile = new Map<string, Set<number>>();
	const archiveSources = new Map<string, string>();
	for (const [sourcePath, displayPath] of archiveDisplayMap) {
		if (!archiveSources.has(displayPath)) archiveSources.set(displayPath, sourcePath);
	}

	// Inspect one complete source at a time so the byte cap also bounds live buffers.
	for (const [relativePath, fileMatches] of matchesByFile) {
		const hashContext = hashContexts.get(relativePath);
		let source = hashContext ? (editStore.byHashText(hashContext.path, hashContext.tag) ?? undefined) : undefined;
		if (source === undefined) {
			const sourcePath =
				archiveSources.get(relativePath) ?? resolveSearchResultPath(searchPath, fileMatches[0]!.path);
			try {
				const bytes = await filesystem.readPrefix(sourcePath, maxSourceBytes + 1);
				if (bytes.byteLength <= maxSourceBytes) source = sourceDecoder.decode(bytes);
			} catch {
				// Unreadable or incomplete source cannot establish credential context.
			}
		}
		const offsets = new Map<number, number>();
		if (source !== undefined) {
			source = source.replace(/\r\n/g, "\n");
			boundary.discover(source);
			const wanted = new Set<number>();
			for (const match of fileMatches) {
				wanted.add(match.lineNumber);
				for (const ctx of match.contextBefore ?? []) wanted.add(ctx.lineNumber);
				for (const ctx of match.contextAfter ?? []) wanted.add(ctx.lineNumber);
			}
			for (let lineNumber = 1, offset = 0; offset <= source.length && offsets.size < wanted.size; lineNumber++) {
				if (wanted.has(lineNumber)) offsets.set(lineNumber, offset);
				const end = source.indexOf("\n", offset);
				if (end < 0) break;
				offset = end + 1;
			}
		}
		const protectLine = (lineNumber: number, line: string, truncated = false): string => {
			if (truncated || (line.endsWith("...") && Buffer.byteLength(line) >= DEFAULT_MAX_COLUMN - 6)) {
				const omitted = omittedLinesByFile.get(relativePath) ?? new Set<number>();
				omitted.add(lineNumber);
				omittedLinesByFile.set(relativePath, omitted);
				return "[Incomplete source line omitted while credential protection is active]";
			}
			const offset = offsets.get(lineNumber);
			if (
				source === undefined ||
				offset === undefined ||
				!source.startsWith(line, offset) ||
				(offset + line.length < source.length && source[offset + line.length] !== "\n")
			) {
				const omitted = omittedLinesByFile.get(relativePath) ?? new Set<number>();
				omitted.add(lineNumber);
				omittedLinesByFile.set(relativePath, omitted);
				return "[Source context unavailable; line omitted while credential protection is active]";
			}
			return boundary.text(line);
		};
		for (const match of fileMatches) {
			match.line = protectLine(match.lineNumber, match.line, match.truncated);
			for (const ctx of match.contextBefore ?? []) ctx.line = protectLine(ctx.lineNumber, ctx.line);
			for (const ctx of match.contextAfter ?? []) ctx.line = protectLine(ctx.lineNumber, ctx.line);
		}
	}
	return omittedLinesByFile;
}
