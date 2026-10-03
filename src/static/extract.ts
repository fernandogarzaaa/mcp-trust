/**
 * Best-effort tool extraction from source.
 *
 * The MCP tool surface is authoritative only at runtime (tools/list), but
 * the static pass benefits from knowing tool names and descriptions before
 * spawning anything. This module extracts `server.tool(...)` /
 * `registerTool(...)` call sites with tolerant regexes over JS/TS source.
 *
 * It is explicitly best-effort: dynamic registration, wrappers, and
 * non-SDK frameworks will be missed. Findings built from extracted tools
 * are labeled origin "extracted" so the report never overstates them.
 */

import { readFileSync } from "node:fs";
import type { ToolDescriptor } from "./capabilities.js";

/** Matches: server.tool("name", "description", ...) or registerTool("name", "description", ...) */
const TOOL_CALL =
	/(?:server\s*\.\s*tool|registerTool)\s*\(\s*["'`]([^"'`]+)["'`]\s*(?:,\s*["'`]([^"'`]*)["'`])?/g;
/** Matches: { name: "x", description: "y" } object-literal registrations */
const TOOL_OBJECT =
	/\{\s*name\s*:\s*["'`]([^"'`]+)["'`]\s*,\s*description\s*:\s*["'`]([^"'`]*)["'`]/g;

function unescapeJs(s: string): string {
	return s.replace(/\\(["'`\\nrt])/g, (_m, c: string) => {
		switch (c) {
			case "n":
				return "\n";
			case "r":
				return "\r";
			case "t":
				return "\t";
			default:
				return c;
		}
	});
}

/** Extract tool descriptors from one source file's text. */
export function extractToolsFromText(text: string): ToolDescriptor[] {
	const found = new Map<string, ToolDescriptor>();
	const patterns = [TOOL_CALL, TOOL_OBJECT];
	for (const pattern of patterns) {
		pattern.lastIndex = 0;
		let match = pattern.exec(text);
		while (match !== null) {
			const name = match[1];
			const description = match[2] !== undefined ? unescapeJs(match[2]) : "";
			if (name && !found.has(name)) {
				found.set(name, { name, description, origin: "extracted" });
			}
			match = pattern.exec(text);
		}
	}
	return [...found.values()];
}

/** Extract tool descriptors from a file on disk. Returns [] on read errors. */
export function extractToolsFromFile(path: string): ToolDescriptor[] {
	try {
		return extractToolsFromText(readFileSync(path, "utf8"));
	} catch {
		return [];
	}
}
