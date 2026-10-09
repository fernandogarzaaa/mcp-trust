/**
 * Manifest parsing: package.json, server entry detection.
 *
 * Reads the scanned tree's package.json (when present) and figures out how
 * the MCP server is launched, so the behavioral pass can spawn it. Never
 * executes anything: pure file reads.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

export interface ServerManifest {
	readonly root: string;
	readonly name: string | null;
	readonly version: string | null;
	/** Absolute path of the launch entry, when one could be determined. */
	readonly entry: string | null;
	/** How the entry was chosen (bin field, main field, conventional file). */
	readonly entrySource: string | null;
	readonly hasMcpDependency: boolean;
	readonly raw: Record<string, unknown> | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readJsonFile(path: string): Record<string, unknown> | null {
	try {
		const text = readFileSync(path, "utf8");
		const parsed: unknown = JSON.parse(text);
		return isRecord(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

/** Candidate server files, in preference order, when bin/main are absent. */
const CONVENTIONAL_FILES = [
	"server.js",
	"server.mjs",
	"server.cjs",
	"index.js",
	"index.mjs",
	"dist/server.js",
	"dist/index.js",
	"build/server.js",
];

/**
 * Pick the server launcher from a multi-entry `bin` map.
 *
 * Packages often ship a CLI next to the MCP server (`{"tool": "cli.js",
 * "tool-mcp": "mcp.js"}`). Spawning the CLI makes the behavioral pass hang
 * or fail, so prefer a bin whose name says it is the MCP server, then one
 * that says "server", then the first entry (the previous behavior).
 */
export function pickServerBin(
	bin: Record<string, unknown>,
): { name: string; path: string } | null {
	const entries = Object.entries(bin).filter(
		(e): e is [string, string] => typeof e[1] === "string" && e[1].length > 0,
	);
	if (entries.length === 0) return null;
	const byName = (re: RegExp) => entries.find(([name]) => re.test(name));
	const chosen =
		byName(/(^|[-_.])mcp($|[-_.])/i) ??
		byName(/mcp/i) ??
		byName(/server/i) ??
		entries[0];
	if (!chosen) return null;
	return { name: chosen[0], path: chosen[1] };
}

export function readManifest(root: string): ServerManifest {
	const absRoot = resolve(root);
	const pkg = readJsonFile(join(absRoot, "package.json"));

	let name: string | null = null;
	let version: string | null = null;
	let entry: string | null = null;
	let entrySource: string | null = null;
	let hasMcpDependency = false;

	if (pkg !== null) {
		if (typeof pkg.name === "string") name = pkg.name;
		if (typeof pkg.version === "string") version = pkg.version;
		const deps = {
			...(isRecord(pkg.dependencies) ? pkg.dependencies : {}),
			...(isRecord(pkg.devDependencies) ? pkg.devDependencies : {}),
		};
		hasMcpDependency = Object.keys(deps).some(
			(d) =>
				d === "@modelcontextprotocol/sdk" ||
				d.startsWith("@modelcontextprotocol/"),
		);

		const bin = pkg.bin;
		if (typeof bin === "string" && bin.length > 0) {
			entry = join(absRoot, bin);
			entrySource = "package.json bin";
		} else if (isRecord(bin)) {
			const picked = pickServerBin(bin);
			if (picked !== null) {
				entry = join(absRoot, picked.path);
				entrySource =
					Object.keys(bin).length > 1
						? `package.json bin (${picked.name})`
						: "package.json bin";
			}
		}
		if (entry === null && typeof pkg.main === "string" && pkg.main.length > 0) {
			entry = join(absRoot, pkg.main as string);
			entrySource = "package.json main";
		}
	}

	if (entry === null) {
		for (const candidate of CONVENTIONAL_FILES) {
			const full = join(absRoot, candidate);
			if (existsSync(full)) {
				entry = full;
				entrySource = `conventional file (${candidate})`;
				break;
			}
		}
	}

	if (entry !== null && !existsSync(entry)) {
		entry = null;
		entrySource = null;
	}

	return {
		root: absRoot,
		name,
		version,
		entry,
		entrySource,
		hasMcpDependency,
		raw: pkg,
	};
}
