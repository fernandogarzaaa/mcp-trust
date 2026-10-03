/**
 * Resolving the exact installable artifact for a scan target, so the badge
 * can record it and `trustscan pin` / `trustscan install` can reproduce the
 * verified install later.
 *
 * - npm: the registry spec "name@version" plus dist.integrity when the
 *   registry provides it.
 * - git: the clone URL (no integrity; pin/install refuse these honestly).
 * - local: scanned in place; nothing to install.
 */

import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { TargetKind } from "./resolve.js";
import type { BadgeArtifact } from "./sign.js";

const execFileAsync = promisify(execFile);

function readPackageNameVersion(dir: string): {
	name: string;
	version: string;
} | null {
	try {
		const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
			name?: unknown;
			version?: unknown;
		};
		if (typeof pkg.name === "string" && typeof pkg.version === "string") {
			return { name: pkg.name, version: pkg.version };
		}
		return null;
	} catch {
		return null;
	}
}

async function npmDistIntegrity(
	name: string,
	version: string,
): Promise<string | null> {
	try {
		const { stdout } = await execFileAsync(
			"npm",
			["view", `${name}@${version}`, "dist.integrity", "--json"],
			{ timeout: 60_000, maxBuffer: 4 * 1024 * 1024 },
		);
		const parsed: unknown = JSON.parse(String(stdout));
		return typeof parsed === "string" && parsed.length > 0 ? parsed : null;
	} catch {
		return null;
	}
}

/**
 * Resolve the installable artifact for a scan target. Never throws for
 * missing integrity: integrity is best-effort and reported as null when
 * the registry does not provide it.
 */
export async function resolveArtifact(
	target: string,
	kind: TargetKind,
	dir: string,
): Promise<BadgeArtifact | null> {
	if (kind === "npm") {
		const nv = readPackageNameVersion(dir);
		if (!nv) return null;
		const spec = `${nv.name}@${nv.version}`;
		const integrity = await npmDistIntegrity(nv.name, nv.version);
		return {
			type: "npm",
			spec,
			...(integrity ? { integrity } : {}),
		};
	}
	if (kind === "git") {
		return { type: "git", spec: target.trim() };
	}
	return { type: "local", spec: "local" };
}
