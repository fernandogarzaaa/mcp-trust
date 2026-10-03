/**
 * Target resolution: turn a scan target into a local directory.
 *
 * Accepted target forms:
 * - local directory path (existing directory on disk): used in place,
 *   read-only. The scanner never writes into it.
 * - npm package spec (`name`, `name@version`, `@scope/name@tag`): fetched
 *   with `npm pack` into a temp dir and unpacked.
 * - git URL (`https://...`, `git@...`, `git+...`, or anything ending in
 *   `.git`): shallow-cloned into a temp dir.
 *
 * Temp dirs are created under os.tmpdir() and left for the OS to reap;
 * callers that want prompt cleanup can remove `result.cleanup()`.
 */

import { execFile } from "node:child_process";
import {
	existsSync,
	mkdtempSync,
	readdirSync,
	rmSync,
	statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type TargetKind = "local" | "npm" | "git";

export interface ResolvedTarget {
	readonly kind: TargetKind;
	/** Absolute path of the scanned tree. */
	readonly dir: string;
	/** The original target string, for reporting. */
	readonly display: string;
	/** Remove the fetched tree (no-op for local dirs). */
	cleanup(): void;
}

function isGitUrl(target: string): boolean {
	if (target.endsWith(".git")) return true;
	if (/^(git@|ssh:\/\/|git\+https?:)/.test(target)) return true;
	// owner/repo shorthand without any npm-spec characters
	if (/^[^/@\s]+\/[^/@\s]+$/.test(target) && !target.startsWith("@"))
		return true;
	return false;
}

function isNpmSpec(target: string): boolean {
	if (
		target.startsWith(".") ||
		target.startsWith("/") ||
		target.startsWith("~")
	)
		return false;
	if (existsSync(resolve(target))) return false;
	if (isGitUrl(target)) return false;
	if (/^https?:\/\//.test(target)) return false;
	// npm spec: name, @scope/name, with optional @version/@tag suffix
	return /^(@[^/]+\/)?[^/@\s]+(@[^/\s]+)?$/.test(target);
}

function makeTempDir(prefix: string): string {
	return mkdtempSync(join(tmpdir(), prefix));
}

async function fetchNpm(target: string): Promise<ResolvedTarget> {
	const workdir = makeTempDir("trustscan-npm-");
	const { stdout } = await execFileAsync(
		"npm",
		["pack", target, "--pack-destination", workdir],
		{
			timeout: 180_000,
			maxBuffer: 64 * 1024 * 1024,
		},
	);
	const tarballName = String(stdout).trim().split("\n").pop() ?? "";
	if (!tarballName.endsWith(".tgz")) {
		throw new Error(
			`npm pack did not produce a tarball for "${target}" (output: ${tarballName})`,
		);
	}
	const outdir = join(workdir, "package");
	await execFileAsync(
		"tar",
		["-xzf", join(workdir, tarballName), "-C", workdir],
		{
			timeout: 60_000,
		},
	);
	// Install production dependencies so the behavioral pass can actually
	// launch the server. Without this, packed servers fail to start with
	// missing-module errors and the scan degrades to static-only.
	// Best-effort: if install fails, the behavioral pass reports it honestly.
	try {
		await execFileAsync(
			"npm",
			[
				"install",
				"--omit=dev",
				"--ignore-scripts",
				"--legacy-peer-deps",
				"--no-audit",
				"--no-fund",
				"--loglevel=error",
			],
			{ cwd: outdir, timeout: 300_000, maxBuffer: 64 * 1024 * 1024 },
		);
	} catch {
		// The behavioral pass will fail gracefully and say so in the report.
	}
	return {
		kind: "npm",
		dir: outdir,
		display: target,
		cleanup: () => rmSync(workdir, { recursive: true, force: true }),
	};
}

async function fetchGit(target: string): Promise<ResolvedTarget> {
	const workdir = makeTempDir("trustscan-git-");
	const url = /^[^/@\s]+\/[^/@\s]+$/.test(target)
		? `https://github.com/${target}.git`
		: target;
	await execFileAsync("git", ["clone", "--depth", "1", url, workdir], {
		timeout: 180_000,
		maxBuffer: 64 * 1024 * 1024,
	});
	// Shallow clone into an existing dir leaves .git inside workdir: fine.
	return {
		kind: "git",
		dir: workdir,
		display: target,
		cleanup: () => rmSync(workdir, { recursive: true, force: true }),
	};
}

/** Classify a target string without touching the network or disk. */
export function classifyTarget(target: string): TargetKind {
	const trimmed = target.trim();
	if (trimmed.length === 0) throw new Error("empty scan target");
	try {
		if (statSync(resolve(trimmed)).isDirectory()) return "local";
	} catch {
		// not a local path; fall through to URL/spec detection
	}
	if (isGitUrl(trimmed)) return "git";
	if (isNpmSpec(trimmed)) return "npm";
	throw new Error(
		`cannot resolve target "${target}": not a local directory, git URL, or npm package spec`,
	);
}

/** Resolve a target to a local directory, fetching when needed. */
export async function resolveTarget(target: string): Promise<ResolvedTarget> {
	const kind = classifyTarget(target);
	if (kind === "local") {
		return {
			kind,
			dir: resolve(target.trim()),
			display: target.trim(),
			cleanup: () => {},
		};
	}
	if (kind === "npm") return fetchNpm(target.trim());
	return fetchGit(target.trim());
}

/** List candidate source files under a dir (skips node_modules, dist, .git, test). */
export function listSourceFiles(root: string): string[] {
	const out: string[] = [];
	const skip = new Set([
		"node_modules",
		"dist",
		"build",
		".git",
		"coverage",
		".turbo",
		"__tests__",
		"__test__",
	]);
	const skipFile = /(\.test\.|\.spec\.)(js|mjs|cjs|ts|mts|cts|jsx|tsx|py)$/;
	const walk = (dir: string): void => {
		let entries: string[];
		try {
			entries = readdirSync(dir, { withFileTypes: true }).map((e) => e.name);
		} catch {
			return;
		}
		for (const name of entries) {
			if (name.startsWith(".") && name !== ".") {
				if (name === ".git") continue;
			}
			// Skip test directories entirely: fixtures and dummy credentials
			// in tests are a top source of false positives.
			if (name === "test" || name === "tests") continue;
			const full = join(dir, name);
			let isDir = false;
			try {
				isDir = statSync(full).isDirectory();
			} catch {
				continue;
			}
			if (isDir) {
				if (!skip.has(name)) walk(full);
			} else if (/\.(js|mjs|cjs|ts|mts|cts|jsx|tsx|py)$/.test(name)) {
				if (skipFile.test(full)) continue;
				out.push(full);
			}
		}
	};
	walk(root);
	return out;
}
