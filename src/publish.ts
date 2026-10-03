/**
 * trustscan publish: submit a signed trust badge to the public trust index
 * (fernandogarzaaa/mcp-trust-index) by opening a pull request.
 *
 * Flow: local verify first, then via the GitHub CLI (gh): clone the index
 * repo to a temp dir, add badges/<server>/<version>.json on a new branch,
 * push, and open a PR. Every step shells out to real commands; there are no
 * stubs. When gh is missing or unauthenticated the command fails with a
 * clear error telling the user exactly what to do.
 *
 * The command runner is injectable so the orchestration logic is unit
 * tested without touching the network.
 */

import { execFile } from "node:child_process";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { type TrustBadge, verifyBadge } from "./sign.js";

export const INDEX_REPO = "fernandogarzaaa/mcp-trust-index";
export const INDEX_BRANCH = "main";

/**
 * Path segment rule. MUST stay identical to scripts/validate.mjs in the
 * index repo: lowercase, anything outside [a-z0-9._-] becomes "-", runs
 * collapsed, leading/trailing dashes and dots trimmed.
 */
export function sanitizeSegment(raw: string): string {
	const out = String(raw)
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, "-")
		.replace(/-+/g, "-")
		.replace(/^[-.]+|[-.]+$/g, "");
	return out;
}

/** badges/<server>/<version>.json for a badge. Throws on unusable names. */
export function badgeTargetPath(badge: TrustBadge): string {
	const server = sanitizeSegment(badge.server);
	const version = sanitizeSegment(badge.version);
	if (!server || server === "." || server === "..") {
		throw new Error(
			`cannot publish: server name "${badge.server}" has no usable path segment`,
		);
	}
	if (!version || version === "." || version === "..") {
		throw new Error(
			`cannot publish: version "${badge.version}" has no usable path segment`,
		);
	}
	return `badges/${server}/${version}.json`;
}

export function publishBranchName(badge: TrustBadge): string {
	const rand = Math.random().toString(36).slice(2, 8);
	return `badge/${sanitizeSegment(badge.server)}-${sanitizeSegment(badge.version)}-${rand}`;
}

export function publishPrTitle(badge: TrustBadge): string {
	return `Add trust badge: ${badge.server}@${badge.version}`;
}

export function publishPrBody(badge: TrustBadge): string {
	const fc = badge.findingCounts;
	return [
		"Trust badge submission via trustscan.",
		"",
		`- Server: ${badge.server} @ ${badge.version}`,
		`- Risk: ${badge.riskScore}/100 (${badge.riskLevel})`,
		`- Findings: ${fc.critical} critical, ${fc.major} major, ${fc.minor} minor, ${fc.info} info`,
		`- Signer key: ${badge.keyId}`,
		`- Issued: ${badge.issuedAt}`,
		"",
		"CI validates the badge schema and Ed25519 signature before merge.",
	].join("\n");
}

export interface RunResult {
	readonly stdout: string;
	readonly stderr: string;
}

export type RunFn = (
	cmd: string,
	args: string[],
	opts?: { cwd?: string },
) => Promise<RunResult>;

export class CommandError extends Error {
	readonly cmd: string;
	readonly args: string[];
	readonly stderr: string;
	constructor(cmd: string, args: string[], stderr: string) {
		super(
			`\`${cmd} ${args.join(" ")}\` failed: ${stderr.trim() || "(no output)"}`,
		);
		this.name = "CommandError";
		this.cmd = cmd;
		this.args = args;
		this.stderr = stderr;
	}
}

export const defaultRun: RunFn = (cmd, args, opts) =>
	new Promise((resolvePromise, reject) => {
		execFile(
			cmd,
			args,
			{ cwd: opts?.cwd, maxBuffer: 10 * 1024 * 1024 },
			(error, stdout, stderr) => {
				if (error) {
					const err = error as NodeJS.ErrnoException & {
						code?: string | number;
					};
					if (err.code === "ENOENT") {
						reject(
							new Error(
								`command not found: "${cmd}". trustscan publish needs the GitHub CLI (gh): install it from https://cli.github.com and run \`gh auth login\`.`,
							),
						);
						return;
					}
					reject(new CommandError(cmd, args, String(stderr)));
					return;
				}
				resolvePromise({ stdout: String(stdout), stderr: String(stderr) });
			},
		);
	});

async function checkGh(run: RunFn): Promise<void> {
	await run("gh", ["--version"]);
	try {
		await run("gh", ["auth", "status"]);
	} catch {
		throw new Error(
			"gh is not authenticated. Run `gh auth login`, then try again.",
		);
	}
}

async function ghUsername(run: RunFn): Promise<string> {
	try {
		const { stdout } = await run("gh", ["api", "user", "--jq", ".login"]);
		const login = stdout.trim();
		if (login) return login;
	} catch {
		// fall through to default
	}
	return "trustscan";
}

/** Returns true when the badge path already exists in the index repo. */
async function badgeAlreadyIndexed(
	run: RunFn,
	repo: string,
	targetPath: string,
): Promise<boolean> {
	try {
		await run("gh", ["api", `repos/${repo}/contents/${targetPath}`]);
		return true;
	} catch (error) {
		if (error instanceof CommandError) return false; // 404 or similar: not indexed
		throw error;
	}
}

export interface PublishOptions {
	/** Index repo override, default fernandogarzaaa/mcp-trust-index. */
	repo?: string;
	run?: RunFn;
	/** Keep the temp clone for debugging instead of deleting it. */
	keepWorkdir?: boolean;
}

export interface PublishResult {
	readonly prUrl: string;
	readonly branch: string;
	readonly targetPath: string;
	readonly workdir: string | null;
}

/**
 * Publish a signed badge file to the trust index via a pull request.
 * Runs local cryptographic verification first and submits nothing when the
 * badge is invalid.
 */
export async function publishBadge(
	badgePath: string,
	opts: PublishOptions = {},
): Promise<PublishResult> {
	const run = opts.run ?? defaultRun;
	const repo = opts.repo ?? INDEX_REPO;
	const resolved = resolve(badgePath);

	let badge: TrustBadge;
	try {
		badge = JSON.parse(readFileSync(resolved, "utf8")) as TrustBadge;
	} catch (error) {
		throw new Error(
			`cannot read badge file ${resolved}: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
	const verified = verifyBadge(badge);
	if (!verified.ok) {
		throw new Error(
			`badge failed local verification (${verified.reason}); not submitting anything`,
		);
	}
	const targetPath = badgeTargetPath(badge);

	await checkGh(run);
	if (await badgeAlreadyIndexed(run, repo, targetPath)) {
		throw new Error(
			`${targetPath} is already indexed in ${repo}; each version is published once`,
		);
	}

	const parentDir = mkdtempSync(join(tmpdir(), "trustscan-publish-"));
	const workdir = join(parentDir, "index");
	try {
		await run("gh", ["repo", "clone", repo, workdir]);
		const branch = publishBranchName(badge);
		await run("git", ["checkout", "-b", branch], { cwd: workdir });
		const dest = join(workdir, targetPath);
		mkdirSync(join(workdir, "badges", sanitizeSegment(badge.server)), {
			recursive: true,
		});
		writeFileSync(dest, `${JSON.stringify(badge, null, 2)}\n`);
		await run("git", ["add", targetPath], { cwd: workdir });
		const login = await ghUsername(run);
		await run(
			"git",
			[
				"-c",
				`user.name=${login}`,
				"-c",
				`user.email=${login}@users.noreply.github.com`,
				"commit",
				"-m",
				`Add trust badge: ${badge.server}@${badge.version}`,
			],
			{ cwd: workdir },
		);
		await run("git", ["push", "-u", "origin", branch], { cwd: workdir });
		const { stdout } = await run(
			"gh",
			[
				"pr",
				"create",
				"--repo",
				repo,
				"--head",
				branch,
				"--base",
				INDEX_BRANCH,
				"--title",
				publishPrTitle(badge),
				"--body",
				publishPrBody(badge),
			],
			{ cwd: workdir },
		);
		const prUrl = stdout.trim().split("\n").pop() ?? "";
		if (!prUrl.startsWith("http")) {
			throw new Error(
				`gh pr create did not return a PR URL (got: ${stdout.trim() || "(empty)"})`,
			);
		}
		if (!opts.keepWorkdir) {
			rmSync(parentDir, { recursive: true, force: true });
			return { prUrl, branch, targetPath, workdir: null };
		}
		return { prUrl, branch, targetPath, workdir };
	} catch (error) {
		if (!opts.keepWorkdir) rmSync(parentDir, { recursive: true, force: true });
		throw error;
	}
}
