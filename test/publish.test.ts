import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { TrustBadge } from "../src/publish.js";
import {
	CommandError,
	INDEX_REPO,
	badgeTargetPath,
	publishBadge,
	publishBranchName,
	publishPrBody,
	publishPrTitle,
	sanitizeSegment,
} from "../src/publish.js";
import type { RunFn, RunResult } from "../src/publish.js";
import type { TrustReport } from "../src/report.js";
import { keygen, signBadge } from "../src/sign.js";

function minimalReport(): TrustReport {
	return {
		tool: "sigil",
		toolVersion: "0.1.0",
		target: "fixture",
		targetKind: "local",
		server: { name: "fixture-server", version: "0.1.0" },
		riskScore: 0,
		riskLevel: "critical",
		counts: { critical: 1, major: 0, minor: 0, info: 0 },
		static: {
			root: "/tmp/x",
			packageName: "fixture-server",
			packageVersion: "0.1.0",
			toolSource: "runtime",
			toolCount: 1,
			findings: [],
			dependencies: {
				ran: false,
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0,
				info: 0,
			},
			durationMs: 1,
		},
		behavioral: null,
		behavioralError: null,
		durationMs: 2,
	};
}

function signedBadgeFile(dir?: string): string {
	const keyDir = mkdtempSync(join(tmpdir(), "sigil-key-"));
	const { privatePath } = keygen(keyDir);
	const badge = signBadge(minimalReport(), privatePath);
	const outDir = dir ?? mkdtempSync(join(tmpdir(), "sigil-badge-"));
	const path = join(outDir, "badge.json");
	writeFileSync(path, JSON.stringify(badge, null, 2));
	return path;
}

/** Fake runner that simulates gh/git side effects without the network. */
function fakeRunner(
	opts: {
		contentsExists?: boolean;
		authed?: boolean;
		ghPresent?: boolean;
	} = {},
): { run: RunFn; calls: string[] } {
	const calls: string[] = [];
	const run: RunFn = async (
		cmd: string,
		args: string[],
		_runOpts?: { cwd?: string },
	): Promise<RunResult> => {
		calls.push(`${cmd} ${args.join(" ")}`);
		if (cmd === "gh" && args[0] === "--version") {
			if (opts.ghPresent === false) {
				// Same wording as defaultRun's ENOENT path.
				const err = new Error(
					'command not found: "gh". sigil publish needs the GitHub CLI (gh): install it from https://cli.github.com and run `gh auth login`.',
				) as Error & { code: string };
				err.code = "ENOENT";
				throw err;
			}
			return { stdout: "gh version 2.0.0\n", stderr: "" };
		}
		if (cmd === "gh" && args[0] === "auth") {
			if (opts.authed === false) throw new Error("not authenticated");
			return { stdout: "", stderr: "" };
		}
		if (cmd === "gh" && args[0] === "api" && args[1] === "user") {
			return { stdout: "testuser\n", stderr: "" };
		}
		if (cmd === "gh" && args[0] === "api" && args[1]?.includes("/contents/")) {
			if (opts.contentsExists) return { stdout: "{}\n", stderr: "" };
			throw new CommandError(cmd, args, "404 Not Found");
		}
		if (cmd === "gh" && args[0] === "repo" && args[1] === "clone") {
			mkdirSync(args[3], { recursive: true });
			return { stdout: "", stderr: "" };
		}
		if (cmd === "gh" && args[0] === "pr" && args[1] === "create") {
			return {
				stdout: "https://github.com/fernandogarzaaa/sigil-index/pull/1\n",
				stderr: "",
			};
		}
		if (cmd === "git") {
			return { stdout: "", stderr: "" };
		}
		throw new Error(
			`unexpected command in fake runner: ${cmd} ${args.join(" ")}`,
		);
	};
	return { run, calls };
}

describe("sanitizeSegment", () => {
	it("lowercases and replaces unsafe characters", () => {
		expect(sanitizeSegment("My Server!")).toBe("my-server");
		expect(sanitizeSegment("@scope/pkg")).toBe("scope-pkg");
		expect(sanitizeSegment("1.2.3")).toBe("1.2.3");
		// underscore is in the allowed set, only runs of "-" collapse
		expect(sanitizeSegment("a__b")).toBe("a__b");
		expect(sanitizeSegment("a--b")).toBe("a-b");
	});
	it("matches the index validator rule on tricky input", () => {
		expect(sanitizeSegment("...")).toBe("");
		expect(sanitizeSegment("UPPER_CASE.Name-1")).toBe("upper_case.name-1");
	});
});

describe("badgeTargetPath", () => {
	it("builds badges/<server>/<version>.json", () => {
		const badge = { server: "fixture-server", version: "0.1.0" } as TrustBadge;
		expect(badgeTargetPath(badge)).toBe("badges/fixture-server/0.1.0.json");
	});
	it("sanitizes scoped names", () => {
		const badge = { server: "@Org/My Server", version: "2.0" } as TrustBadge;
		expect(badgeTargetPath(badge)).toBe("badges/org-my-server/2.0.json");
	});
	it("rejects unusable names", () => {
		const badge = { server: "...", version: "1.0" } as TrustBadge;
		expect(() => badgeTargetPath(badge)).toThrow(/no usable path segment/);
	});
});

describe("publish PR metadata", () => {
	it("builds a branch name, title, and body", () => {
		const badge = {
			server: "fixture-server",
			version: "0.1.0",
			riskScore: 0,
			riskLevel: "critical",
			findingCounts: { critical: 1, major: 0, minor: 0, info: 0 },
			keyId: "abc123",
			issuedAt: "2026-10-04T00:00:00.000Z",
		} as TrustBadge;
		expect(publishBranchName(badge)).toMatch(
			/^badge\/fixture-server-0\.1\.0-[a-z0-9]{6}$/,
		);
		expect(publishPrTitle(badge)).toBe("Add trust badge: fixture-server@0.1.0");
		const body = publishPrBody(badge);
		expect(body).toContain("0/100 (critical)");
		expect(body).toContain("abc123");
	});
});

describe("publishBadge", () => {
	it("happy path: verifies, clones, commits, pushes, opens a PR", async () => {
		const badgePath = signedBadgeFile();
		const { run, calls } = fakeRunner();
		const result = await publishBadge(badgePath, { run });
		expect(result.prUrl).toBe(
			"https://github.com/fernandogarzaaa/sigil-index/pull/1",
		);
		expect(result.targetPath).toBe("badges/fixture-server/0.1.0.json");
		expect(result.branch).toMatch(/^badge\/fixture-server-0\.1\.0-/);
		const script = calls.join("\n");
		expect(script).toContain("gh --version");
		expect(script).toContain("gh auth status");
		expect(script).toContain(
			"gh api repos/fernandogarzaaa/sigil-index/contents/badges/fixture-server/0.1.0.json",
		);
		expect(script).toContain("gh repo clone fernandogarzaaa/sigil-index");
		expect(script).toContain("git checkout -b badge/fixture-server-0.1.0-");
		expect(script).toContain("git push -u origin badge/fixture-server-0.1.0-");
		expect(script).toContain("gh pr create");
		expect(script).toContain("--repo fernandogarzaaa/sigil-index");
	});

	it("refuses to submit an invalid badge before touching gh", async () => {
		const dir = mkdtempSync(join(tmpdir(), "sigil-badge-"));
		const path = join(dir, "badge.json");
		writeFileSync(path, JSON.stringify({ type: "nope" }));
		const { run, calls } = fakeRunner();
		await expect(publishBadge(path, { run })).rejects.toThrow(
			/failed local verification/,
		);
		expect(calls).toEqual([]);
	});

	it("fails clearly when gh is missing", async () => {
		const badgePath = signedBadgeFile();
		const { run } = fakeRunner({ ghPresent: false });
		await expect(publishBadge(badgePath, { run })).rejects.toThrow(
			/GitHub CLI.*gh auth login/,
		);
	});

	it("fails clearly when gh is not authenticated", async () => {
		const badgePath = signedBadgeFile();
		const { run } = fakeRunner({ authed: false });
		await expect(publishBadge(badgePath, { run })).rejects.toThrow(
			/gh auth login/,
		);
	});

	it("refuses when the version is already indexed", async () => {
		const badgePath = signedBadgeFile();
		const { run, calls } = fakeRunner({ contentsExists: true });
		await expect(publishBadge(badgePath, { run })).rejects.toThrow(
			/already indexed/,
		);
		// verified and checked, but never cloned or pushed
		expect(calls.join("\n")).not.toContain("gh repo clone");
	});

	it("respects a custom repo override", async () => {
		const badgePath = signedBadgeFile();
		const { run, calls } = fakeRunner();
		await publishBadge(badgePath, { run, repo: "someone/else-index" });
		expect(calls.join("\n")).toContain("--repo someone/else-index");
		expect(INDEX_REPO).toBe("fernandogarzaaa/sigil-index");
	});
});
