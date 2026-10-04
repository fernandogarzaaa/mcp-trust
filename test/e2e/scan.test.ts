import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const cli = join(repoRoot, "dist", "cli.js");
const fixture = join(repoRoot, "test", "fixtures", "fixture-server");

interface RunResult {
	code: number;
	stdout: string;
	stderr: string;
}

async function runCli(args: string[]): Promise<RunResult> {
	if (!existsSync(cli)) {
		throw new Error(
			`dist/cli.js not found: run "npm run build" before the e2e tests`,
		);
	}
	try {
		const { stdout, stderr } = await execFileAsync("node", [cli, ...args], {
			timeout: 120_000,
			maxBuffer: 16 * 1024 * 1024,
			env: { ...process.env, NO_COLOR: "1" },
		});
		return { code: 0, stdout, stderr };
	} catch (error) {
		const err = error as { code?: number; stdout?: string; stderr?: string };
		return {
			code: err.code ?? 1,
			stdout: String(err.stdout ?? ""),
			stderr: String(err.stderr ?? ""),
		};
	}
}

describe("sigil scan (end to end against the fixture server)", () => {
	it("exits 2 and reports critical risk on the intentionally sketchy fixture", async () => {
		const result = await runCli([
			"scan",
			fixture,
			"--skip-audit",
			"--timeout",
			"3000",
		]);
		expect(result.code).toBe(2);
		expect(result.stdout).toContain("risk score:");
		expect(result.stdout).toContain("(critical)");
		expect(result.stdout).toContain("fixture-server");
	}, 150_000);

	it("emits a JSON report with the expected static and behavioral findings", async () => {
		const result = await runCli([
			"scan",
			fixture,
			"--skip-audit",
			"--timeout",
			"3000",
			"--json",
		]);
		expect(result.code).toBe(2);
		const report = JSON.parse(result.stdout) as {
			riskLevel: string;
			counts: { critical: number };
			static: { findings: { title: string }[] };
			behavioral: {
				findings: { title: string }[];
				scores: { dimension: string }[];
			} | null;
		};
		expect(report.riskLevel).toBe("critical");
		expect(report.counts.critical).toBeGreaterThanOrEqual(1);

		const staticTitles = report.static.findings.map((f) => f.title);
		expect(staticTitles.some((t) => t.includes("Instruction-override"))).toBe(
			true,
		);
		expect(staticTitles.some((t) => t.includes("AWS access key"))).toBe(true);
		expect(
			staticTitles.some((t) =>
				t.includes("data access, network egress, and code execution"),
			),
		).toBe(true);

		expect(report.behavioral).not.toBeNull();
		const behavioralTitles = report.behavioral!.findings.map((f) => f.title);
		expect(behavioralTitles.some((t) => t.includes("no description"))).toBe(
			true,
		);
		expect(report.behavioral!.scores.map((s) => s.dimension).sort()).toEqual([
			"mcp.conformance",
			"mcp.robustness",
			"mcp.schemaQuality",
		]);
	}, 150_000);

	it("passes a well-behaved server: exit 0 under the default gate", async () => {
		const clean = join(repoRoot, "test", "fixtures", "clean-server");
		const result = await runCli([
			"scan",
			clean,
			"--skip-audit",
			"--timeout",
			"3000",
			"--json",
		]);
		expect(result.code).toBe(0);
		const report = JSON.parse(result.stdout) as {
			riskLevel: string;
			riskScore: number;
		};
		expect(report.riskLevel).toBe("low");
		expect(report.riskScore).toBeGreaterThanOrEqual(90);
	}, 150_000);

	it("rejects a bad --fail-on value with exit 1", async () => {
		const result = await runCli([
			"scan",
			fixture,
			"--skip-audit",
			"--no-fuzz",
			"--fail-on",
			"bogus",
		]);
		expect(result.code).toBe(1);
		expect(result.stderr).toContain("--fail-on must be one of");
	}, 60_000);
});
