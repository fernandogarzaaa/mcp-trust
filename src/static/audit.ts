/**
 * Dependency audit via `npm audit --json`.
 *
 * Runs the npm audit the developer would run themselves, then rolls the
 * counts up into findings. The audit needs a network connection and can be
 * slow on large trees, so it runs with a timeout and degrades to an info
 * finding ("audit unavailable") instead of failing the scan.
 */

import { execFile } from "node:child_process";
import type { DependencySummary, StaticFinding } from "./types.js";

const AUDIT_TIMEOUT_MS = 90_000;
const MAX_BUFFER = 16 * 1024 * 1024;

interface AuditJson {
	metadata?: {
		vulnerabilities?: {
			critical?: number;
			high?: number;
			moderate?: number;
			low?: number;
			info?: number;
		};
	};
	advisories?: Record<
		string,
		{ severity?: string; title?: string; url?: string }
	>;
}

function runAudit(dir: string): Promise<AuditJson | null> {
	return new Promise((resolve) => {
		execFile(
			"npm",
			["audit", "--json", "--omit=dev"],
			{ cwd: dir, timeout: AUDIT_TIMEOUT_MS, maxBuffer: MAX_BUFFER },
			(error, stdout) => {
				// npm exits non-zero when vulnerabilities are found; stdout still
				// carries the JSON report, so parse regardless of exit code.
				try {
					const parsed: unknown = JSON.parse(String(stdout));
					if (parsed && typeof parsed === "object") {
						resolve(parsed as AuditJson);
						return;
					}
				} catch {
					// fall through to null
				}
				void error;
				resolve(null);
			},
		);
	});
}

let nextId = 0;

/** Roll the audit counts into a summary plus findings. */
export function summarizeAudit(json: AuditJson | null): {
	summary: DependencySummary;
	findings: StaticFinding[];
} {
	if (json === null) {
		return {
			summary: {
				ran: false,
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0,
				info: 0,
				note: "npm audit did not return usable JSON (no network, no lockfile, or timed out)",
			},
			findings: [
				{
					id: `st-dep-${++nextId}`,
					severity: "info",
					category: "static.dependency",
					title: "Dependency audit unavailable",
					description:
						"npm audit could not run (no network, no lockfile, or it timed out). Dependency risk is unknown, not zero.",
					evidence: ["npm audit --json produced no usable report"],
				},
			],
		};
	}
	const vulns = json.metadata?.vulnerabilities ?? {};
	const summary: DependencySummary = {
		ran: true,
		critical: vulns.critical ?? 0,
		high: vulns.high ?? 0,
		moderate: vulns.moderate ?? 0,
		low: vulns.low ?? 0,
		info: vulns.info ?? 0,
	};
	const findings: StaticFinding[] = [];
	const push = (
		severity: StaticFinding["severity"],
		title: string,
		description: string,
		evidence: string[],
	): void => {
		findings.push({
			id: `st-dep-${++nextId}`,
			severity,
			category: "static.dependency",
			title,
			description,
			evidence,
			recommendation: "Run npm audit fix or upgrade the affected packages.",
		});
	};
	if (summary.critical > 0) {
		push(
			"major",
			`${summary.critical} critical-severity vulnerabilities in dependencies`,
			"npm audit reports critical vulnerabilities in the dependency tree. A compromised dependency can subvert the whole server.",
			[`npm audit: ${summary.critical} critical`],
		);
	}
	if (summary.high > 0) {
		push(
			"minor",
			`${summary.high} high-severity vulnerabilities in dependencies`,
			"npm audit reports high-severity vulnerabilities in the dependency tree.",
			[`npm audit: ${summary.high} high`],
		);
	}
	if (summary.moderate + summary.low + summary.info > 0) {
		findings.push({
			id: `st-dep-${++nextId}`,
			severity: "info",
			category: "static.dependency",
			title: "Lower-severity dependency findings present",
			description:
				"npm audit reports moderate/low/info findings. Review on a normal cadence.",
			evidence: [
				`npm audit: ${summary.moderate} moderate, ${summary.low} low, ${summary.info} info`,
			],
		});
	}
	return { summary, findings };
}

/** Run the audit and summarize it. Set SIGIL_SKIP_AUDIT=1 to skip (tests). */
export async function auditDependencies(dir: string): Promise<{
	summary: DependencySummary;
	findings: StaticFinding[];
}> {
	if (process.env.SIGIL_SKIP_AUDIT === "1") {
		return {
			summary: {
				ran: false,
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0,
				info: 0,
				note: "skipped via SIGIL_SKIP_AUDIT=1",
			},
			findings: [],
		};
	}
	const json = await runAudit(dir);
	return summarizeAudit(json);
}

/** Reset finding-id counters (tests). */
export function resetAuditIds(): void {
	nextId = 0;
}
