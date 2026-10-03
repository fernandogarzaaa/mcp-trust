/**
 * Trust report: unifies the static and behavioral passes into one scored,
 * explainable verdict.
 *
 * Risk score: every finding deducts from 100 on one schedule
 * (critical 25 / major 12 / minor 4 / info 1, the same schedule the
 * behavioral oracles use), floored at 0. Higher is more trustworthy.
 *
 * Risk level: any critical finding forces "critical". Otherwise the score
 * bands decide: below 70 is "high", below 90 is "medium", the rest "low".
 * The mapping is documented here and in the README so a score is never a
 * black box.
 */

import type { BehavioralReport } from "./behavioral/index.js";
import type { TargetKind } from "./resolve.js";
import type { BadgeArtifact } from "./sign.js";
import type { StaticReport } from "./static/index.js";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export const RISK_LEVELS: readonly RiskLevel[] = [
	"low",
	"medium",
	"high",
	"critical",
];

export interface FindingCounts {
	readonly critical: number;
	readonly major: number;
	readonly minor: number;
	readonly info: number;
}

export interface TrustReport {
	readonly tool: "mcp-trust";
	readonly toolVersion: string;
	readonly target: string;
	readonly targetKind: TargetKind;
	readonly server: { readonly name: string; readonly version: string } | null;
	/** Exact installable artifact, when the target resolved to one. */
	readonly artifact: BadgeArtifact | null;
	readonly riskScore: number;
	readonly riskLevel: RiskLevel;
	readonly counts: FindingCounts;
	readonly static: StaticReport;
	/** Null when the server could not be started or connected to. */
	readonly behavioral: BehavioralReport | null;
	readonly behavioralError: string | null;
	readonly durationMs: number;
}

const PENALTY = { critical: 25, major: 12, minor: 4, info: 1 } as const;

export function computeRiskScore(
	staticReport: StaticReport,
	behavioral: BehavioralReport | null,
): { score: number; counts: FindingCounts; level: RiskLevel } {
	const counts: { -readonly [K in keyof FindingCounts]: number } = {
		critical: 0,
		major: 0,
		minor: 0,
		info: 0,
	};
	for (const f of staticReport.findings) counts[f.severity] += 1;
	if (behavioral) {
		for (const f of behavioral.findings) counts[f.severity] += 1;
	}
	const deducted =
		counts.critical * PENALTY.critical +
		counts.major * PENALTY.major +
		counts.minor * PENALTY.minor +
		counts.info * PENALTY.info;
	const score = Math.max(0, 100 - deducted);
	const level: RiskLevel =
		counts.critical > 0
			? "critical"
			: score < 70
				? "high"
				: score < 90
					? "medium"
					: "low";
	return { score, counts, level };
}

export function assembleReport(args: {
	toolVersion: string;
	target: string;
	targetKind: TargetKind;
	server: { readonly name: string; readonly version: string } | null;
	artifact?: BadgeArtifact | null;
	static: StaticReport;
	behavioral: BehavioralReport | null;
	behavioralError: string | null;
	durationMs: number;
}): TrustReport {
	const { score, counts, level } = computeRiskScore(
		args.static,
		args.behavioral,
	);
	return {
		tool: "mcp-trust",
		toolVersion: args.toolVersion,
		target: args.target,
		targetKind: args.targetKind,
		server: args.server,
		artifact: args.artifact ?? null,
		riskScore: score,
		riskLevel: level,
		counts,
		static: args.static,
		behavioral: args.behavioral,
		behavioralError: args.behavioralError,
		durationMs: args.durationMs,
	};
}

/** Render the human-readable summary (no em dashes, CI-log friendly). */
export function renderHumanSummary(report: TrustReport): string {
	const lines: string[] = [];
	const serverLabel = report.server
		? `${report.server.name}@${report.server.version}`
		: (report.static.packageName ?? report.target);
	lines.push(`trustscan: ${serverLabel} [${report.targetKind}]`);
	lines.push(`risk score: ${report.riskScore}/100 (${report.riskLevel})`);
	const c = report.counts;
	lines.push(
		`findings: ${c.critical + c.major + c.minor + c.info} total ` +
			`(${c.critical} critical, ${c.major} major, ${c.minor} minor, ${c.info} info)`,
	);
	lines.push(
		`static: ${report.static.findings.length} findings over ${report.static.toolCount} tool(s) [${report.static.toolSource}]`,
	);
	if (report.behavioral) {
		const b = report.behavioral;
		const scores = b.scores
			.map((s) => `${s.dimension.replace("mcp.", "")} ${s.value}/100`)
			.join(", ");
		lines.push(`behavioral: ${scores}`);
		if (b.fuzz) {
			lines.push(
				`fuzz: ${b.fuzz.calls} calls over ${b.fuzz.toolsFuzzed} tool(s): ` +
					`${b.fuzz.protocolErrors} protocol errors, ${b.fuzz.errorResults} error results, ` +
					`${b.fuzz.acceptedInvalid} accepted-invalid, ${b.fuzz.hangs} hangs, ${b.fuzz.crashes} crashes`,
			);
		}
	} else {
		lines.push(
			`behavioral: skipped (${report.behavioralError ?? "no launchable server entry found"})`,
		);
	}
	lines.push("");
	const all = [
		...report.static.findings.map((f) => ({ ...f, pass: "static" })),
		...(report.behavioral
			? report.behavioral.findings.map((f) => ({ ...f, pass: "behavioral" }))
			: []),
	];
	const rank: Record<string, number> = {
		critical: 0,
		major: 1,
		minor: 2,
		info: 3,
	};
	const sorted = [...all].sort(
		(a, b) => (rank[a.severity] ?? 99) - (rank[b.severity] ?? 99),
	);
	for (const f of sorted.slice(0, 25)) {
		const where = f.tool ? ` [${f.tool}]` : "";
		const file = "file" in f && f.file ? ` (${f.file})` : "";
		lines.push(`[${f.severity}]${where}${file} ${f.title} (${f.pass})`);
		for (const ev of f.evidence.slice(0, 3)) lines.push(`    - ${ev}`);
	}
	if (sorted.length > 25)
		lines.push(
			`... and ${sorted.length - 25} more (see --json for the full report)`,
		);
	lines.push("");
	lines.push(
		"Note: static checks are heuristics and can misfire; a passing scan is not a guarantee. See README limitations.",
	);
	return `${lines.join("\n")}\n`;
}
