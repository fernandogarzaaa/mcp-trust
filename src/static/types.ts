/** Types for the static analysis pass. */

export type StaticSeverity = "critical" | "major" | "minor" | "info";

export type StaticCategory =
	| "static.manifest"
	| "static.capability"
	| "static.secret"
	| "static.egress"
	| "static.exec"
	| "static.poisoning"
	| "static.dependency";

export interface StaticFinding {
	readonly id: string;
	readonly severity: StaticSeverity;
	readonly category: StaticCategory;
	/** Which tool this is about, when the finding is tool-scoped. */
	readonly tool?: string;
	/** Source file (relative to the scanned root) carrying the evidence. */
	readonly file?: string;
	readonly title: string;
	readonly description: string;
	/** Observed snippets. Never vibes. */
	readonly evidence: readonly string[];
	readonly recommendation?: string;
}

export interface DependencySummary {
	readonly ran: boolean;
	readonly critical: number;
	readonly high: number;
	readonly moderate: number;
	readonly low: number;
	readonly info: number;
	readonly note?: string;
}

export interface StaticReport {
	/** Absolute path of the scanned tree. */
	readonly root: string;
	readonly packageName: string | null;
	readonly packageVersion: string | null;
	/** How tools were enumerated: runtime list, source extraction, or none. */
	readonly toolSource: "runtime" | "extracted" | "none";
	readonly toolCount: number;
	readonly findings: readonly StaticFinding[];
	readonly dependencies: DependencySummary;
	readonly durationMs: number;
}
