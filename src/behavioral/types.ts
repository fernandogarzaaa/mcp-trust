/**
 * Types for the behavioral MCP evaluation pass.
 *
 * Ported from EVE's mcp-eval harness
 * (experience-validation-engine, src/mcpEval/types.ts). The category and
 * dimension vocabularies are kept identical so reports stay comparable;
 * EVE's global finding-registry wiring is intentionally not ported (it is
 * session-report plumbing, not evaluation semantics).
 */

export type Severity = "critical" | "major" | "minor" | "info";

/** Finding categories, mirroring EVE's mcp-eval pack. */
export const FINDING_CATEGORIES = [
	"mcp.schema-quality",
	"mcp.robustness",
	"mcp.conformance",
] as const;

export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

/** Score dimensions, mirroring EVE's mcp-eval pack. */
export const DIMENSIONS = [
	"mcp.schemaQuality",
	"mcp.robustness",
	"mcp.conformance",
] as const;

export type Dimension = (typeof DIMENSIONS)[number];

/** Finding category to score dimension correspondence. */
export const DIMENSION_FOR_CATEGORY: Record<FindingCategory, Dimension> = {
	"mcp.schema-quality": "mcp.schemaQuality",
	"mcp.robustness": "mcp.robustness",
	"mcp.conformance": "mcp.conformance",
};

/** An evidence-backed finding about an MCP server. */
export interface Finding {
	readonly id: string;
	readonly severity: Severity;
	readonly category: FindingCategory;
	readonly title: string;
	readonly description: string;
	/** What the evaluator observed. Never vibes. */
	readonly evidence: readonly string[];
	/** The tool this finding is about, when specific to one. */
	readonly tool?: string;
	readonly recommendation?: string;
}

/** A 0..100 score on one dimension, with its derivation. */
export interface DimensionScore {
	readonly dimension: Dimension;
	readonly value: number;
	readonly evidence: readonly string[];
}

/** Aggregate fuzz-run statistics. */
export interface FuzzStats {
	readonly toolsFuzzed: number;
	readonly calls: number;
	/** Rejected with a proper JSON-RPC protocol error (the correct behavior). */
	readonly protocolErrors: number;
	/** Rejected with a tool-level `isError` result (acceptable). */
	readonly errorResults: number;
	/** Clearly-invalid input accepted without any error. */
	readonly acceptedInvalid: number;
	/** No response within the call timeout. */
	readonly hangs: number;
	/** The transport died under a call (server crash). */
	readonly crashes: number;
}

/** The full behavioral evaluation report for one MCP server. */
export interface BehavioralReport {
	readonly target: string;
	readonly server: { readonly name: string; readonly version: string } | null;
	readonly toolCount: number;
	/** Tools as advertised on tools/list (names/descriptions normalized). */
	readonly tools: ReadonlyArray<{
		readonly name: string;
		readonly description: string;
	}>;
	/** Whether the server advertises `tools.listChanged` (null: no tools capability). */
	readonly listChanged: boolean | null;
	readonly findings: readonly Finding[];
	readonly scores: readonly DimensionScore[];
	/** Null when fuzzing was disabled or never ran (e.g. zero tools). */
	readonly fuzz: FuzzStats | null;
	readonly durationMs: number;
}
