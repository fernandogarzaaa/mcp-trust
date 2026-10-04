/**
 * Dimension scoring for the behavioral pass.
 *
 * The penalty schedule (critical 25 / major 12 / minor 4 / info 1,
 * starting from 100, clamped to 0..100) is EVE's session-scorer schedule,
 * documented in experience-validation-engine's src/mcpEval/evaluate.ts and
 * ported here so Sigil stays dependency-free. The evidence selection
 * (top deductions by severity) is a simplified local equivalent: EVE's
 * full scorer threads findings through its global registries, which is
 * session-report plumbing rather than scoring semantics.
 */

import {
	DIMENSIONS,
	DIMENSION_FOR_CATEGORY,
	type Dimension,
	type DimensionScore,
	type Finding,
	type Severity,
} from "./types.js";

const PENALTY: Record<Severity, number> = {
	critical: 25,
	major: 12,
	minor: 4,
	info: 1,
};

const SEVERITY_RANK: Record<Severity, number> = {
	critical: 0,
	major: 1,
	minor: 2,
	info: 3,
};

/** Score one dimension from its findings. */
export function scoreDimension(
	dimension: Dimension,
	findings: readonly Finding[],
): DimensionScore {
	const relevant = findings.filter(
		(f) => DIMENSION_FOR_CATEGORY[f.category] === dimension,
	);
	const total = relevant.reduce((sum, f) => sum + PENALTY[f.severity], 0);
	const value = Math.max(0, 100 - total);
	const evidence = [...relevant]
		.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
		.slice(0, 5)
		.map((f) => `[${f.severity}] ${f.title}`);
	return { dimension, value, evidence };
}

/** Score every dimension from the full finding list. */
export function scoreAllDimensions(
	findings: readonly Finding[],
): DimensionScore[] {
	return DIMENSIONS.map((dimension) => scoreDimension(dimension, findings));
}
