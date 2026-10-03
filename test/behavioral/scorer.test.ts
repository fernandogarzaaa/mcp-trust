import { describe, expect, it } from "vitest";
import { scoreDimension } from "../../src/behavioral/scorer.js";
import type { Finding } from "../../src/behavioral/types.js";

function finding(severity: Finding["severity"], title: string): Finding {
	return {
		id: "t",
		severity,
		category: "mcp.schema-quality",
		title,
		description: "",
		evidence: [],
	};
}

describe("dimension scoring", () => {
	it("starts at 100 with no findings", () => {
		expect(scoreDimension("mcp.schemaQuality", []).value).toBe(100);
	});

	it("applies the documented penalty schedule (critical 25 / major 12 / minor 4 / info 1)", () => {
		const score = scoreDimension("mcp.schemaQuality", [
			finding("critical", "c"),
			finding("major", "m"),
			finding("minor", "n"),
			finding("info", "i"),
		]);
		expect(score.value).toBe(100 - 25 - 12 - 4 - 1);
	});

	it("floors at 0", () => {
		const findings = Array.from({ length: 10 }, (_, i) =>
			finding("critical", `c${i}`),
		);
		expect(
			scoreDimension(
				"mcp.robustness",
				findings.map((f) => ({ ...f, category: "mcp.robustness" as const })),
			).value,
		).toBe(0);
	});

	it("only counts findings in its own dimension", () => {
		const score = scoreDimension("mcp.conformance", [
			finding("major", "schema issue"),
		]);
		expect(score.value).toBe(100);
	});

	it("cites the driving findings as evidence", () => {
		const score = scoreDimension("mcp.schemaQuality", [
			finding("major", "headline problem"),
		]);
		expect(score.evidence.some((e) => e.includes("headline problem"))).toBe(
			true,
		);
	});
});
