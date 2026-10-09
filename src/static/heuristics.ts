/**
 * Source-code heuristics: secrets, egress, and execution patterns.
 *
 * Scans JavaScript/TypeScript (and Python, where recognizable) source files
 * for patterns that commonly indicate exfiltration or code-execution risk.
 * Every pattern is a regex over words, so false positives are expected:
 * findings carry file, line, and snippet evidence and are worded as review
 * prompts. Severity is calibrated conservatively: only committed secrets
 * reach critical.
 */

import type { StaticFinding, StaticSeverity } from "./types.js";

export interface CodeHit {
	readonly file: string;
	readonly line: number;
	readonly snippet: string;
}

interface Pattern {
	readonly id: string;
	readonly severity: StaticSeverity;
	readonly title: string;
	readonly description: string;
	readonly recommendation?: string;
	readonly test: RegExp;
	/** Skip lines matching this (reduces comment/import noise). */
	readonly skipLine?: RegExp;
}

const COMMENT_LINE = /^\s*(\/\/|#|\*)/;

const PATTERNS: readonly Pattern[] = [
	{
		id: "secret-aws-key",
		severity: "critical",
		title: "Possible AWS access key committed in source",
		description:
			"A string matching the AWS access-key format was found in source. Committed credentials are live until rotated.",
		recommendation:
			"Rotate the key immediately and move it to environment configuration.",
		test: /\bAKIA[0-9A-Z]{16}\b/,
		skipLine: COMMENT_LINE,
	},
	{
		id: "secret-private-key",
		severity: "critical",
		title: "Private key material in source",
		description: "PEM-encoded private key material was found in source.",
		recommendation:
			"Remove the key material and load keys from a secret store at runtime.",
		test: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
		skipLine: COMMENT_LINE,
	},
	{
		id: "secret-generic",
		severity: "major",
		title: "Possible hardcoded secret assignment",
		description:
			"A variable named like a secret is assigned a non-trivial string literal. Often a committed credential.",
		recommendation: "Move the value to environment configuration.",
		test: /\b(api[_-]?key|secret|passwd|password|auth[_-]?token)\b\s*[:=]\s*["'][^"']{8,}["']/i,
		skipLine: COMMENT_LINE,
	},
	{
		id: "exec-eval",
		severity: "minor",
		title: "Dynamic code evaluation (eval / new Function)",
		description:
			"eval() and new Function() execute strings as code. In a server that also handles untrusted input, this is a code-injection vector.",
		recommendation: "Replace with static dispatch or a sandboxed evaluator.",
		test: /\beval\s*\(|\bnew Function\s*\(/,
		skipLine: COMMENT_LINE,
	},
	{
		id: "exec-template-command",
		severity: "major",
		title: "Shell command built from interpolated input",
		description:
			"A shell command string is assembled with template interpolation or concatenation: a command-injection shape.",
		recommendation:
			"Use execFile with an argument array instead of a shell string.",
		// A bare call, or a call on a child_process-like receiver. Method calls
		// on other objects (`db.exec(...)` in SQLite, `re.exec(...)`) run SQL
		// or regexes, not shells, and were a top false positive.
		test: /(?:(?<![\w$.])|\b(?:child_process|childProcess|cp|proc)\.)(exec|execSync|spawn|spawnSync)\s*\(\s*[`'"][^`'"]*\$\{/,
		skipLine: COMMENT_LINE,
	},
	{
		id: "exec-child-process",
		severity: "minor",
		title: "Shell command execution via child_process",
		description:
			"The server can spawn OS processes. Combined with network input this becomes remote code execution.",
		test: /\b(child_process|execSync|execFileSync|spawnSync)\b|\brequire\s*\(\s*["']child_process["']\s*\)/,
		skipLine: COMMENT_LINE,
	},
	{
		id: "egress-fetch-url",
		severity: "info",
		title: "Network fetch to a hardcoded host",
		description:
			"Source references a hardcoded remote host. Normal for API clients; review where response data flows.",
		test: /\b(fetch|axios\.(get|post)|https?\.request|got\()\s*\(\s*[`'"]https?:\/\//,
		skipLine: COMMENT_LINE,
	},
	{
		id: "egress-hardcoded-url",
		severity: "info",
		title: "Hardcoded remote URL in source",
		description:
			"A hardcoded http(s) URL was found. Verify the host is expected and that no sensitive data is sent to it.",
		test: /["'`]https?:\/\/(?!localhost|127\.0\.0\.1|example\.com)[^\s"'`]+["'`]/,
		skipLine: COMMENT_LINE,
	},
	{
		id: "egress-env-exfil",
		severity: "minor",
		title: "Environment values flow toward a network call in the same file",
		description:
			"The file both reads process.env and makes network calls: a possible credential-exfiltration path. This is normal for API-client servers, so it is minor; confirm by reading the code.",
		test: /__NEVER_MATCHES__/,
		skipLine: COMMENT_LINE,
	},
];

/**
 * File-level composite check: process.env reads plus network calls in one
 * file. Implemented as a composite because no single line carries the
 * pattern.
 */
function checkEnvExfil(lines: string[]): boolean {
	const hasEnv = lines.some(
		(l) => !COMMENT_LINE.test(l) && /\bprocess\.env\b/.test(l),
	);
	const hasNet = lines.some(
		(l) =>
			!COMMENT_LINE.test(l) &&
			/\b(fetch|axios|https?\.request|WebSocket)\b/.test(l),
	);
	return hasEnv && hasNet;
}

/** Scan one file's lines; return one hit per pattern per line (deduped). */
export function scanLines(file: string, lines: readonly string[]): CodeHit[] {
	const hits: CodeHit[] = [];
	lines.forEach((line, index) => {
		for (const pattern of PATTERNS) {
			if (pattern.id === "egress-env-exfil") continue;
			if (pattern.skipLine?.test(line)) continue;
			if (pattern.test.test(line)) {
				hits.push({
					file,
					line: index + 1,
					snippet: line.trim().slice(0, 200),
				});
				break;
			}
		}
	});
	return hits;
}

let nextId = 0;

/** Convert raw hits into findings, one per pattern (evidence lists hits). */
export function hitsToFindings(
	file: string,
	lines: readonly string[],
	hits: readonly CodeHit[],
): StaticFinding[] {
	const findings: StaticFinding[] = [];
	const byPattern = new Map<string, CodeHit[]>();
	// Re-derive the pattern per hit by re-testing (keeps scanLines simple).
	for (const hit of hits) {
		const line = lines[hit.line - 1] ?? "";
		for (const pattern of PATTERNS) {
			if (pattern.id === "egress-env-exfil") continue;
			if (pattern.skipLine?.test(line)) continue;
			if (pattern.test.test(line)) {
				const list = byPattern.get(pattern.id) ?? [];
				list.push(hit);
				byPattern.set(pattern.id, list);
				break;
			}
		}
	}
	for (const pattern of PATTERNS) {
		if (pattern.id === "egress-env-exfil") continue;
		const list = byPattern.get(pattern.id);
		if (!list || list.length === 0) continue;
		findings.push({
			id: `st-heu-${++nextId}`,
			severity: pattern.severity,
			category:
				pattern.id.startsWith("secret") || pattern.id === "egress-env-exfil"
					? "static.secret"
					: pattern.id.startsWith("egress")
						? "static.egress"
						: "static.exec",
			file,
			title: pattern.title,
			description: pattern.description,
			evidence: list
				.slice(0, 5)
				.map((h) => `${h.file}:${h.line}: ${h.snippet}`),
			...(pattern.recommendation
				? { recommendation: pattern.recommendation }
				: {}),
		});
	}
	if (checkEnvExfil([...lines])) {
		const pattern = PATTERNS.find((p) => p.id === "egress-env-exfil");
		if (!pattern) return findings;
		findings.push({
			id: `st-heu-${++nextId}`,
			severity: pattern.severity,
			category: "static.secret",
			file,
			title: pattern.title,
			description: pattern.description,
			evidence: [
				`${file}: reads process.env and makes network calls (heuristic)`,
			],
		});
	}
	return findings;
}

/** Reset finding-id counters (tests). */
export function resetHeuristicIds(): void {
	nextId = 0;
}
