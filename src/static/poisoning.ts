/**
 * Tool-description poisoning scanner.
 *
 * Tool descriptions are a documented 2026 attack vector: hidden
 * instructions smuggled into a tool's description can steer the agent that
 * reads them (tool poisoning, rug-pulls, indirect injection). This module
 * runs deterministic pattern checks over tool descriptions, the cheap
 * static control recommended by the ape-mcp improvement research (Sep 2026).
 *
 * Patterns are worded conservatively: several also match legitimate text
 * ("ignore previous instructions" appears in honest docs), so findings are
 * review prompts with quoted evidence, never verdicts.
 */

import type { StaticFinding, StaticSeverity } from "./types.js";

interface PoisonPattern {
	readonly severity: StaticSeverity;
	readonly title: string;
	readonly description: string;
	readonly test: RegExp;
}

const PATTERNS: readonly PoisonPattern[] = [
	{
		severity: "major",
		title: "Instruction-override phrasing in tool description",
		description:
			"The description tells the reader to ignore previous instructions. This is the canonical tool-poisoning shape: it attempts to override the agent's system prompt.",
		test: /\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)\b/i,
	},
	{
		severity: "major",
		title: "System-prompt disclosure request in tool description",
		description:
			"The description asks for the agent's system prompt or instructions to be revealed or repeated.",
		test: /\b(reveal|disclose|repeat|print|output|show)\b.{0,40}\b(system prompt|your instructions|your prompt|initial instructions)\b/i,
	},
	{
		severity: "major",
		title: "Data-exfiltration directive in tool description",
		description:
			"The description instructs sending data to a remote destination.",
		test: /\b(send|post|upload|transmit|exfiltrate)\b.{0,40}\b(to\s+)?(https?:\/\/|an? external|a remote)\b/i,
	},
	{
		severity: "major",
		title: "Jailbreak phrasing in tool description",
		description:
			"The description contains jailbreak-style framing (DAN mode, do-anything-now).",
		test: /\b(do anything now|DAN mode|jailbreak|unrestricted mode|developer mode)\b/i,
	},
	{
		severity: "minor",
		title: "Embedded markdown link in tool description",
		description:
			"The description contains a markdown link. Links in tool metadata can smuggle exfiltration endpoints or prompt-injection payloads past casual review.",
		test: /\[[^\]]+\]\(https?:\/\/[^)]+\)/,
	},
	{
		severity: "minor",
		title: "Urgency/authority manipulation phrasing in tool description",
		description:
			"The description uses urgency or authority framing (act now, do not verify) that pressures an agent to skip checks.",
		test: /\b(act (now|immediately)|do not (verify|question|check)|urgent(ly)?|asap)\b/i,
	},
];

let nextId = 0;

/** Scan one tool description; return findings with quoted evidence. */
export function scanDescription(
	toolName: string,
	description: string,
): StaticFinding[] {
	const findings: StaticFinding[] = [];
	for (const pattern of PATTERNS) {
		const match = pattern.test.exec(description);
		if (match) {
			findings.push({
				id: `st-poi-${++nextId}`,
				severity: pattern.severity,
				category: "static.poisoning",
				tool: toolName,
				title: pattern.title,
				description: `${pattern.description} Matched text is quoted below; confirm intent before installing.`,
				evidence: [
					`description of "${toolName}" matched: "${match[0].slice(0, 160)}"`,
				],
				recommendation:
					"Read the full tool description and confirm the phrasing is intentional.",
			});
		}
		// Reset lastIndex for safety with global-free regexes (defensive).
		pattern.test.lastIndex = 0;
	}
	return findings;
}

/** Reset finding-id counters (tests). */
export function resetPoisoningIds(): void {
	nextId = 0;
}
