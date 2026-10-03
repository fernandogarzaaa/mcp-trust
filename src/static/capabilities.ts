/**
 * Tool capability classification and the lethal-trifecta heuristic.
 *
 * Every tool is classified along three capability axes from its name and
 * description (and, when available, its source handler):
 *
 * - data access: reads files, environment, credentials, or other private data
 * - network egress: sends data out over the network
 * - code execution: runs shell commands, scripts, or dynamic code
 *
 * A single tool surface combining all three is the "lethal trifecta"
 * (private-data access + untrusted content + external comms): the shape in
 * which prompt-injection and exfiltration attacks do the most damage. Pairs
 * are worth a look; the full triple is the headline finding.
 *
 * This is a heuristic over words, not a proof of behavior. Legitimate tools
 * (deploy, backup, sync) routinely combine these capabilities, so every
 * finding says so and carries its evidence.
 */

import type { StaticFinding, StaticSeverity } from "./types.js";

export interface ToolDescriptor {
	readonly name: string;
	readonly description: string;
	/** Where this descriptor came from: the live tools/list or source extraction. */
	readonly origin: "runtime" | "extracted";
}

export interface CapabilitySet {
	readonly dataAccess: boolean;
	readonly networkEgress: boolean;
	readonly codeExec: boolean;
}

const DATA_ACCESS = [
	/\b(reads?|loads?|fetch|fetches|cat|opens?)\b.{0,24}\b(file|directory|folder|path|disk)\b/i,
	/\b(fs\.read|readFile|readdir|glob)\b/,
	/\b(env|environment variable|credential|secret|token|api[-_ ]?key|password|private key)\b/i,
	/\bprocess\.env\b/,
	/\b(clipboard|keychain|keyring)\b/i,
];

const NETWORK_EGRESS = [
	/\b(fetch|axios|request|got|ky)\b.{0,24}\b(url|http|endpoint|webhook)\b/i,
	/https?:\/\//,
	/\b(webhook|upload|POST|exfiltrat)/i,
	/\b(dns\.lookup|net\.connect|new WebSocket|EventSource)\b/,
	/\b(send|post|publish).{0,24}\b(email|sms|slack|discord|http)\b/i,
];

const CODE_EXEC = [
	/\b(child_process|execSync|execFile|spawnSync|spawn)\b/,
	/\beval\s*\(/,
	/\bnew Function\s*\(/,
	/\b(vm\.run|vm\.createScript)\b/,
	/\b(run|execute).{0,24}\b(command|shell|script|query|binary)\b/i,
	/\b(shell|bash|sh|powershell|cmd\.exe)\b/i,
];

function matchesAny(text: string, patterns: readonly RegExp[]): boolean {
	return patterns.some((p) => p.test(text));
}

export function classifyCapabilities(
	tool: Pick<ToolDescriptor, "name" | "description">,
): CapabilitySet {
	const text = `${tool.name} ${tool.description}`;
	return {
		dataAccess: matchesAny(text, DATA_ACCESS),
		networkEgress: matchesAny(text, NETWORK_EGRESS),
		codeExec: matchesAny(text, CODE_EXEC),
	};
}

function capabilityWords(caps: CapabilitySet): string[] {
	const words: string[] = [];
	if (caps.dataAccess) words.push("data access");
	if (caps.networkEgress) words.push("network egress");
	if (caps.codeExec) words.push("code execution");
	return words;
}

let nextId = 0;

function finding(
	severity: StaticSeverity,
	tool: string,
	title: string,
	description: string,
	evidence: string[],
	recommendation?: string,
): StaticFinding {
	return {
		id: `st-cap-${++nextId}`,
		severity,
		category: "static.capability",
		tool,
		title,
		description,
		evidence,
		...(recommendation ? { recommendation } : {}),
	};
}

/**
 * Flag capability combinations on each tool. Returns one finding per tool
 * that combines two or more capabilities (three = major, two = minor),
 * plus an info finding listing single-capability tools for the record.
 */
export function checkCapabilities(
	tools: readonly ToolDescriptor[],
): StaticFinding[] {
	const findings: StaticFinding[] = [];
	for (const tool of tools) {
		const caps = classifyCapabilities(tool);
		const count = [caps.dataAccess, caps.networkEgress, caps.codeExec].filter(
			Boolean,
		).length;
		if (count === 3) {
			findings.push(
				finding(
					"major",
					tool.name,
					`"${tool.name}" combines data access, network egress, and code execution`,
					"This is the lethal-trifecta shape: a single tool surface that can read private data, send it out over the network, and run code. It is also the shape of legitimate deploy/backup/sync tools, so treat this as a review prompt, not a verdict.",
					[
						`capabilities detected: ${capabilityWords(caps).join(", ")}`,
						`name: "${tool.name}"`,
						`description: "${tool.description.slice(0, 160)}"`,
						`descriptor origin: ${tool.origin}`,
					],
					"Confirm the tool needs all three capabilities; if it does, document why in the tool description.",
				),
			);
		} else if (count === 2) {
			findings.push(
				finding(
					"minor",
					tool.name,
					`"${tool.name}" combines two sensitive capabilities`,
					"Tools that pair private-data access with network egress, or either with code execution, deserve a second look before install.",
					[
						`capabilities detected: ${capabilityWords(caps).join(", ")}`,
						`descriptor origin: ${tool.origin}`,
					],
				),
			);
		}
	}
	return findings;
}
