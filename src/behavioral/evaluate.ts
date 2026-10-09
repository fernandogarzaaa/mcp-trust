/**
 * Behavioral evaluation entry point: connect to a server, run the
 * deterministic oracles, and produce an evidence-backed report.
 *
 * Oracle mix (ported from EVE's mcp-eval):
 * - schema oracle -> `mcp.schemaQuality` (no calls; pure advertisement checks)
 * - conformance   -> `mcp.conformance`  (handshake, capabilities, ping, error codes)
 * - fuzz oracle   -> `mcp.robustness`    (seeded adversarial inputs, crash/hang classification)
 */

import { checkConformance } from "./conformanceOracle.js";
import { type FuzzOptions, fuzzTools } from "./fuzzOracle.js";
import {
	type ConnectOptions,
	connectMcpServer,
	type McpConnector,
} from "./mcpConnection.js";
import { checkToolSchemas, resetFindingIds } from "./schemaOracle.js";
import { scoreAllDimensions } from "./scorer.js";
import type { BehavioralReport, Finding } from "./types.js";

export interface EvaluateOptions {
	/** Override the transport (tests inject an in-process fixture server). */
	readonly connector?: McpConnector;
	/** Options passed through to stdio spawning (cwd, env). */
	readonly connect?: ConnectOptions;
	/** Fuzzing is on by default; pass false to skip, or options to tune it. */
	readonly fuzz?: boolean | FuzzOptions;
}

/**
 * Evaluate one MCP server and return the full report. The connection is
 * always closed before returning, including on oracle failure.
 *
 * Target forms: `node server.js --flag` (stdio), `http(s)://...` (HTTP), or
 * anything accepted by the injected connector. An `mcp:` scheme prefix is
 * stripped if present.
 */
export async function evaluateMcpServer(
	target: string,
	options: EvaluateOptions = {},
): Promise<BehavioralReport> {
	resetFindingIds();
	const bareTarget = target.startsWith("mcp:") ? target.slice(4) : target;
	const connector: McpConnector =
		options.connector ??
		((t: string) => connectMcpServer(t, options.connect ?? {}));
	const started = Date.now();

	const conn = await connector(bareTarget);
	try {
		const tools = await conn.listTools();
		const findings: Finding[] = [...checkToolSchemas(tools)];

		const conformance = await checkConformance(conn);
		findings.push(...conformance.findings);

		let fuzz: BehavioralReport["fuzz"] = null;
		if (options.fuzz !== false && tools.length > 0 && !conn.closed) {
			const fuzzOptions = typeof options.fuzz === "object" ? options.fuzz : {};
			const result = await fuzzTools(conn, tools, fuzzOptions);
			findings.push(...result.findings);
			fuzz = result.stats;
		}

		const info = conn.serverInfo;
		return {
			target: bareTarget,
			server: info ? { name: info.name, version: info.version } : null,
			toolCount: tools.length,
			tools: tools.map((t) => ({
				name: typeof t.name === "string" ? t.name : "(unnamed)",
				description: typeof t.description === "string" ? t.description : "",
			})),
			listChanged: conformance.listChanged,
			findings,
			scores: scoreAllDimensions(findings),
			fuzz,
			durationMs: Date.now() - started,
		};
	} finally {
		await conn.close().catch(() => {});
	}
}

export type { BehavioralReport, Finding };
