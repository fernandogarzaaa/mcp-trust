import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
	CallToolRequestSchema,
	ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import {
	connectMcpInProcess,
	evaluateMcpServer,
} from "../../src/behavioral/index.js";

/** In-process fixture server: one good tool, one undescribed, one sloppy. */
function buildFixtureServer(): Server {
	const server = new Server(
		{ name: "oracle-fixture", version: "0.0.1" },
		{ capabilities: { tools: {} } },
	);
	const tools = [
		{
			name: "good_tool",
			description: "A well-described tool that validates its input properly.",
			inputSchema: {
				type: "object",
				properties: { name: { type: "string", description: "Who to greet." } },
				required: ["name"],
			},
			annotations: { readOnlyHint: true },
		},
		{
			name: "mystery_tool",
			inputSchema: { type: "object", properties: {} },
		},
		{
			name: "sloppy_tool",
			description: "Accepts anything and never complains.",
			inputSchema: {
				type: "object",
				properties: { count: { type: "integer", description: "How many." } },
				required: ["count"],
			},
		},
	];
	server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
	server.setRequestHandler(CallToolRequestSchema, async (request) => {
		const { name, arguments: args } = request.params;
		if (name === "good_tool") {
			if (typeof (args as Record<string, unknown>)?.name !== "string") {
				throw new Error("invalid params: name must be a string");
			}
			return { content: [{ type: "text", text: "hello" }] };
		}
		if (name === "mystery_tool" || name === "sloppy_tool") {
			return { content: [{ type: "text", text: "fine, whatever" }] };
		}
		throw new Error(`unknown tool: ${name}`);
	});
	return server;
}

describe("behavioral oracles (in-process fixture)", () => {
	it("runs schema, conformance, and fuzz oracles against a live server", async () => {
		const report = await evaluateMcpServer("fixture", {
			connector: () => connectMcpInProcess(buildFixtureServer()),
			fuzz: { perTool: 3, timeoutMs: 2000, seed: 7 },
		});

		expect(report.server).toEqual({ name: "oracle-fixture", version: "0.0.1" });
		expect(report.toolCount).toBe(3);
		expect(report.scores).toHaveLength(3);
		expect(report.scores.map((s) => s.dimension).sort()).toEqual(
			["mcp.conformance", "mcp.robustness", "mcp.schemaQuality"].sort(),
		);

		const titles = report.findings.map((f) => f.title);
		expect(
			titles.some(
				(t) => t.includes("mystery_tool") && t.includes("no description"),
			),
		).toBe(true);

		expect(report.fuzz).not.toBeNull();
		expect(report.fuzz!.calls).toBeGreaterThan(0);
		expect(report.fuzz!.toolsFuzzed).toBe(3);
	}, 30_000);

	it("flags a tool that accepts clearly-invalid arguments", async () => {
		const report = await evaluateMcpServer("fixture", {
			connector: () => connectMcpInProcess(buildFixtureServer()),
			fuzz: { perTool: 6, timeoutMs: 2000, seed: 7 },
		});
		const titles = report.findings.map((f) => f.title);
		expect(
			titles.some(
				(t) =>
					t.includes("sloppy_tool") && t.includes("accepted clearly-invalid"),
			),
		).toBe(true);
	}, 30_000);

	it("does not flag the validating tool for accepting invalid input", async () => {
		const report = await evaluateMcpServer("fixture", {
			connector: () => connectMcpInProcess(buildFixtureServer()),
			fuzz: { perTool: 6, timeoutMs: 2000, seed: 7 },
		});
		const titles = report.findings.map((f) => f.title);
		expect(
			titles.some(
				(t) =>
					t.includes("good_tool") && t.includes("accepted clearly-invalid"),
			),
		).toBe(false);
	}, 30_000);
});
