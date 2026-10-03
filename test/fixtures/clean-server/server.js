/**
 * Clean fixture MCP server for trustscan tests. Well-behaved on purpose:
 * described tools, valid schemas, honest annotations, input validation,
 * no secrets, no network calls. Expect a passing scan.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
	CallToolRequestSchema,
	ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
	{ name: "clean-server", version: "0.1.0" },
	{ capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
	tools: [
		{
			name: "get_time",
			description:
				"Returns the current server time as an ISO-8601 string. Takes no meaningful input; the format argument is accepted for compatibility.",
			inputSchema: {
				type: "object",
				properties: {
					format: {
						type: "string",
						description: "Reserved for compatibility; ignored.",
					},
				},
				required: [],
			},
			annotations: { readOnlyHint: true },
		},
	],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
	const { name } = request.params;
	if (name === "get_time") {
		return { content: [{ type: "text", text: new Date().toISOString() }] };
	}
	throw new Error(`unknown tool: ${name}`);
});

const transport = new StdioServerTransport();
await server.connect(transport);
