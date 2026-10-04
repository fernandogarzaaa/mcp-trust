/**
 * MCP client connector: the transport layer for evaluating MCP servers.
 *
 * Adapted from EVE's src/surface/mcpClient.ts. This module uses the official
 * SDK's client half to connect to a *target* server. Two transports:
 *
 * - stdio (`node server.js --flag`): the target is spawned as a subprocess,
 *   exactly how MCP hosts launch servers.
 * - Streamable HTTP (`http://` / `https://` URLs): for already-running servers.
 *
 * TRUST BOUNDARY: a non-HTTP target SPAWNS A LOCAL PROCESS with the
 * caller's environment. Only scan targets you have decided to run; the
 * scanner itself is the thing that executes the server under evaluation.
 * Tokenization never uses a shell; stderr is inherited so a crashing target
 * stays debuggable.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
	type CallToolResult,
	CallToolResultSchema,
	type Implementation,
	McpError,
	type ServerCapabilities,
	type Tool,
	ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";

/** How a tool call ended, flattened to what an operator could perceive. */
export interface McpCallOutcome {
	/** The server answered with a tool-level error result (`isError: true`). */
	readonly isError: boolean;
	/** Concatenated text content: what a user of the tool would read. */
	readonly text: string;
	/** Structured content, when the tool returned any. */
	readonly structured?: unknown;
}

/**
 * A live connection to the MCP server under evaluation. Narrow on purpose:
 * oracles need tools/list, tools/call, ping and close. Nothing else.
 */
export interface McpConnection {
	/** The target string the connection was opened for (for reporting). */
	readonly target: string;
	/** Server identity from the initialize handshake, once connected. */
	readonly serverInfo: Implementation | undefined;
	/** Capabilities the server declared at initialize. */
	readonly serverCapabilities: ServerCapabilities | undefined;
	/** True after the transport has closed (server exit, crash, kill). */
	readonly closed: boolean;
	listTools(): Promise<readonly Tool[]>;
	/**
	 * Call a tool. Tool-level failures come back as `isError` outcomes;
	 * protocol-level failures (invalid params, unknown method, timeout,
	 * connection loss) reject, and the oracles classify on that distinction.
	 */
	callTool(
		name: string,
		args: Record<string, unknown>,
		timeoutMs?: number,
	): Promise<McpCallOutcome>;
	/** Subscribe to `notifications/tools/list_changed`. */
	onToolsChanged(handler: () => void): void;
	ping(): Promise<void>;
	close(): Promise<void>;
}

/** A function that opens a connection to a target. Injectable for tests. */
export type McpConnector = (target: string) => Promise<McpConnection>;

const CLIENT_INFO: Implementation = {
	name: "sigil-evaluator",
	version: "0.1.0",
};
const DEFAULT_CALL_TIMEOUT_MS = 10_000;

/** Minimal shell-like tokenizer: honors single/double-quoted arguments. */
export function tokenizeCommand(command: string): string[] {
	const tokens: string[] = [];
	const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
	let match = pattern.exec(command);
	while (match !== null) {
		tokens.push(match[1] ?? match[2] ?? match[3] ?? "");
		match = pattern.exec(command);
	}
	return tokens;
}

/** {@link McpConnection} over the official SDK client. */
class SdkMcpConnection implements McpConnection {
	private readonly client: Client;
	private readonly connectPromise: Promise<void>;
	private isClosed = false;

	private constructor(
		readonly target: string,
		transport: Transport,
	) {
		this.client = new Client(CLIENT_INFO, { capabilities: {} });
		this.client.onclose = () => {
			this.isClosed = true;
		};
		this.connectPromise = this.client.connect(transport);
	}

	static async open(
		target: string,
		transport: Transport,
	): Promise<SdkMcpConnection> {
		const conn = new SdkMcpConnection(target, transport);
		await conn.connectPromise;
		return conn;
	}

	get serverInfo(): Implementation | undefined {
		return this.client.getServerVersion();
	}

	get serverCapabilities(): ServerCapabilities | undefined {
		return this.client.getServerCapabilities();
	}

	get closed(): boolean {
		return this.isClosed;
	}

	async listTools(): Promise<readonly Tool[]> {
		const result = await this.client.listTools();
		return result.tools;
	}

	async callTool(
		name: string,
		args: Record<string, unknown>,
		timeoutMs = DEFAULT_CALL_TIMEOUT_MS,
	): Promise<McpCallOutcome> {
		const result = await this.client.callTool(
			{ name, arguments: args },
			CallToolResultSchema,
			{
				timeout: timeoutMs,
			},
		);
		return flattenResult(result as CallToolResult);
	}

	onToolsChanged(handler: () => void): void {
		this.client.setNotificationHandler(
			ToolListChangedNotificationSchema,
			() => {
				handler();
			},
		);
	}

	async ping(): Promise<void> {
		await this.client.ping();
	}

	async close(): Promise<void> {
		try {
			await this.client.close();
		} finally {
			this.isClosed = true;
		}
	}
}

/** Reduce a tool result to what an operator could actually read. */
function flattenResult(result: CallToolResult): McpCallOutcome {
	const parts: string[] = [];
	for (const block of result.content ?? []) {
		if (block.type === "text") parts.push(block.text);
		else parts.push(`[${block.type} content]`);
	}
	const structured = (result as { structuredContent?: unknown })
		.structuredContent;
	return {
		isError: result.isError === true,
		text: parts.join("\n"),
		...(structured !== undefined ? { structured } : {}),
	};
}

export interface ConnectOptions {
	/** Working directory for a spawned stdio server. */
	cwd?: string;
	/** Environment for a spawned stdio server (defaults to process.env). */
	env?: Record<string, string>;
}

/**
 * Connect to an MCP server target.
 *
 * Target forms (after any `mcp:` scheme prefix has been stripped):
 * - `http://...` / `https://...` -> Streamable HTTP transport
 * - anything else -> a command line spawned over stdio
 */
export async function connectMcpServer(
	target: string,
	options: ConnectOptions = {},
): Promise<McpConnection> {
	if (/^https?:\/\//.test(target)) {
		return SdkMcpConnection.open(
			target,
			new StreamableHTTPClientTransport(new URL(target)),
		);
	}
	const [command, ...args] = tokenizeCommand(target);
	if (!command) throw new Error(`empty MCP target command in "${target}"`);
	return SdkMcpConnection.open(
		target,
		new StdioClientTransport({
			command,
			args,
			stderr: "inherit",
			cwd: options.cwd,
			env: options.env,
		}),
	);
}

/**
 * Connect to an MCP server running in the same process (an SDK `Server`
 * instance). Tests use this to evaluate fixture servers without spawning
 * anything.
 */
export async function connectMcpInProcess(
	server: Server,
	target = "in-process",
): Promise<McpConnection> {
	const [clientTransport, serverTransport] =
		InMemoryTransport.createLinkedPair();
	await server.connect(serverTransport);
	return SdkMcpConnection.open(target, clientTransport);
}

/** JSON-RPC error codes the evaluators classify on. */
export { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

/** Is this error the transport dying underneath a call (a server crash)? */
export function isConnectionClosedError(error: unknown): boolean {
	return (
		error instanceof McpError && error.message.includes("Connection closed")
	);
}

/** Is this error the client giving up on an unanswered request (a hang)? */
export function isTimeoutError(error: unknown): boolean {
	return error instanceof McpError && error.message.includes("timed out");
}
