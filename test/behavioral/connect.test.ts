import { describe, expect, it } from "vitest";
import { connectMcpServer } from "../../src/behavioral/mcpConnection.js";

describe("connectMcpServer", () => {
	it("fails fast when the target never answers initialize", async () => {
		const started = Date.now();
		await expect(
			connectMcpServer('node -e "setInterval(() => {}, 1000)"', {
				connectTimeoutMs: 500,
			}),
		).rejects.toThrow(/timed out/i);
		expect(Date.now() - started).toBeLessThan(10_000);
	});

	it("includes the server's stderr when the handshake fails", async () => {
		await expect(
			connectMcpServer(
				"node -e \"console.error('usage: needs a directory'); setInterval(() => {}, 1000)\"",
				{ connectTimeoutMs: 1_000 },
			),
		).rejects.toThrow(/usage: needs a directory/);
	});
});
