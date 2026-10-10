import { describe, expect, it } from "vitest";
import { pickServerBin } from "../../src/static/manifest.js";

describe("pickServerBin", () => {
	it("prefers the MCP launcher over a CLI listed first", () => {
		expect(
			pickServerBin({
				godmode: "./bin/godmode.js",
				"godmode-mcp": "./bin/godmode-mcp.js",
			}),
		).toEqual({ name: "godmode-mcp", path: "./bin/godmode-mcp.js" });
	});

	it("falls back to a server-named bin, then the first entry", () => {
		expect(
			pickServerBin({ tool: "./cli.js", "tool-server": "./server.js" })?.path,
		).toBe("./server.js");
		expect(pickServerBin({ a: "./a.js", b: "./b.js" })?.path).toBe("./a.js");
	});

	it("ignores non-string entries and returns null when none remain", () => {
		expect(pickServerBin({ a: 1, b: "" })).toBeNull();
	});
});
