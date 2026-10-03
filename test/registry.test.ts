import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	type IndexManifest,
	compareVersions,
	fetchManifest,
	installCommandFor,
	resolvePin,
} from "../src/registry.js";

function badge(
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	return {
		server: "demo-server",
		version: "1.0.0",
		riskScore: 92,
		riskLevel: "low",
		scores: null,
		findingCounts: { critical: 0, major: 0, minor: 1, info: 2 },
		keyId: "ab12cd34ef56ab78",
		issuedAt: "2026-10-04T00:00:00.000Z",
		path: "badges/demo-server/1.0.0.json",
		artifact: {
			type: "npm",
			spec: "demo-server@1.0.0",
			integrity: "sha512-abc",
		},
		status: "active",
		...overrides,
	};
}

function manifestWith(badges: Record<string, unknown>[]): IndexManifest {
	return {
		generatedAt: "2026-10-04T00:00:00.000Z",
		count: badges.length,
		badges: badges as never,
	};
}

describe("compareVersions", () => {
	it("orders numeric parts numerically", () => {
		expect(compareVersions("1.10.0", "1.9.0")).toBeGreaterThan(0);
		expect(compareVersions("1.9.0", "1.10.0")).toBeLessThan(0);
		expect(compareVersions("2.0.0", "1.99.99")).toBeGreaterThan(0);
	});
	it("treats equal versions as equal", () => {
		expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
	});
	it("handles different lengths and pre-release tags", () => {
		expect(compareVersions("1.2", "1.2.0")).toBe(0);
		expect(compareVersions("1.0.0-alpha", "1.0.0")).toBeLessThan(0);
		expect(compareVersions("1.0.0", "1.0.0-alpha")).toBeGreaterThan(0);
	});
});

describe("resolvePin", () => {
	const m = manifestWith([
		badge({ version: "1.0.0", status: "superseded" }),
		badge({ version: "1.1.0", status: "active" }),
		badge({
			version: "2.0.0",
			status: "revoked",
			revocationReason: "key compromised",
		}),
	]);

	it("resolves an explicit version", () => {
		const { badge: b, explicitVersion } = resolvePin(m, "demo-server", "1.0.0");
		expect(b.version).toBe("1.0.0");
		expect(explicitVersion).toBe(true);
	});

	it("picks the newest active version when no version is given", () => {
		const { badge: b, explicitVersion } = resolvePin(m, "demo-server");
		expect(b.version).toBe("1.1.0");
		expect(explicitVersion).toBe(false);
	});

	it("refuses a revoked version with its reason", () => {
		expect(() => resolvePin(m, "demo-server", "2.0.0")).toThrow(
			/REVOKED.*key compromised/,
		);
	});

	it("errors on an unknown server with a hint", () => {
		expect(() => resolvePin(m, "nope")).toThrow(/not indexed/);
	});

	it("errors on an unknown version listing what exists", () => {
		expect(() => resolvePin(m, "demo-server", "9.9.9")).toThrow(
			/not indexed.*available/,
		);
	});

	it("errors when every version is revoked", () => {
		const allRevoked = manifestWith([
			badge({ version: "1.0.0", status: "revoked" }),
		]);
		expect(() => resolvePin(allRevoked, "demo-server")).toThrow(
			/every indexed version.*revoked/,
		);
	});
});

describe("installCommandFor", () => {
	it("emits the npm install command for npm artifacts", () => {
		const b = badge() as never;
		expect(installCommandFor(b)).toBe('npm install -g "demo-server@1.0.0"');
	});
	it("refuses non-npm artifacts honestly", () => {
		const b = badge({ artifact: { type: "git", spec: "https://x/y.git" } });
		expect(() => installCommandFor(b as never)).toThrow(
			/needs an npm artifact/,
		);
	});
	it("refuses badges with no artifact", () => {
		const b = badge({ artifact: null });
		expect(() => installCommandFor(b as never)).toThrow(
			/needs an npm artifact/,
		);
	});
});

describe("fetchManifest", () => {
	let server: ReturnType<typeof createServer>;
	let url: string;
	const manifest = manifestWith([badge()]);

	beforeAll(async () => {
		server = createServer((req, res) => {
			if (req.url === "/index.json") {
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify(manifest));
			} else {
				res.writeHead(404);
				res.end();
			}
		});
		await new Promise<void>((resolve) =>
			server.listen(0, "127.0.0.1", resolve),
		);
		const addr = server.address() as AddressInfo;
		url = `http://127.0.0.1:${addr.port}/index.json`;
	});

	afterAll(async () => {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	});

	it("fetches and validates a manifest", async () => {
		const m = await fetchManifest(url);
		expect(m.badges).toHaveLength(1);
		expect(m.badges[0]?.server).toBe("demo-server");
	});

	it("rejects non-JSON", async () => {
		await expect(fetchManifest(`${url}-missing`)).rejects.toThrow(/HTTP 404/);
	});

	it("fails fast on unreachable hosts", async () => {
		await expect(
			fetchManifest("http://127.0.0.1:1/index.json", 500),
		).rejects.toThrow(/could not reach/);
	});
});
