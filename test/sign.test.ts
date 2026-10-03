import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { TrustReport } from "../src/report.js";
import {
	evalHashForReport,
	generateKeyPair,
	keygen,
	signBadge,
	verifyBadge,
} from "../src/sign.js";

function minimalReport(overrides: Partial<TrustReport> = {}): TrustReport {
	return {
		tool: "mcp-trust",
		toolVersion: "0.1.0",
		target: "fixture",
		targetKind: "local",
		server: { name: "fixture-server", version: "0.1.0" },
		riskScore: 62,
		riskLevel: "high",
		counts: { critical: 0, major: 2, minor: 3, info: 4 },
		static: {
			root: "/tmp/x",
			packageName: "fixture-server",
			packageVersion: "0.1.0",
			toolSource: "runtime",
			toolCount: 1,
			findings: [
				{
					id: "st-1",
					severity: "major",
					category: "static.poisoning",
					tool: "fetch_and_run",
					title: "Instruction-override phrasing in tool description",
					description: "d",
					evidence: ["e"],
				},
			],
			dependencies: {
				ran: false,
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0,
				info: 0,
			},
			durationMs: 1,
		},
		behavioral: null,
		behavioralError: null,
		durationMs: 2,
		...overrides,
	};
}

describe("Ed25519 badge signing", () => {
	it("round-trips: keygen, sign, verify", () => {
		const dir = mkdtempSync(join(tmpdir(), "trustscan-key-"));
		const { keyId, privatePath } = keygen(dir);
		expect(keyId).toMatch(/^[0-9a-f]{16}$/);

		const badge = signBadge(minimalReport(), privatePath);
		expect(badge.keyId).toBe(keyId);
		expect(badge.server).toBe("fixture-server");
		expect(badge.version).toBe("0.1.0");
		expect(badge.evalHash).toBe(evalHashForReport(minimalReport()));

		const result = verifyBadge(badge);
		expect(result.ok).toBe(true);
	});

	it("rejects a tampered badge", () => {
		const dir = mkdtempSync(join(tmpdir(), "trustscan-key-"));
		const { privatePath } = keygen(dir);
		const badge = signBadge(minimalReport(), privatePath);
		const tampered = { ...badge, riskScore: 100, riskLevel: "low" };
		expect(verifyBadge(tampered).ok).toBe(false);
	});

	it("rejects a badge whose keyId does not match the embedded key", () => {
		const dir = mkdtempSync(join(tmpdir(), "trustscan-key-"));
		const { privatePath } = keygen(dir);
		const badge = signBadge(minimalReport(), privatePath);
		const { keyId } = generateKeyPair();
		expect(verifyBadge({ ...badge, keyId }).ok).toBe(false);
	});

	it("rejects non-badge input", () => {
		expect(verifyBadge({} as never).ok).toBe(false);
		expect(verifyBadge(null as never).ok).toBe(false);
	});
});
