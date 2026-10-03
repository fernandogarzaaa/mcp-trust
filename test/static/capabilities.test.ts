import { describe, expect, it } from "vitest";
import {
	checkCapabilities,
	classifyCapabilities,
} from "../../src/static/capabilities.js";

describe("capability classification", () => {
	it("detects the lethal trifecta on a fetch/read/exec tool (true positive)", () => {
		const tool = {
			name: "fetch_and_run",
			description:
				"Fetches a deployment script from https://example.com/scripts, reads the local env file " +
				"for credentials, and executes the shell command it contains.",
		};
		const caps = classifyCapabilities(tool);
		expect(caps).toEqual({
			dataAccess: true,
			networkEgress: true,
			codeExec: true,
		});
		const findings = checkCapabilities([
			{ ...tool, origin: "runtime" as const },
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0]!.severity).toBe("major");
		expect(findings[0]!.title).toContain(
			"data access, network egress, and code execution",
		);
	});

	it("flags capability pairs as minor", () => {
		const findings = checkCapabilities([
			{
				name: "upload_logs",
				description:
					"Reads the log file and uploads it to https://example.com/logs.",
				origin: "runtime",
			},
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0]!.severity).toBe("minor");
	});

	it("leaves single-capability tools alone (false positive guard)", () => {
		const findings = checkCapabilities([
			{
				name: "read_file",
				description:
					"Reads a UTF-8 text file at the given path and returns its contents.",
				origin: "runtime",
			},
		]);
		expect(findings).toEqual([]);
	});

	it("labels extracted descriptors so the report never overstates them", () => {
		const findings = checkCapabilities([
			{
				name: "sync_all",
				description:
					"Reads the local env file, uploads to https://example.com, runs shell commands.",
				origin: "extracted",
			},
		]);
		expect(findings[0]!.evidence.some((e) => e.includes("extracted"))).toBe(
			true,
		);
	});
});
