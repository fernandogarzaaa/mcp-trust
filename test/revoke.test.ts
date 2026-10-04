import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { keygen, signRevocation, verifyRevocation } from "../src/sign.js";

function freshKey(): { privatePath: string; keyId: string } {
	const dir = mkdtempSync(join(tmpdir(), "revoke-test-"));
	const { keyId, privatePath } = keygen(dir);
	return { privatePath, keyId };
}

function publicKeyIdFor(privatePath: string): string {
	const pubPath = privatePath.replace("key.priv.json", "key.pub.json");
	const parsed = JSON.parse(readFileSync(pubPath, "utf8")) as {
		keyId: string;
	};
	return parsed.keyId;
}

describe("signRevocation / verifyRevocation", () => {
	it("round-trips a revocation", () => {
		const { privatePath } = freshKey();
		const rev = signRevocation({
			server: "demo-server",
			version: "1.2.3",
			reason: "Signer key compromised.",
			keyPath: privatePath,
		});
		expect(rev.type).toBe("sigil-revocation/v1");
		expect(rev.status).toBe("revoked");
		expect(rev.server).toBe("demo-server");
		const check = verifyRevocation(rev, rev.keyId);
		expect(check.ok).toBe(true);
	});

	it("rejects a revocation checked against the wrong project key", () => {
		const { privatePath } = freshKey();
		const other = freshKey();
		const rev = signRevocation({
			server: "demo-server",
			version: "1.2.3",
			reason: "x",
			keyPath: privatePath,
		});
		// Wrong expected key id.
		expect(verifyRevocation(rev, "0000000000000000").ok).toBe(false);
		// A different real key id also fails: the embedded key belongs to
		// the signing key, not the other one.
		const otherKeyId = publicKeyIdFor(other.privatePath);
		expect(otherKeyId).not.toBe(rev.keyId);
		expect(verifyRevocation(rev, otherKeyId).ok).toBe(false);
	});

	it("rejects a tampered revocation", () => {
		const { privatePath } = freshKey();
		const rev = signRevocation({
			server: "demo-server",
			version: "1.2.3",
			reason: "original reason",
			keyPath: privatePath,
		});
		const tampered = { ...rev, reason: "forged reason" };
		expect(verifyRevocation(tampered, rev.keyId).ok).toBe(false);
	});

	it("rejects empty fields", () => {
		const { privatePath } = freshKey();
		expect(() =>
			signRevocation({
				server: "",
				version: "1.0.0",
				reason: "x",
				keyPath: privatePath,
			}),
		).toThrow(/non-empty --server/);
		expect(() =>
			signRevocation({
				server: "s",
				version: "1.0.0",
				reason: "  ",
				keyPath: privatePath,
			}),
		).toThrow(/non-empty --reason/);
	});

	it("rejects a missing key file with a helpful error", () => {
		expect(() =>
			signRevocation({
				server: "s",
				version: "1.0.0",
				reason: "x",
				keyPath: "/nonexistent/key.json",
			}),
		).toThrow(/run "sigil keygen" first/);
	});
});
