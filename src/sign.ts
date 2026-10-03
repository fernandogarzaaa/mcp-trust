/**
 * Ed25519 signing for trust badges. Real cryptography via node:crypto,
 * no stubs.
 *
 * A badge binds a scan result to a version pin and a signer:
 *
 *   { type, server, version, riskScore, riskLevel, scores, findingCounts,
 *     evalHash, keyId, publicKey, issuedAt, signature }
 *
 * - evalHash is the SHA-256 of the canonical JSON of the scored content
 *   (findings + dimension scores), so any tampering with the scores or the
 *   finding list invalidates the badge.
 * - signature is Ed25519 over the canonical JSON of the badge minus the
 *   signature field.
 * - The badge embeds the signer's public key, so `trustscan verify` needs
 *   no key management: anyone can check the math. Trust in the *signer*
 *   (keyId) is out of band, like a PGP key id.
 */

import {
	createHash,
	createPrivateKey,
	createPublicKey,
	sign as cryptoSign,
	verify as cryptoVerify,
	generateKeyPairSync,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { TrustReport } from "./report.js";

export const BADGE_TYPE = "mcp-trust-badge/v1";

export interface TrustBadge {
	readonly type: typeof BADGE_TYPE;
	readonly server: string;
	readonly version: string;
	readonly riskScore: number;
	readonly riskLevel: string;
	/** Behavioral dimension scores, or null when the behavioral pass was skipped. */
	readonly scores: Readonly<Record<string, number>> | null;
	readonly findingCounts: {
		critical: number;
		major: number;
		minor: number;
		info: number;
	};
	/** SHA-256 of the canonical scored content. */
	readonly evalHash: string;
	readonly keyId: string;
	/** Embedded Ed25519 public key (JWK) so verification is self-contained. */
	readonly publicKey: Record<string, unknown>;
	readonly issuedAt: string;
	readonly signature: string;
}

export interface VerifyResult {
	readonly ok: boolean;
	readonly reason: string;
}

/** Canonical JSON: object keys sorted recursively, no whitespace. */
export function canonicalize(value: unknown): string {
	if (Array.isArray(value)) {
		return `[${value.map((v) => canonicalize(v)).join(",")}]`;
	}
	if (value !== null && typeof value === "object") {
		const entries = Object.entries(value as Record<string, unknown>)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`);
		return `{${entries.join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

export function sha256Hex(data: string): string {
	return createHash("sha256").update(data, "utf8").digest("hex");
}

export interface KeyPair {
	/** First 16 hex chars of SHA-256 over the canonical public JWK. */
	readonly keyId: string;
	readonly publicJwk: Record<string, unknown>;
	readonly privateJwk: Record<string, unknown>;
}

export function generateKeyPair(): KeyPair {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Record<
		string,
		unknown
	>;
	const privateJwk = privateKey.export({ format: "jwk" }) as unknown as Record<
		string,
		unknown
	>;
	const keyId = sha256Hex(canonicalize(publicJwk)).slice(0, 16);
	return { keyId, publicJwk, privateJwk };
}

export function defaultKeyDir(): string {
	return join(homedir(), ".config", "mcp-trust");
}

export function defaultPrivateKeyPath(): string {
	return join(defaultKeyDir(), "key.priv.json");
}

export function defaultPublicKeyPath(): string {
	return join(defaultKeyDir(), "key.pub.json");
}

/**
 * Generate a keypair and store it. The private key file is written with
 * mode 0600. Returns the key id and the public key path.
 */
export function keygen(outDir?: string): {
	keyId: string;
	privatePath: string;
	publicPath: string;
} {
	const dir = outDir ?? defaultKeyDir();
	mkdirSync(dir, { recursive: true });
	const { keyId, publicJwk, privateJwk } = generateKeyPair();
	const privatePath = outDir
		? join(dir, "key.priv.json")
		: defaultPrivateKeyPath();
	const publicPath = outDir
		? join(dir, "key.pub.json")
		: defaultPublicKeyPath();
	writeFileSync(
		privatePath,
		JSON.stringify({ keyId, privateKey: privateJwk }, null, 2),
		{
			mode: 0o600,
		},
	);
	writeFileSync(
		publicPath,
		JSON.stringify({ keyId, publicKey: publicJwk }, null, 2),
	);
	return { keyId, privatePath, publicPath };
}

interface StoredPrivateKey {
	keyId: string;
	privateKey: Record<string, unknown>;
}

function loadPrivateKeyFile(path: string): StoredPrivateKey {
	if (!existsSync(path)) {
		throw new Error(
			`no private key at ${path}: run "trustscan keygen" first, or pass --key <path>`,
		);
	}
	const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
	if (
		!parsed ||
		typeof parsed !== "object" ||
		typeof (parsed as { keyId?: unknown }).keyId !== "string" ||
		!(parsed as { privateKey?: unknown }).privateKey ||
		typeof (parsed as { privateKey?: unknown }).privateKey !== "object"
	) {
		throw new Error(`private key file at ${path} is not a trustscan key file`);
	}
	return parsed as StoredPrivateKey;
}

/** The content the evalHash commits to: findings plus dimension scores. */
function scoredContent(report: TrustReport): unknown {
	const staticFindings = [...report.static.findings]
		.map((f) => ({
			id: f.id,
			severity: f.severity,
			category: f.category,
			tool: f.tool ?? null,
			file: f.file ?? null,
			title: f.title,
			evidence: [...f.evidence],
		}))
		.sort((a, b) => (a.id < b.id ? -1 : 1));
	const behavioralFindings = report.behavioral
		? [...report.behavioral.findings]
				.map((f) => ({
					id: f.id,
					severity: f.severity,
					category: f.category,
					tool: f.tool ?? null,
					title: f.title,
					evidence: [...f.evidence],
				}))
				.sort((a, b) => (a.id < b.id ? -1 : 1))
		: null;
	const scores = report.behavioral
		? Object.fromEntries(
				report.behavioral.scores.map((s) => [s.dimension, s.value]),
			)
		: null;
	return { staticFindings, behavioralFindings, scores };
}

/** Sign a trust report, producing a self-contained badge. */
export function signBadge(report: TrustReport, keyPath?: string): TrustBadge {
	const stored = loadPrivateKeyFile(keyPath ?? defaultPrivateKeyPath());
	const privateKey = createPrivateKey({
		key: stored.privateKey as never,
		format: "jwk",
	});
	const publicKey = createPublicKey(privateKey);
	const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Record<
		string,
		unknown
	>;

	const scores = report.behavioral
		? Object.fromEntries(
				report.behavioral.scores.map((s) => [s.dimension, s.value]),
			)
		: null;
	const badge: Omit<TrustBadge, "signature"> = {
		type: BADGE_TYPE,
		server: report.server?.name ?? report.static.packageName ?? report.target,
		version:
			report.server?.version ?? report.static.packageVersion ?? "unknown",
		riskScore: report.riskScore,
		riskLevel: report.riskLevel,
		scores,
		findingCounts: { ...report.counts },
		evalHash: sha256Hex(canonicalize(scoredContent(report))),
		keyId: stored.keyId,
		publicKey: publicJwk,
		issuedAt: new Date().toISOString(),
	};
	const signature = cryptoSign(
		null,
		Buffer.from(canonicalize(badge), "utf8"),
		privateKey,
	);
	return { ...badge, signature: signature.toString("base64") };
}

/** Verify a badge's evalHash and signature. Returns ok=false with a reason on any failure. */
export function verifyBadge(badge: TrustBadge): VerifyResult {
	if (!badge || badge.type !== BADGE_TYPE) {
		return { ok: false, reason: "not a mcp-trust badge (bad type field)" };
	}
	if (
		!badge.publicKey ||
		typeof badge.publicKey !== "object" ||
		typeof badge.signature !== "string"
	) {
		return {
			ok: false,
			reason: "badge is missing its public key or signature",
		};
	}
	let publicKey: ReturnType<typeof createPublicKey>;
	try {
		publicKey = createPublicKey({
			key: badge.publicKey as never,
			format: "jwk",
		});
	} catch (error) {
		return {
			ok: false,
			reason: `embedded public key is invalid: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	const { signature, ...unsigned } = badge;
	const expectedKeyId = sha256Hex(canonicalize(badge.publicKey)).slice(0, 16);
	if (badge.keyId !== expectedKeyId) {
		return {
			ok: false,
			reason: `keyId "${badge.keyId}" does not match the embedded public key (expected "${expectedKeyId}")`,
		};
	}
	let signatureOk = false;
	try {
		signatureOk = cryptoVerify(
			null,
			Buffer.from(canonicalize(unsigned), "utf8"),
			publicKey,
			Buffer.from(signature, "base64"),
		);
	} catch (error) {
		return {
			ok: false,
			reason: `signature check threw: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	if (!signatureOk) {
		return {
			ok: false,
			reason: "signature does not verify against the embedded public key",
		};
	}
	return {
		ok: true,
		reason: "signature valid; evalHash commits to the scored content",
	};
}

/** Recompute what the evalHash should be for a report (for cross-checking). */
export function evalHashForReport(report: TrustReport): string {
	return sha256Hex(canonicalize(scoredContent(report)));
}
