/**
 * Client for the public trust index manifest.
 *
 * The manifest lives at the index Pages site and is rebuilt by CI on every
 * merge. Each entry carries the badge's install artifact and its derived
 * status (active / superseded / revoked), so `sigil pin`, `install`,
 * and `verify` can resolve and gate on indexed trust without cloning the
 * index repo.
 */

export const INDEX_MANIFEST_URL =
	"https://fernandogarzaaa.github.io/sigil-index/index.json";

export type BadgeStatus = "active" | "superseded" | "revoked";

export interface ManifestArtifact {
	readonly type: "npm" | "git" | "local";
	readonly spec: string;
	readonly integrity?: string;
}

export interface ManifestBadge {
	readonly server: string;
	readonly version: string;
	readonly riskScore: number;
	readonly riskLevel: string;
	readonly scores: Readonly<Record<string, number>> | null;
	readonly findingCounts: {
		critical: number;
		major: number;
		minor: number;
		info: number;
	};
	readonly keyId: string;
	readonly issuedAt: string;
	readonly path: string;
	readonly artifact: ManifestArtifact | null;
	readonly status: BadgeStatus;
	readonly revocationReason?: string;
}

export interface IndexManifest {
	readonly generatedAt: string;
	readonly count: number;
	readonly badges: ManifestBadge[];
}

/** Numeric-aware version compare: 1.10.0 > 1.9.0. A pre-release
 * (extra non-numeric parts) sorts below the release: 1.0.0-alpha < 1.0.0.
 * Missing numeric parts count as 0, so 1.2 == 1.2.0. */
export function compareVersions(a: string, b: string): number {
	const pa = String(a).split(/[.-]/);
	const pb = String(b).split(/[.-]/);
	const n = Math.max(pa.length, pb.length);
	for (let i = 0; i < n; i++) {
		const xa = i < pa.length ? (pa[i] as string) : null;
		const xb = i < pb.length ? (pb[i] as string) : null;
		if (xa === null && xb === null) continue;
		// One side ran out of parts: a numeric part means "equal so far"
		// (1.2 == 1.2.0); a non-numeric part means a pre-release, which
		// sorts below the release.
		if (xa === null) return /^\d+$/.test(xb as string) ? 0 : 1;
		if (xb === null) return /^\d+$/.test(xa) ? 0 : -1;
		const na = /^\d+$/.test(xa) ? Number(xa) : null;
		const nb = /^\d+$/.test(xb) ? Number(xb) : null;
		if (na !== null && nb !== null) {
			if (na !== nb) return na - nb;
		} else if (xa !== xb) {
			return xa < xb ? -1 : 1;
		}
	}
	return 0;
}

export class ManifestFetchError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ManifestFetchError";
	}
}

/** Fetch and minimally validate the index manifest. */
export async function fetchManifest(
	url: string = INDEX_MANIFEST_URL,
	timeoutMs = 15_000,
): Promise<IndexManifest> {
	let res: Response;
	try {
		res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
	} catch (error) {
		throw new ManifestFetchError(
			`could not reach the trust index at ${url}: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
	if (!res.ok) {
		throw new ManifestFetchError(
			`trust index returned HTTP ${res.status} for ${url}`,
		);
	}
	let parsed: unknown;
	try {
		parsed = await res.json();
	} catch (error) {
		throw new ManifestFetchError(
			`trust index at ${url} did not return valid JSON: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
	if (
		!parsed ||
		typeof parsed !== "object" ||
		!Array.isArray((parsed as { badges?: unknown }).badges)
	) {
		throw new ManifestFetchError(
			`trust index at ${url} is not a valid manifest (missing badges array)`,
		);
	}
	return parsed as IndexManifest;
}

export interface PinResolution {
	readonly badge: ManifestBadge;
	/** True when the user asked for an older version explicitly. */
	readonly explicitVersion: boolean;
}

/**
 * Resolve a server[@version] against the manifest. Without a version,
 * picks the newest active (non-revoked) version. Throws when the server
 * is unknown, the version is unknown, or every version is revoked.
 */
export function resolvePin(
	manifest: IndexManifest,
	server: string,
	version?: string,
): PinResolution {
	const matches = manifest.badges.filter((b) => b.server === server);
	if (matches.length === 0) {
		const known = [...new Set(manifest.badges.map((b) => b.server))].sort();
		const hint =
			known.length > 0
				? ` (indexed servers include: ${known.slice(0, 8).join(", ")}${known.length > 8 ? ", ..." : ""})`
				: "";
		throw new ManifestFetchError(`server "${server}" is not indexed${hint}`);
	}
	if (version !== undefined) {
		const exact = matches.find((b) => b.version === version);
		if (!exact) {
			const available = matches
				.map((b) => b.version)
				.sort(compareVersions)
				.join(", ");
			throw new ManifestFetchError(
				`version "${version}" of "${server}" is not indexed (available: ${available})`,
			);
		}
		if (exact.status === "revoked") {
			const reason = exact.revocationReason
				? `: ${exact.revocationReason}`
				: "";
			throw new ManifestFetchError(
				`${server}@${version} is REVOKED and must not be installed${reason}`,
			);
		}
		return { badge: exact, explicitVersion: true };
	}
	const active = matches
		.filter((b) => b.status !== "revoked")
		.sort((a, b) => compareVersions(b.version, a.version));
	if (active.length === 0) {
		throw new ManifestFetchError(
			`every indexed version of "${server}" is revoked; nothing safe to pin`,
		);
	}
	return { badge: active[0] as ManifestBadge, explicitVersion: false };
}

/** The exact install command for a resolved badge. Throws for non-npm artifacts. */
export function installCommandFor(badge: ManifestBadge): string {
	const artifact = badge.artifact;
	if (!artifact || artifact.type !== "npm") {
		throw new ManifestFetchError(
			`pin/install needs an npm artifact; ${badge.server}@${badge.version} records ${artifact ? `type "${artifact.type}"` : "no artifact"}`,
		);
	}
	return `npm install -g "${artifact.spec}"`;
}
