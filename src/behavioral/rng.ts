/**
 * Deterministic pseudo-random number generation for the fuzz oracle.
 *
 * Ported from EVE's src/core/random.ts (mulberry32 + FNV-1a string seed).
 * Seeded fuzzing keeps every scan reproducible: the same seed selects the
 * same adversarial cases.
 */

export interface Rng {
	/** Uniform float in [0, 1). */
	next(): number;
}

/** mulberry32: small, fast, good-enough statistical quality for fuzzing. */
export function createRng(seed: number): Rng {
	let state = seed >>> 0;
	const next = (): number => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
	return { next };
}

/** Derive a numeric seed from an arbitrary string (FNV-1a). */
export function seedFromString(input: string): number {
	let hash = 0x811c9dc5;
	for (let i = 0; i < input.length; i++) {
		hash ^= input.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return hash >>> 0;
}
