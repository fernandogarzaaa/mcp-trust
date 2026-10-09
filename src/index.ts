/** Sigil public API (also usable as a library). */
export { evaluateMcpServer } from "./behavioral/index.js";
export {
	badgeTargetPath,
	INDEX_REPO,
	publishBadge,
	sanitizeSegment,
} from "./publish.js";
export { assembleReport, renderHumanSummary } from "./report.js";
export { resolveTarget } from "./resolve.js";
export { keygen, signBadge, verifyBadge } from "./sign.js";
export { runStaticPass } from "./static/index.js";
