/** mcp-trust public API (also usable as a library). */
export { evaluateMcpServer } from "./behavioral/index.js";
export { runStaticPass } from "./static/index.js";
export { assembleReport, renderHumanSummary } from "./report.js";
export { keygen, signBadge, verifyBadge } from "./sign.js";
export {
	INDEX_REPO,
	publishBadge,
	sanitizeSegment,
	badgeTargetPath,
} from "./publish.js";
export { resolveTarget } from "./resolve.js";
