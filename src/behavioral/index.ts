/**
 * Behavioral pass: the public surface of the ported EVE mcp-eval harness.
 */
export { type EvaluateOptions, evaluateMcpServer } from "./evaluate.js";
export {
	connectMcpInProcess,
	connectMcpServer,
	type McpConnection,
} from "./mcpConnection.js";
export {
	type BehavioralReport,
	DIMENSION_FOR_CATEGORY,
	DIMENSIONS,
	type Dimension,
	type DimensionScore,
	FINDING_CATEGORIES,
	type Finding,
	type FindingCategory,
	type FuzzStats,
	type Severity,
} from "./types.js";
