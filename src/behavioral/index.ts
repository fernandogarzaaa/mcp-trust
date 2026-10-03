/**
 * Behavioral pass: the public surface of the ported EVE mcp-eval harness.
 */
export { evaluateMcpServer, type EvaluateOptions } from "./evaluate.js";
export {
	connectMcpInProcess,
	connectMcpServer,
	type McpConnection,
} from "./mcpConnection.js";
export {
	DIMENSIONS,
	DIMENSION_FOR_CATEGORY,
	FINDING_CATEGORIES,
	type BehavioralReport,
	type Dimension,
	type DimensionScore,
	type Finding,
	type FindingCategory,
	type FuzzStats,
	type Severity,
} from "./types.js";
