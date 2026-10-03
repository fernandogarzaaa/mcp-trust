#!/usr/bin/env node
/**
 * trustscan: the mcp-trust CLI.
 *
 * Commands:
 *   trustscan scan <target> [options]   scan an MCP server
 *   trustscan keygen [--out <dir>]       generate an Ed25519 signing key
 *   trustscan verify <badge.json>        verify a signed trust badge
 *
 * Exit codes: 0 = scan passed the risk gate; 2 = risk at or above --fail-on;
 * 1 = operational error (bad args, unresolvable target, IO failure).
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateMcpServer } from "./behavioral/index.js";
import {
	RISK_LEVELS,
	type RiskLevel,
	assembleReport,
	renderHumanSummary,
} from "./report.js";
import { type TargetKind, classifyTarget, resolveTarget } from "./resolve.js";
import { type TrustBadge, keygen, signBadge, verifyBadge } from "./sign.js";
import { readManifest } from "./static/index.js";
import { runStaticPass } from "./static/index.js";

function packageVersion(): string {
	try {
		const here = dirname(fileURLToPath(import.meta.url));
		const pkg = JSON.parse(
			readFileSync(join(here, "..", "package.json"), "utf8"),
		) as {
			version?: string;
		};
		return typeof pkg.version === "string" ? pkg.version : "0.0.0";
	} catch {
		return "0.0.0";
	}
}

const VERSION = packageVersion();

function printHelp(): void {
	console.log(`trustscan ${VERSION}: trust scanning for MCP servers.

Usage:
  trustscan scan <target> [options]   Scan an MCP server.
    <target> is a local directory, an npm package spec (name[@version]),
    or a git URL (https://..., git@..., or owner/repo).
    --json            print the full JSON report instead of the summary
    --sign            sign a trust badge with your key (see keygen)
    --key <path>      private key file for --sign
    --badge-out <path>  write the badge JSON to a file (implies --sign)
    --fail-on <level> exit 2 when the risk level reaches this (default: high)
                      levels: low, medium, high, critical
    --no-fuzz         skip the fuzz oracle in the behavioral pass
    --skip-audit      skip the npm audit in the static pass
    --timeout <ms>    per-call timeout for the behavioral pass (default 5000)

  trustscan keygen [--out <dir>]      Generate an Ed25519 signing key.
  trustscan verify <badge.json>      Verify a signed trust badge.

Exit codes: 0 passed the gate, 2 risk at/above --fail-on, 1 operational error.

A passing scan is not a guarantee: static checks are heuristics with false
positives, and the behavioral pass only exercises what it can reach.`);
}

interface ScanOptions {
	json: boolean;
	sign: boolean;
	keyPath?: string;
	badgeOut?: string;
	failOn: RiskLevel;
	fuzz: boolean;
	skipAudit: boolean;
	timeoutMs: number;
}

function parseScanArgs(args: string[]): {
	target: string;
	options: ScanOptions;
} {
	const options: ScanOptions = {
		json: false,
		sign: false,
		failOn: "high",
		fuzz: true,
		skipAudit: false,
		timeoutMs: 5000,
	};
	let target: string | undefined;
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === undefined) continue;
		if (arg === "--json") options.json = true;
		else if (arg === "--sign") options.sign = true;
		else if (arg === "--key") {
			const value = args[++i];
			if (value === undefined) throw new Error("--key needs a path");
			options.keyPath = value;
		} else if (arg === "--badge-out") {
			options.badgeOut = args[++i];
			options.sign = true;
		} else if (arg === "--fail-on") {
			const level = args[++i] as RiskLevel | undefined;
			if (level === undefined) throw new Error("--fail-on needs a level");
			if (!RISK_LEVELS.includes(level)) {
				throw new Error(`--fail-on must be one of ${RISK_LEVELS.join(", ")}`);
			}
			options.failOn = level;
		} else if (arg === "--no-fuzz") options.fuzz = false;
		else if (arg === "--skip-audit") options.skipAudit = true;
		else if (arg === "--timeout") {
			const rawMs = args[++i];
			if (rawMs === undefined) throw new Error("--timeout needs a value");
			const ms = Number(rawMs);
			if (!Number.isFinite(ms) || ms <= 0)
				throw new Error("--timeout must be a positive number");
			options.timeoutMs = ms;
		} else if (arg.startsWith("--")) {
			throw new Error(`unknown flag ${arg}`);
		} else if (target === undefined) {
			target = arg;
		} else {
			throw new Error(`unexpected argument ${arg}`);
		}
	}
	if (target === undefined)
		throw new Error("scan needs a target: trustscan scan <target>");
	if (
		options.keyPath === undefined &&
		options.badgeOut === undefined &&
		options.sign
	) {
		// --sign without --key uses the default key location; fine.
	}
	return { target, options };
}

const LEVEL_RANK: Record<RiskLevel, number> = {
	low: 0,
	medium: 1,
	high: 2,
	critical: 3,
};

async function cmdScan(rawArgs: string[]): Promise<number> {
	const started = Date.now();
	const { target, options } = parseScanArgs(rawArgs);
	const kind: TargetKind = classifyTarget(target);

	const resolved = await resolveTarget(target);
	try {
		const manifest = readManifest(resolved.dir);

		// Behavioral pass: spawn the server entry over stdio. When the server
		// cannot be started, the scan continues with the static pass only and
		// says so in the report.
		let behavioral: Awaited<ReturnType<typeof evaluateMcpServer>> | null = null;
		let behavioralError: string | null = null;
		if (manifest.entry) {
			const stdioTarget = `node "${manifest.entry}"`;
			try {
				behavioral = await evaluateMcpServer(stdioTarget, {
					connect: { cwd: manifest.root },
					fuzz: options.fuzz ? { timeoutMs: options.timeoutMs } : false,
				});
			} catch (error) {
				behavioralError =
					error instanceof Error ? error.message : String(error);
			}
		} else {
			behavioralError =
				"no launchable server entry found (bin/main/conventional file)";
		}

		const staticReport = await runStaticPass(manifest.root, {
			runtimeTools: behavioral?.tools,
			skipAudit: options.skipAudit,
		});

		const report = assembleReport({
			toolVersion: VERSION,
			target,
			targetKind: kind,
			server:
				behavioral?.server ??
				(manifest.name
					? { name: manifest.name, version: manifest.version ?? "unknown" }
					: null),
			static: staticReport,
			behavioral,
			behavioralError,
			durationMs: Date.now() - started,
		});

		if (options.json) {
			console.log(JSON.stringify(report, null, 2));
		} else {
			process.stdout.write(renderHumanSummary(report));
		}

		if (options.sign || options.badgeOut) {
			const badge = signBadge(report, options.keyPath);
			const badgeJson = JSON.stringify(badge, null, 2);
			if (options.badgeOut) {
				writeFileSync(resolve(options.badgeOut), `${badgeJson}\n`);
				if (!options.json)
					console.log(`badge written to ${resolve(options.badgeOut)}`);
			} else {
				console.log(badgeJson);
			}
		}

		const levelRank = LEVEL_RANK[report.riskLevel] ?? 0;
		const failRank = LEVEL_RANK[options.failOn] ?? 0;
		return levelRank >= failRank ? 2 : 0;
	} finally {
		resolved.cleanup();
	}
}

function cmdKeygen(rawArgs: string[]): number {
	let out: string | undefined;
	for (let i = 0; i < rawArgs.length; i++) {
		if (rawArgs[i] === "--out") {
			out = rawArgs[++i];
			if (out === undefined) throw new Error("--out needs a directory");
		} else throw new Error(`unknown flag ${rawArgs[i]}`);
	}
	const { keyId, privatePath, publicPath } = keygen(out);
	console.log(`key id: ${keyId}`);
	console.log(`private key: ${privatePath} (mode 0600: keep it secret)`);
	console.log(`public key:  ${publicPath}`);
	return 0;
}

function cmdVerify(rawArgs: string[]): number {
	if (rawArgs.length !== 1 || !rawArgs[0]) {
		throw new Error("verify needs a badge file: trustscan verify <badge.json>");
	}
	const badge = JSON.parse(
		readFileSync(resolve(rawArgs[0]), "utf8"),
	) as TrustBadge;
	const result = verifyBadge(badge);
	if (result.ok) {
		console.log(
			`valid badge: ${badge.server}@${badge.version} risk ${badge.riskScore}/100 (${badge.riskLevel}), key ${badge.keyId}`,
		);
		return 0;
	}
	console.error(`invalid badge: ${result.reason}`);
	return 1;
}

async function main(): Promise<number> {
	const [, , command, ...rest] = process.argv;
	try {
		switch (command) {
			case "scan":
				return await cmdScan(rest);
			case "keygen":
				return cmdKeygen(rest);
			case "verify":
				return cmdVerify(rest);
			case "--help":
			case "-h":
			case undefined:
				printHelp();
				return 0;
			case "--version":
			case "-v":
				console.log(VERSION);
				return 0;
			default:
				console.error(`unknown command "${command}"`);
				printHelp();
				return 1;
		}
	} catch (error) {
		console.error(
			`trustscan: ${error instanceof Error ? error.message : String(error)}`,
		);
		return 1;
	}
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
	main().then(
		(code) => process.exit(code),
		(error) => {
			console.error(
				`trustscan: ${error instanceof Error ? error.message : String(error)}`,
			);
			process.exit(1);
		},
	);
}
