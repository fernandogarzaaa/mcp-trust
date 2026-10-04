import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const cli = join(repoRoot, "dist", "cli.js");

interface RunResult {
	code: number;
	stdout: string;
	stderr: string;
}

async function runNode(script: string, args: string[]): Promise<RunResult> {
	try {
		const { stdout, stderr } = await execFileAsync("node", [script, ...args], {
			timeout: 60_000,
			env: { ...process.env, NO_COLOR: "1" },
		});
		return { code: 0, stdout, stderr };
	} catch (error) {
		const err = error as { code?: number; stdout?: string; stderr?: string };
		return {
			code: err.code ?? 1,
			stdout: String(err.stdout ?? ""),
			stderr: String(err.stderr ?? ""),
		};
	}
}

describe("cli entrypoint", () => {
	it("starts when invoked directly", async () => {
		if (!existsSync(cli)) {
			throw new Error(`dist/cli.js not found: run "npm run build" first`);
		}
		const result = await runNode(cli, ["--help"]);
		expect(result.code).toBe(0);
		expect(result.stdout).toContain("sigil");
	});

	it("starts when invoked through a symlink (npm .bin layout)", async () => {
		if (!existsSync(cli)) {
			throw new Error(`dist/cli.js not found: run "npm run build" first`);
		}
		// npm installs bins as symlinks in node_modules/.bin; argv[1] is the
		// unresolved link path while import.meta.url is the real path. The
		// entrypoint must still start. Regression test: a strict
		// argv[1] === import.meta.url comparison silently exits 0 here.
		const dir = mkdtempSync(join(tmpdir(), "sigil-bin-"));
		const link = join(dir, "sigil");
		symlinkSync(cli, link);
		const result = await runNode(link, ["--help"]);
		expect(result.code).toBe(0);
		expect(result.stdout).toContain("sigil");
	});
});
