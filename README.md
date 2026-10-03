# mcp-trust

[![ci](https://github.com/fernandogarzaaa/mcp-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/fernandogarzaaa/mcp-trust/actions/workflows/ci.yml)

Trust scanning for MCP servers: static heuristics plus behavioral evals, with signed version-pinned trust badges. The place you check before you install an MCP server.

Existing scanners audit code statically. mcp-trust adds what they do not: it **runs the server** (schema, conformance, and seeded fuzz oracles ported from [EVE](https://github.com/fernandogarzaaa/experience-validation-engine)'s mcp-eval harness) and publishes the result as a **signed, version-pinned badge** anyone can verify without key management.

## Install

Requires Node.js 20 or later.

> **Note:** `mcp-trust` is not published to npm yet. The commands below show the intended install path; until release, run from source.

```bash
npm install -g mcp-trust
# or run without installing
npx mcp-trust scan ./my-server
```

From source:

```bash
git clone https://github.com/fernandogarzaaa/mcp-trust.git
cd mcp-trust
npm install
npm run build
node dist/cli.js scan ./my-server
```

## Quickstart

Check a server before you install it, using the public trust index:

```bash
# See the verified install for a server (newest active version)
trustscan pin @modelcontextprotocol/server-filesystem
# Pin an exact version
trustscan pin @modelcontextprotocol/server-filesystem@2025.1.0
# Install the verified version (shows the badge first)
trustscan install @modelcontextprotocol/server-filesystem --dry-run
```

Scan a server yourself and publish the badge:

```bash
trustscan scan ./my-server --sign --badge-out my-server.trust.json
trustscan verify my-server.trust.json
trustscan publish --badge my-server.trust.json
```

## Usage

```bash
# Scan a local directory (also accepts an npm spec or git URL)
trustscan scan ./my-mcp-server
trustscan scan express-mcp-server@1.2.3
trustscan scan https://github.com/org/server.git

# CI gating: exit 2 when risk reaches the threshold (default: high)
trustscan scan ./my-mcp-server --fail-on high

# Full JSON report
trustscan scan ./my-mcp-server --json

# Sign a badge with your key (see keygen below)
trustscan keygen
trustscan scan ./my-mcp-server --sign --badge-out server.trust.json
trustscan verify server.trust.json

# Publish a badge to the public trust index (opens a pull request)
trustscan publish --badge server.trust.json
# or scan, sign, and publish in one step
trustscan scan ./my-mcp-server --sign --publish

# Resolve the verified install from the public index
trustscan pin my-server@1.2.3
trustscan pin my-server              # newest active (non-revoked) version
# Install the verified version (npm); shows the badge summary first
trustscan install my-server@1.2.3
trustscan install my-server --dry-run   # preview only

# Revoke a badge version (project maintainer key)
trustscan revoke --server my-server --version 1.2.3 \
  --reason "Signer key compromised" \
  --key ~/.config/mcp-trust/project/key.priv.json \
  --out revocation.json
# then open a PR adding revocations/my-server/1.2.3.json
```

Options for `scan`: `--json`, `--sign`, `--key <path>`, `--badge-out <path>`, `--publish`, `--fail-on <low|medium|high|critical>`, `--no-fuzz`, `--skip-audit`, `--timeout <ms>`.

`verify` also checks the badge against the public trust index (use `--offline` to skip): revoked badges exit 2 with the reason, superseded ones warn.

Exit codes: `0` passed the gate (or the command succeeded), `2` risk at or above `--fail-on` or a revoked badge on verify, `1` operational error.

## Trust Index

Badges are more useful in public. The [mcp-trust-index](https://github.com/fernandogarzaaa/mcp-trust-index) is a git-backed public registry of signed badges at `badges/<server>/<version>.json`, browsable at <https://fernandogarzaaa.github.io/mcp-trust-index/>.

`trustscan publish --badge <file>` verifies the badge locally first, then opens a pull request against the index (needs the GitHub CLI, `gh`, installed and authenticated). CI checks every submitted badge: JSON schema, Ed25519 signature against the embedded public key, correct `badges/<server>/<version>.json` placement, and no duplicate versions. The index is append-only per version: a new scan of a new version adds a new file.

Each badge carries a derived **status**: `active` (newest indexed version), `superseded` (an older version), or `revoked` (the project maintainer published a signed revocation at `revocations/<server>/<version>.json`). `trustscan pin` refuses revoked versions, and `trustscan verify` reports the status from the index.

A badge attests to the exact version scanned, nothing more. Trust in the signer (the key id) is out of band, like a PGP key id: the index proves a badge is intact and well-formed, not that its signer is honest.

## What it checks

**Static pass** (no execution):

- Tool capability classification, including the lethal-trifecta shape: one tool surface combining private-data access, network egress, and code execution.
- Tool-description poisoning patterns: instruction overrides ("ignore previous instructions"), system-prompt disclosure requests, exfiltration directives, jailbreak phrasing, embedded markdown links.
- Source heuristics: committed secrets (AWS keys, private key material), `eval`/`new Function`, shell commands built with interpolation, hardcoded remote URLs, env values flowing toward network calls.
- `npm audit` severity rollup over the dependency tree.
- Best-effort tool extraction from source when the server cannot be started.

**Behavioral pass** (spawns the server over stdio, or connects over HTTP):

- Schema oracle: malformed input schemas, missing/thin descriptions, annotation dishonesty (`delete_*` with `destructiveHint: false`).
- Conformance oracle: initialize handshake, capability declaration, ping, unknown-tool error behavior.
- Fuzz oracle: seeded adversarial inputs per tool (type violations, missing required fields, boundary values, oversized payload), classified as protocol error, error result, accepted, hang, or crash.

**Scoring**: every finding deducts from 100 on one schedule (critical 25, major 12, minor 4, info 1). Any critical finding forces a `critical` risk level; otherwise below 70 is `high`, below 90 is `medium`, the rest `low`.

**Badges**: Ed25519-signed JSON binding server, version pin, scores, finding counts, and a SHA-256 hash of the scored content. The badge embeds the signer's public key, so verification is self-contained. Trust in the signer (key id) is out of band, like a PGP key id.

## Example output

```
trustscan: fixture-server@0.1.0 [local]
risk score: 0/100 (critical)
findings: 16 total (1 critical, 6 major, 6 minor, 3 info)
static: 10 findings over 4 tool(s) [runtime]
behavioral: schemaQuality 79/100, robustness 92/100, conformance 100/100
fuzz: 8 calls over 4 tool(s): 0 protocol errors, 0 error results, 4 accepted-invalid, 0 hangs, 0 crashes

[critical] (server.js) Possible AWS access key committed in source (static)
    - server.js:23: const AWS_KEY = "AKIA...";
[major] [fetch_and_run] "fetch_and_run" combines data access, network egress, and code execution (static)
    - capabilities detected: data access, network egress, code execution
[major] [fetch_and_run] Instruction-override phrasing in tool description (static)
    - description of "fetch_and_run" matched: "Ignore previous instructions"
[major] [get_status] "get_status" has no description (behavioral)
    - tools/list entry for "get_status" carries no description
...
```

## Limitations (read before trusting a scan)

- **Static checks are heuristics with false positives.** A tool that reads files, calls the network, and runs commands may be a perfectly legitimate deploy tool. Findings are review prompts with quoted evidence, never verdicts.
- **A passing scan is not a guarantee.** The behavioral pass only exercises what it can reach over the protocol; it does not review business logic, and the fuzz oracle uses a small seeded case budget.
- **The scanner executes the target.** The behavioral pass spawns the server as a subprocess. Only scan code you have decided to run.
- **Dependency audit needs the network** and degrades to "unknown" when `npm audit` cannot run.
- **Eval scores attest to the scanned version only.** A badge is pinned to an exact version; a new release needs a new scan.

## Development

```bash
npm run build      # typecheck + emit to dist/
npm test           # vitest (build first: the e2e tests run dist/cli.js)
npm run lint       # biome check
```

## License

MIT. See [LICENSE](LICENSE).
