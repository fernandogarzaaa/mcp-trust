# Changelog

All notable changes to mcp-trust are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `trustscan pin <server>[@<version>]`: resolve the verified install from the
  public trust index. Prints the exact `npm install -g` command, the
  registry integrity hash, and the badge summary. Refuses revoked versions;
  warns on superseded ones.
- `trustscan install <server>[@<version>] [--dry-run]`: install the verified
  version after showing its badge. `--dry-run` previews without installing.
- `trustscan revoke --server <s> --version <v> --reason <r> --key <keyfile>`:
  sign a badge revocation with the project maintainer key (submits as
  `revocations/<server>/<version>.json` via PR).
- `trustscan verify` now checks the badge's index status
  (active / superseded / revoked) unless `--offline` is passed. Revoked
  badges exit 2 with the revocation reason.
- Badges record the exact installable `artifact`
  (`{ type: "npm" | "git" | "local", spec, integrity? }`) so pins are
  reproducible.

### Changed
- The public trust index derives a per-badge status and shows it on the
  site and in the machine-readable manifest.

## [0.1.0] - 2026-10-03

Initial release.

### Added
- `trustscan scan <target>`: static heuristics (tool capabilities, the
  lethal-trifecta shape, tool-description poisoning, secrets/egress/exec
  patterns, `npm audit`) plus behavioral evals (schema, conformance, and
  seeded fuzz oracles) against a live server.
- `trustscan keygen`, `trustscan verify`, `trustscan publish`: Ed25519
  key management, self-contained badge verification, and badge submission
  to the public trust index via pull request.
- Risk scoring: every finding deducts from 100 on one documented schedule
  (critical 25 / major 12 / minor 4 / info 1); any critical finding forces
  the `critical` level.
- CI gating: `--fail-on` exits 2 when the risk level reaches the threshold.
