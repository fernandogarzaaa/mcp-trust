# Known limitations (from seeding the index with 21 real MCP servers)

Learned by scanning real published MCP servers and fixing the worst false
positives. Updated 2026-10-04.

## Fixed during v1 seeding

- Test files are no longer scanned. Fixtures and dummy credentials in
  `test/`, `tests/`, `__tests__/`, and `*.test.*` files caused false
  positives (e.g. example secrets in test fixtures).
- The "environment values flow toward a network call" heuristic is now
  minor, not major. Nearly every real API-client server reads keys from
  `process.env` and makes network calls; flagging that shape as major
  punished legitimate code.
- npm targets now get `npm install --omit=dev --ignore-scripts
  --legacy-peer-deps` before the behavioral pass. Without it, packed
  servers always failed to start (missing dependencies) and every npm
  badge degraded to static-only.

## Still open

- Servers that need credentials or CLI arguments cannot complete the
  behavioral pass. The badge records `scores: null` and the report says
  why. This is honest but means many real-world badges are static-only.
- The static heuristics are regex-based. They flag suspicious shapes, not
  proven vulnerabilities. A clean scan is not a guarantee; a flagged
  finding still needs a human to read the code.
- `npm audit` only sees the published dependency tree, not transitive
  risk in bundled code.
- Badge identity is the npm package name plus version. A malicious
  package with a confusingly similar name gets its own badge; the index
  does not do typosquat detection.
- The index trusts the project key absolutely. If the private key is
  compromised, an attacker can sign badges and revocations. Key rotation
  is not yet implemented.
