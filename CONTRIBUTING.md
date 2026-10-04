# Contributing to Sigil

## Development

Requires Node.js 20 or later.

```bash
npm install
npm run build      # typecheck + emit to dist/
npm test           # vitest (build first: the e2e tests run dist/cli.js)
npm run lint       # biome check
```

## Ground rules

- **No stubs, no TODOs.** Every shipped code path is real and tested. If
  something cannot be fully verified, say so in the PR description.
- **Findings are review prompts, never verdicts.** Static heuristics have
  false positives by design; word them as such and always attach evidence.
- **No em dashes** in user-facing writing (README, CLI help and output).
- One PR per change, merged only on green CI. Never push to `main`
  directly.

## Tests

- Unit tests live next to what they cover under `test/`.
- Heuristic tests need both true-positive and false-positive fixtures.
- The e2e tests in `test/e2e/` run the built CLI in `dist/`, so build
  before testing.

## Badges and the trust index

- Badge format changes must stay backward compatible for verification:
  old badges (without newer optional fields) still verify.
- The index validator (`scripts/validate.mjs` in
  [sigil-index](https://github.com/fernandogarzaaa/sigil-index))
  is the other half of any badge-format change; update both together.
- Never commit a private key. The project signing key lives outside the
  repo; only its public key is published at `keys/project.json` in the
  index.

## Manual verification checklist

Some paths need a human with credentials; they are unit-tested but not
exercised in CI:

- `sigil publish` against a real authenticated `gh` (CI and this
  environment lack GitHub CLI auth): run
  `sigil publish --badge <file>` with `gh auth login` done, and
  confirm the PR opens.
- `sigil install` actually installing: run with `--dry-run` in CI;
  a human should confirm a real install once per release.

## Releases

Releases are cut by the maintainer: bump `version` in `package.json`,
add a CHANGELOG entry under a dated heading, and `npm publish`.
