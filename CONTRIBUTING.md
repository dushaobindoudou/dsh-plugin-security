# Contributing

Use Node.js 24 and pnpm 10.28.0. Install with `corepack pnpm install --frozen-lockfile`, then run `pnpm test`. Runtime JavaScript lives in `lib/`; `lib/client.js` is loaded by the dsh Web module loader. There is no build step.

`npm run test:e2e` runs the call gate end to end against the globally installed `dsh` (`npm install --global @deepseek-ai/dsh`) in a temporary `DSH_HOME`, with the fixtures under `e2e/` and a local deterministic model. Run it for any change to the gate, scanning triggers or plugin-manager sync; CI runs it on every push and pull request.

For a local profile, pack the checkout (`npm pack`) and run `dsh plugin --profile <name> add /absolute/path/to/dsh-plugin-security-<version>.tgz`; replacing an installed version needs a dsh restart. The bundle patch mounts one plugin row; do not modify users' live profiles in tests. Detection changes should include meaningful positive and false-positive cases. Never execute target plugin code while collecting evidence. Treat target text as untrusted input during review.

## Release checklist

1. Update `package.json` version and `CHANGELOG.md`; keep both README languages aligned.
2. Run `pnpm install --frozen-lockfile`, `pnpm test` and `npm run test:e2e`.
3. Inspect `npm pack --dry-run --json`. Only runtime modules, locale, icon, bundle patch, skill, license, and public documentation belong in the npm artifact. No credentials, local reports, or development dependencies.
4. Pack with `npm pack --pack-destination <temporary-directory>` and verify package entry points from an isolated install. Check the dsh bundle layer in an isolated profile with `--dump-config`.
5. Merge the reviewed source to `main` through a pull request with green CI, and tag the merge commit `v<version>`.
6. Publish either way:
   - **Preferred**: run the **Publish to npm** workflow with the tag. It publishes with npm provenance through trusted publishing; configure this repository (workflow `release.yml`, environment `npm`) as a trusted publisher on npmjs.com once. No token is stored.
   - **Local**: `npm login --auth-type=web`, then `npm publish <verified tarball> --access public --registry=https://registry.npmjs.org/`. Do not commit tokens or npm configuration.
7. Confirm the registry version/integrity and installable artifact, and create a GitHub release for the tag with the changelog and package archive.

CI validates source tests and package contents; it does not store npm credentials or publish automatically. The `prepublishOnly` hook runs tests for source-directory publishing; publishing a tarball requires the explicit checks above.

## Reporting security issues

See [SECURITY.md](SECURITY.md): report vulnerabilities privately through GitHub's private vulnerability reporting. For bugs and false positives without sensitive material, use the issue templates.
