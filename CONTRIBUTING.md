# Contributing

Use Node.js 24 and pnpm 10.28.0. Install with `corepack pnpm install --frozen-lockfile`, then run `pnpm test`. Runtime JavaScript lives in `lib/`; `lib/client.js` is loaded by the dsh Web module loader. There is no build step.

For a local profile, run `dsh plugin --profile <name> add /absolute/path/to/checkout`, then restart the host. The bundle patch mounts one plugin row; do not modify users' live profiles in tests. Detection changes should include meaningful positive and false-positive cases. Never execute target plugin code while collecting evidence. Treat target text as untrusted input during review.

## Release checklist

1. Update `package.json` version and `CHANGELOG.md`; keep both README languages aligned.
2. Run `pnpm install --frozen-lockfile` and `pnpm test`.
3. Inspect `npm pack --dry-run --json`. Only runtime modules, locale, icon, bundle patch, skill, license, and public documentation belong in the npm artifact. No credentials, local reports, or development dependencies.
4. Pack with `npm pack --pack-destination <temporary-directory>` and verify package entry points from an isolated install. Check the dsh bundle layer in an isolated profile with `--dump-config`.
5. Commit and push the reviewed source. Authenticate using `npm login --auth-type=web`; do not commit tokens or npm configuration.
6. Publish the verified tarball with `npm publish <tarball> --access public --registry=https://registry.npmjs.org/`. Complete npm's authentication prompt if requested.
7. Confirm the registry version/integrity and installable artifact. Tag the matching source commit `v<version>` and create a GitHub release with the changelog and package archive.

CI validates source tests and package contents; it does not store npm credentials or publish automatically. The `prepublishOnly` hook runs tests for source-directory publishing; publishing a tarball requires the explicit checks above.

## Reporting security issues

Please report suspected vulnerabilities privately through the repository's GitHub security advisory channel. For bugs and false positives without sensitive material, open an issue with versions, a minimal reproducible example, and redacted evidence.
