# dsh-plugin-security

[中文](./README.zh-CN.md) · [npm](https://www.npmjs.com/package/dsh-plugin-security) · [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)

**Know what a plugin can do before you let it in — and before every update.**
`dsh-plugin-security` is the supply-chain gate for DeepSeek Harness: audit any npm
plugin before installing it, and diff what an update changes. It reads the code a
package actually ships, then reports the permission profile with file:line evidence.

The dsh plugin shop explicitly does not sandbox plugins: once loaded, a plugin
reaches your full `ctx` — filesystem, shell, and the requests your model sends.
This plugin is the missing gate in front of that door.

## What it does

**1. `plugin_security` — pre-install audit.** Give it an npm package name (or a
local plugin directory). It downloads the tarball straight from the registry,
scans the shipped files, and returns a permission card:

```markdown
## Plugin security: some-plugin@1.2.3

**Risk: REVIEW** — Human review recommended before installing this version.

| Surface | Observed |
|---|---|
| Install scripts | no |
| Filesystem read | **yes** |
| Child processes | **yes** |
| Network | **yes** |
| Credential access | **yes** |
| Outbound hosts | `api.github.com`, `registry.npmjs.org` |
| Credential-looking env | `GITHUB_TOKEN` |
```

Every finding carries `file:line` evidence, so you can jump straight to the code
that triggered it. The scan is read-only by construction: nothing is written to
disk, and tarballs are parsed in memory.

**2. `plugin_security_diff` — update gate.** The classic supply-chain attack
isn't the version you reviewed — it's the next one. Point the diff at two
versions and it reports what the update **adds**:

```markdown
## Plugin security diff: some-plugin 1.2.3 → 1.3.0

**Risk: BLOCK** — this update adds an install script and credential access.

- Capabilities added: install-script, credential-access, network
- New outbound hosts: `collector.evil.example.com`
```

Risk is judged on the **delta**, not on what you already accepted in the old
version — an update that only fixes a bug stays clean even if the plugin
always had filesystem access.

## Detection model

| Capability | Examples | Severity |
|---|---|---|
| `install-script` | `postinstall` in package.json | critical — the classic npm attack vector |
| `credential-access` | `.npmrc`, `_authToken`, `~/.ssh`, `.aws/credentials`, mnemonics | review |
| `fs-write` | `writeFile`, `rm`, `rename`, `mkdir` | review |
| `subprocess` | `spawn`, `exec`, `execSync` | review |
| `dynamic-exec` | `eval`, `new Function`, `vm.*` | review |
| `obfuscation` | long base64 literals, encoded payloads | review |
| `network` | `fetch`, `https.request`, axios | notice |
| `env-access` | `process.env.*` | notice |
| `fs-read` | `readFile`, `readdir`, `stat` | notice |

**Risk levels** are deliberately conservative:

- **block** — an install script paired with network / subprocess / credential /
  write / obfuscation access (the known attack shape), or obfuscated code that
  also touches credentials and executes dynamically.
- **review** — dangerous capabilities present, but in shapes that can be legitimate
  (a file manager needs filesystem access; a scanner references `.npmrc` to detect it).
- **notice** — read-only surfaces only.
- **clean** — nothing observed.

The tool surfaces evidence; you decide. It is not a verdict.

## Installation

```sh
dsh plugin --profile web add dsh-plugin-security
```

Then, inside the harness:

> Audit this plugin before we install it: use plugin_security on "some-package".

> Before updating dsh-plugin-shop from 0.8.0 to 0.8.5, run plugin_security_diff and tell me what changed.

## Design notes

- **Zero runtime dependencies.** Tarball download uses `fetch`; tar parsing is a
  small in-memory reader — no `child_process`, no temp files.
- **Scans what ships, not what's committed.** `dist/` and `lib/` are in scope;
  only `node_modules` and `.git` are skipped.
- **Registry-configurable.** Works against npmmirror or a corporate registry via
  the `registry` option.
- **Read-only by construction.** The only side effects are network GETs to the
  registry you configure.

## License

MIT
