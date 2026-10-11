# dsh-plugin-security

[中文](README.zh-CN.md) · [npm](https://www.npmjs.com/package/dsh-plugin-security) · [Changelog](CHANGELOG.md)

Plugin security review for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness): dependency advisories, source evidence, AI-assisted contextual review, and reversible enforcement. Includes a Web settings page and agent tools.

**Using `fetch`, `process.env`, filesystem APIs, or subprocesses is not a malware verdict.** Ordinary API matches are capability records. Local data and execution links identify evidence to investigate; an agent reviews the purpose, destination, and authorization before recording a verdict.

## Install

Use a current dsh installation with `@deepseek-ai/dsh-typert-protocol@0.2.0-rc.2`. The plugin requires Node.js 20+; use the Node.js version required by your dsh distribution (Node.js 24 recommended).

```sh
# Add to your existing Web profile, then restart its running host.
dsh plugin --profile web add dsh-plugin-security@latest
dsh --profile web
```

Open **Settings → Security Gate**. The package declares the standard `dsh.bundle` patch and `dsh.client` Web entry point; you do not need to edit the profile manifest manually. For another existing profile, replace `web` with its name. Agent tools work without the Web connection service; the host must provide `tools`, `pluginManager`, and `typert`.

To enable the bundled review skill for your agent, link it from the installed package (adjust the profile and `DSH_HOME` if needed):

```sh
mkdir -p "${DSH_HOME:-$HOME/.dsh}/skills"
ln -sfn "${DSH_HOME:-$HOME/.dsh}/profiles/web/node_modules/dsh-plugin-security/skills/dsh-plugin-security" \
  "${DSH_HOME:-$HOME/.dsh}/skills/dsh-plugin-security"
```

To remove the plugin:

```sh
dsh plugin --profile web remove dsh-plugin-security
```

The separately linked skill and stored reports remain until you remove them.

## What it does

- Audits installed dependency versions against npm advisories; looks up fix versions through OSV. Network failures remain **unknown**, rather than becoming clean cached results.
- Reads source and text files without executing target code. Evidence includes file, line, snippet, and whether it comes from runtime, support material, or dependency code.
- Uses bounded JavaScript AST analysis to identify local links such as whole-environment data entering a request body or decoded text entering an execution API. Package-wide co-occurrence alone does not escalate risk.
- Reuses scans by package version, content fingerprint, and screening-rule revision. Content or rule changes trigger another scan; force rescan is available.
- Provides searchable risk and action tabs, a whitelist, per-plugin actions, JSON/Markdown export, compact scan statistics, and bilingual settings metadata.
- Gates tool calls: a call into a high-risk plugin asks **Allow once / Allow / Disable** as a question card; the settings page enables or disables each plugin, effective immediately.
- Offers reversible disabling after a high-confidence malicious review, with profile backups and a bounded action log.

## When scans run

Each plugin version gets one full check (static screening + npm dependency audit); the result and its three-level risk are recorded in the state file. Scans run, reusing existing records:

1. When this plugin starts (its first start after installation is the first full scan).
2. After a plugin-manager install, removal or enable.
3. When the call gate meets a plugin with no record for its installed version — that plugin is scanned before the decision.

Content-fingerprint or rule-revision changes trigger a rescan; an audit that ended unknown after a network failure is retried. A forced rescan re-screens but keeps the agent review of unchanged content.

## Call gate

The gate listens on the host `tools/pre-execute` waterfall and attributes each tool call to the plugin that registered the tool (the loader entry seen at registration; tools registered before this plugin started are attributed from tool names extracted from source during scans).

| Situation | Result |
| --- | --- |
| Plugin disabled | Denied; the model is told not to retry |
| Installed version not scanned | Scan that plugin first, then apply the rows below |
| High risk, no decision | Question card: **Allow once** (this call) / **Allow** (remembered for this version; a new version asks again) / **Disable** (deny every later call from the plugin) |
| At risk, no risk, whitelisted or protected | Passed on to the host's remaining policies |

The card uses the host `ctx.userQuestions` service, the channel dsh itself uses to ask the user structured questions. When no card can be shown (no web client, a delegated child agent) the gate falls back to the native approval prompt (allow once / reject). Concurrent calls into one plugin share one question.

Each plugin row in the settings page has **Enable / Disable / Reset**: Enable equals Allow, Disable blocks every tool call, Reset returns to risk-based asking. Decisions live under `policies` in the state file and apply on the next call without a restart. Mode `off` disables the gate.

Only tool calls are gated; hooks, system-prompt contributions and web UI from a plugin do not pass through `tools/pre-execute`. If the gate fails internally the call proceeds with a logged warning, but a disabled plugin is still denied.

## Risk labels and actions

| Label | Meaning |
| --- | --- |
| High risk | High-confidence malicious review, or a high/critical dependency advisory. |
| At risk | Behavior requiring review, other advisories, uncertain reviews, incomplete scans, or failed checks. |
| No risk found | No actionable risk found within this scan's scope. Capability records alone do not change this label. This is not a safety guarantee. |
| Whitelist | Checks were skipped. These entries are separate from “No risk found.” |

Risk labels are stored with each scan record and shown in reports and agent tools. Labels and actions are independent: a high-risk plugin is asked about at call time, but the label does **not** automatically disable it. The old A–F grades are no longer shown; legacy report fields remain for compatibility.

## Configuration

Configure these options in the settings page; configuration is stored under `$DSH_HOME/plugin-security/state.json` (default `~/.dsh/plugin-security/state.json`).

| Option | Default | Behavior |
| --- | --- | --- |
| Mode | `report-only` | `off`: no scans, call gate or enforcement. `report-only`: scan and save reports without changing target plugins. `enforce`: apply review-gated disabling. |
| Automatic disable threshold | `critical` | `never` disables automatic enforcement. `critical` and `high` both cover a confirmed high-confidence malicious review, treated as critical for enforcement. Static matches and advisories alone never trigger automatic quarantine. |
| Upgrade suggestions | `false` | Suggest dependency upgrade commands when enabled; commands are not silently executed. |
| Whitelist | Built-in protected entries | Add/remove custom package names through the whitelist tab or each plugin row. Entries skip checks; built-in protected entries cannot be removed in the UI. |

Automatic disabling also requires `enforce` mode and an unprotected target. It removes the bundle from the profile and renames the package directory with a `.security-quarantined` suffix. **Restart dsh for the change to take effect.** Undo restores the bundle and directory. Self and built-in protected packages cannot be disabled or uninstalled through this plugin; the server enforces this restriction.

The scan state and action log are local. Profile edits use atomic writes and keep up to five rolling snapshots; the state retains up to 200 action-log entries. State directories/files use permissions `0700`/`0600` where supported.

## Agent tools

```text
security_scan { package?, force?, evidence? }
security_review { package, verdict, confidence?, reason? }
```

`verdict` is `malicious`, `suspicious`, or `benign`; `confidence` is `high`, `medium`, or `low`. A high-confidence benign review can resolve static concerns, but does not remove dependency advisory facts. Suspicious or uncertain reviews require human follow-up.

The bundled [review skill](skills/dsh-plugin-security/SKILL.md) treats target source, comments, README, and skill text as untrusted evidence. Reports do not themselves invoke a model; contextual review uses your dsh agent and its configured tools/provider.

## Privacy and limits

Dependency auditing sends package names and installed versions to npm, and advisory IDs to OSV for fix lookup. These requests do not upload source code or local paths. Agent-assisted review follows your configured model provider's data handling; evidence passed to an agent may contain source snippets.

This is **post-load inspection**, not a sandbox or a pre-install execution barrier. The inspector and plugins share the host process and permissions. Static analysis is bounded (including file/byte budgets) and does not cover all cross-file flows, dynamic behavior, network transports, or transitive vulnerabilities. Truncated or failed checks remain visible. Whitelisting deliberately removes coverage. Review verdicts are stored locally and are not an independent cryptographic trust guarantee.

## Development and release

```sh
corepack pnpm install --frozen-lockfile
pnpm test
npm pack --dry-run
```

`npm run test:e2e` creates a headless profile in a temporary `DSH_HOME`, installs this package and the two fixtures under `e2e/` (a harmless echo plugin that is high risk on purpose, and an answerer standing in for the person clicking the question card), and drives the real `dsh` through a deterministic local model: first call, allow once, allow, disable, settings enable, whitelist and mode off. It needs the global `dsh` launcher and npm registry access, and never touches your own profiles.

Tests cover detection and false-positive cases, profiles, cache invalidation, reversible disposition, settings behavior, and real Cordis/Typert/gateway RPC lifecycles. Shared host protocol packages are declared as peer and development dependencies per the [dsh packaging guide](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and release steps. Runtime JavaScript is shipped directly; consumers need no build script or install-time code execution from this package.

## Troubleshooting HTTP 404

`transport failure for /api/security/status: HTTP 404` means the host has not registered the settings RPC route. Upgrade this plugin, check the protocol peer version, and restart dsh. The plugin registers an explicit host contract and follows the Web connection service lifecycle.

Look for `plugin-security: RPC contract registration failed` or `Fetch route registration failed` in host logs. `$DSH_HOME/plugin-security/remote-diag.json` records observed service and route registration state. Headless profiles without a Web connection use the agent tools instead.

## License

[MIT](LICENSE) © 2026 dushaobindoudou.
