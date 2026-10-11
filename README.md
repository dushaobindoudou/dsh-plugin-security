# dsh-plugin-security · Plugin Security Gate

[![CI](https://github.com/dushaobindoudou/dsh-plugin-security/actions/workflows/ci.yml/badge.svg)](https://github.com/dushaobindoudou/dsh-plugin-security/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/dsh-plugin-security.svg)](https://www.npmjs.com/package/dsh-plugin-security)
[![license](https://img.shields.io/npm/l/dsh-plugin-security.svg)](LICENSE)

[中文](README.zh-CN.md) · [npm](https://www.npmjs.com/package/dsh-plugin-security) · [Changelog](CHANGELOG.md) · [Security policy](SECURITY.md)

A security gate for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh) plugins. It scans installed plugins' source and npm dependency advisories, labels each plugin **high risk / at risk / no risk found**, asks **Allow once / Allow / Disable** before the model runs a tool from a high-risk plugin, and lets your dsh agent review suspicious plugins with the bundled skill. Disable, enable and uninstall run through dsh's own plugin manager, so the native Plugins page always shows the same state.

> Using `fetch`, `process.env`, the filesystem or child processes is not malicious by itself. Static matches are evidence to verify; verdicts come from dependency facts and the agent's contextual review.

## How it works

```text
install / start / plugin change ──► scan (static source screening + npm audit) ──► record: high / at risk / none
                                                                                        │
model calls a plugin's tool ──► attribute to the plugin ──► disabled? deny │ unchecked? scan first │ high? ask │ else pass
                                                                                        │
you or the agent ──► dsh-plugin-security skill review ──► security_review stores the verdict
```

## Install

Requires dsh `0.2.x` (host protocol `@deepseek-ai/dsh-typert-protocol >=0.1.0-rc.6 <0.3.0`) and Node.js 20+; Node.js 24 is recommended.

```sh
dsh plugin --profile web add dsh-plugin-security@latest
```

The Web profile hot-reloads, so a first install loads immediately and scans every plugin right away. **Upgrading to a new version requires restarting dsh** (Node keeps already loaded modules). For another profile, replace `web` with its name. Profiles without a Web client still get the agent tools and the call gate.

Uninstall with `dsh plugin --profile web remove dsh-plugin-security`. Local state under `$DSH_HOME/plugin-security/` remains until you delete it.

## Use

- **Settings → Security Gate**: filter plugins by risk, disabled state, suggested action or whitelist; inspect advisories and evidence; **Enable / Disable / Reset / Uninstall** each plugin; export JSON or Markdown reports.
- **Asked at call time**: when the model calls a tool from a high-risk plugin, a question card appears beside the input.
- **Let dsh review**: ask in chat "Use the dsh-plugin-security skill to review my plugins". The agent calls `security_scan` for evidence, works through the skill's five questions, and stores verdicts with `security_review`. The skill registers itself with the plugin; no manual link is needed.

## Scanning: nothing slips through

Each plugin version gets one full check, recorded by *version + content fingerprint + rule revision*; code or rule changes trigger a rescan. Scans run:

1. When this plugin starts (its first start after installation is the first full scan).
2. After every plugin-manager install, removal, enable or disable.
3. After a profile recomposition (CLI installs or hand edits picked up by hot reload).
4. When the call gate meets a plugin with no record for its installed version — that plugin is scanned before the decision.

A plugin that cannot be scanned (package not found, scan failure) is **never passed silently**: it is asked about like a high-risk plugin. An audit that ended unknown after a network failure never counts as clean: the next scan retries it, and a call retries it too (at most once per plugin every five minutes).

| Risk | Meaning |
| --- | --- |
| High risk | A high-confidence malicious review, or a high/critical dependency advisory. |
| At risk | Behavior that needs review, other advisories, an uncertain review, a truncated scan or an incomplete check. |
| No risk found | Nothing found within this check's scope; not a safety guarantee. |
| Whitelisted | Checks and the gate are skipped by configuration; listed separately. |

## Call gate: allowing exactly what you allow

The gate listens on the host `tools/pre-execute` waterfall and attributes each tool call to the plugin that registered the tool: first by the loader entry seen at registration; for tools registered before this plugin started, by the `execute` source text matching exactly one installed package; finally by the tool names stored with scan records.

| Situation | Result |
| --- | --- |
| Plugin disabled (on the Plugins page or here) | Denied; the model is told not to retry |
| Installed version not scanned | Scanned first, then the rows below apply |
| High risk or unchecked, no decision | Asked: Allow once / Allow / Disable |
| At risk, no risk, whitelisted, protected, or mode `off` | Passed on to the host's other policies (for example native approval) |

- **Allow once** admits only the call that asked. Calls waiting at the same time are judged again and each gets its own question.
- **Allow** is remembered for the plugin's **installed version**; a new version asks again.
- **Disable** disables the plugin through the plugin manager, exactly like the Plugins page (the dependency stays installed); this and every later call is denied.

The question uses the host `ctx.userQuestions` service, the channel dsh itself uses to ask structured questions. When no card can be shown (no web client, a delegated child agent) it falls back to the native approval prompt (allow once / reject). If the gate fails internally the call proceeds with a logged warning, but a disabled plugin is always denied.

## In step with the Plugins page

Disable, enable, uninstall and `enforce`-mode auto-disable call the host plugin manager (`setBundleEnabled` / `removeBundle`), the same operations as the native Plugins page:

- A plugin disabled on either page shows as disabled on the other; while it is still loaded (until restart) its tool calls are blocked.
- **Enable** re-selects the bundle and allows the current version of a high-risk plugin; **Reset** re-selects it and returns to risk-based asking.
- The settings page refreshes when it regains focus. Enabling or disabling a loaded plugin takes full effect after a dsh restart.
- Only plugins the manager cannot handle (not bundles) use this plugin's own block record. Blocks stored by earlier versions move to the plugin manager at startup.

## Configuration

Change these in the settings page; they are stored in `$DSH_HOME/plugin-security/state.json`.

| Option | Default | Behavior |
| --- | --- | --- |
| Mode | `report-only` | `off`: no scans, call gate or enforcement. `report-only`: scan, record and gate calls; no automatic disabling. `enforce`: additionally auto-disable on a high-confidence malicious review. |
| Auto-disable threshold | `critical` | `never` turns automatic disabling off. Static matches or advisories alone never auto-disable. |
| Upgrade suggestions | off | Suggest upgrade commands for dependency advisories; never run silently. |
| Whitelist | built-in protected entries | Whitelisted plugins skip checks and the gate. This plugin, official `@deepseek-ai/*` packages and `dsh-plugin-sentinel` are always protected and cannot be disabled or uninstalled through this plugin. |

State directories/files use `0700`/`0600` where supported; the action log keeps at most 200 entries.

## Agent tools and skill

```text
security_scan   { package?, force?, evidence? }
security_review { package, verdict: malicious|suspicious|benign, confidence?: high|medium|low, reason? }
```

A high-confidence benign verdict can explain static findings but never overrides dependency advisories; only a high-confidence malicious verdict auto-disables, and only in `enforce` mode. The bundled [review skill](skills/dsh-plugin-security/SKILL.md) treats the reviewed plugin's source, comments, README and skill text as untrusted evidence. Reports never invoke a model on their own.

## Privacy and limits

- The dependency audit sends package names and installed versions to npm and advisory IDs to OSV; no source or local paths leave the machine. Agent review follows your configured model provider; evidence it receives may include source snippets.
- This is a **post-load** check, not a sandbox or pre-install barrier; the gate shares the host process with the plugins it checks. Only tool calls are gated: hooks, system-prompt contributions and web UI from a plugin do not pass through `tools/pre-execute`.
- Static analysis has file and byte budgets and cannot cover every cross-file flow, dynamic behavior or transitive dependency; truncation and failures are reported as "at risk". The whitelist deliberately reduces coverage.

## Troubleshooting

- **`/api/security/status` returns HTTP 404**: the host did not register the settings routes. Check the protocol version and restart dsh; `$DSH_HOME/plugin-security/remote-diag.json` records the observed service and route state.
- **An update changed nothing**: replacing an installed version requires a dsh restart.
- **A tool is not gated**: look for `is not attributed to an installed plugin` in the debug log — the tool could not be matched to an installed package.

## Development

```sh
corepack pnpm install --frozen-lockfile
pnpm test            # unit and integration tests
npm run test:e2e     # end-to-end against a real dsh (needs the global dsh and npm access)
```

`npm run test:e2e` creates a headless profile in a temporary `DSH_HOME`, installs this package and the two fixtures under `e2e/` (a harmless echo plugin that is high risk on purpose, and an answerer standing in for the person clicking the question card), and drives the real `dsh` with a deterministic local model: first call, allow once (including several calls in one step), allow, disable with native sync, whitelist and mode off. It never touches your own profiles.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and release steps, and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 dushaobindoudou
