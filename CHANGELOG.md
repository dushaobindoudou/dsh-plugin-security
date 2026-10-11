# Changelog

## 0.5.0

### Added

- **Call gate.** Every tool call is attributed to the plugin that registered it and checked in the host `tools/pre-execute` waterfall. A call into a high-risk plugin, or one whose security check could not be completed, asks **Allow once / Allow / Disable** through the host user-questions card, falling back to the native approval prompt when no card can be shown. Allow once admits exactly the call that asked; Allow is remembered for the installed version; Disable disables the plugin.
- **Plugin-manager sync.** Disable, enable, uninstall and enforce-mode auto-disable call the host plugin manager (`setBundleEnabled` / `removeBundle`), the same operations as the native Plugins page. A plugin disabled on either page is denied while it is still loaded; gate blocks stored by earlier versions move to the plugin manager at startup.
- Settings page: per-plugin Enable / Disable / Reset, a Disabled tab, native disabled state, refresh on focus.
- The three-level risk (high / at risk / none) and the declared tool names are stored with every scan record and shown in reports and agent tools.
- Scan triggers: plugin-manager changes, profile recompositions (CLI installs under hot reload) and on demand at call time, in addition to startup.
- The bundled review skill registers itself with the host skill catalog; the manual skill link is no longer needed.
- `npm run test:e2e`: a real headless dsh in an isolated `DSH_HOME` with a harmless high-risk fixture plugin, a scripted question answerer and a deterministic local model.
- Repository: security policy, issue and pull-request templates, Dependabot, CODEOWNERS, an e2e CI job and a manual npm publish workflow with provenance.

### Changed

- A plugin no scan can record is asked about instead of passing; dependency audits that ended unknown are retried by the next scan and at call time (at most once per plugin every five minutes).
- A forced rescan keeps the agent review of unchanged content; superseded records of the same package are dropped.
- Tools registered before the gate started are attributed by their `execute` source text, so the first call into a newly installed plugin is gated (found by the e2e run).
- Host-rendered text (the question card, denial messages) follows the dsh UI language set in Settings → General, read per question; `DSH_LOCALE` overrides it and the process locale is the fallback.
- Screening revision `risk-status-4`: existing records are rescanned once after upgrading.

### Fixed

- `security_review` threw `ACTION_ICON is not defined` after it had already stored the verdict.

## 0.4.7

- Widen the `@deepseek-ai/dsh-typert-protocol` peer range to `>=0.1.0-rc.6 <0.3.0`.

## 0.4.6

- Fix `/api/security/status` HTTP 404 with an explicit Typert host contract and connection lifecycle route registration.
- Separate ordinary API capability matches from contextual behavior evidence; remove package-wide co-occurrence escalation and misleading A–F grades.
- Add bounded local AST links, evidence scopes, content/rule cache invalidation, and visible incomplete/failed audit states.
- Keep automatic quarantine gated by a high-confidence malicious review, enforcement mode, threshold, and protection rules.
- Restore disposition settings; add searchable risk/action/whitelist tabs, per-plugin controls, top-of-list exports, SVG icons, and compact scan statistics.
- Document installation, review semantics, privacy, limitations, and troubleshooting in English and Chinese; align package metadata and shared protocol peer dependencies with dsh packaging conventions.

Earlier npm versions predate this changelog. This release replaces the repository's original pre-install scanner interface with the installed-profile review tools documented in the README.
