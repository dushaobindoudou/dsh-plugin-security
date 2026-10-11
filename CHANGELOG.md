# Changelog

## 0.5.0

- Add the call-time gate: every tool call is attributed to the plugin that registered it and checked in `tools/pre-execute`. A call into a high-risk plugin asks the user **Allow once / Allow / Disable** through the host user-questions card, falling back to the native approval prompt when no card can be shown. Allow is remembered per installed version; Disable denies every tool call from the plugin until it is enabled again.
- Add per-plugin Enable / Disable / Reset controls and a Disabled tab to the settings page (`security/policy`); changes apply on the next call without a restart.
- Record the three-level risk (high / risk / none) and the declared tool names with every scan record; reports and the agent tools show it.
- Scan after every plugin-manager change and on demand when the gate meets a plugin with no record for its installed version, in addition to the startup scan.
- Retry dependency audits that ended unknown, keep agent reviews across forced rescans of unchanged content, and drop superseded records of the same package.
- Attribute tools that plugins registered before the gate started by their `execute` source text, so the first call into a newly installed, not yet scanned plugin is gated (found by the e2e run).
- Register the bundled review skill with the host skill catalog at startup; the manual skill link is no longer needed.
- Add `npm run test:e2e`: an isolated headless dsh run with a harmless high-risk fixture plugin, a scripted question answerer and a deterministic local model.
- Fix `security_review` throwing `ACTION_ICON is not defined` after it had already stored the verdict.

## 0.4.6

- Fix `/api/security/status` HTTP 404 with an explicit Typert host contract and connection lifecycle route registration.
- Separate ordinary API capability matches from contextual behavior evidence; remove package-wide co-occurrence escalation and misleading A–F grades.
- Add bounded local AST links, evidence scopes, content/rule cache invalidation, and visible incomplete/failed audit states.
- Keep automatic quarantine gated by a high-confidence malicious review, enforcement mode, threshold, and protection rules.
- Restore disposition settings; add searchable risk/action/whitelist tabs, per-plugin controls, top-of-list exports, SVG icons, and compact scan statistics.
- Document installation, review semantics, privacy, limitations, and troubleshooting in English and Chinese; align package metadata and shared protocol peer dependencies with dsh packaging conventions.

Earlier npm versions predate this changelog. This release replaces the repository's original pre-install scanner interface with the installed-profile review tools documented in the README.
