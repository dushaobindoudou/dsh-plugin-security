/**
 * Disposition — turn scan results into enforcement decisions, and execute
 * them when mode=enforce.
 *
 * Decision inputs, in priority order:
 *   1. agent review verdict (malicious/suspicious/benign, written back via
 *      the security_review tool) — a high-confidence malicious verdict outranks everything
 *      static; a benign verdict can override a static signal
 *   2. static review priority (critical/high findings; never auto-disable)
 *   3. the dependency audit worst level + fixedIn availability
 *
 * Actions:
 *   - `disable`    remove the plugin from the profile bundles array
 *                 (atomic write + one backup; takes effect after restart —
 *                 same surface as plugin_manager, deliberately reversible)
 *   - `upgrade`    the audit found fixes: suggest `pkg@fixedIn`
 *                 (autoUpgrade controls suggestions; upgrades require an
 *                 explicit user action because they introduce new code)
 *   - `allow`      no actionable finding — not a verified-safe verdict
 *   - `review`     evidence needs a human/agent look, no action yet
 *
 * Safety valves baked in:
 *   - the protected list (self, official @deepseek-ai/*, and the configured
 *     extras) is NEVER auto-disabled, whatever the signal says
 *   - every decision is recorded in the scan state with who decided it
 *
 * @module dsh-plugin-security/disposition
 */

import { existsSync, readFileSync, readdirSync, renameSync, writeFileSync, copyFileSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ladderAtLeast } from './audit.js';

/** Names enforcement must never touch. Family seats + the official scope. */
export const PROTECTED_DEFAULT = Object.freeze([
  'dsh-plugin-security',
  'dsh-plugin-sentinel',
]);

export function isProtected(name, config) {
  if (name === undefined || typeof name !== 'string') return true;
  if (name.startsWith('@deepseek-ai/')) return true;
  if (PROTECTED_DEFAULT.includes(name)) return true;
  const extra = Array.isArray(config?.protectedNames) ? config.protectedNames : [];
  return extra.includes(name);
}

/**
 * The decision table. Pure — no IO here so it is exhaustively testable.
 *
 * @param {{signal: {level: string}, depsWorst: string, review: object|null, isSelf: boolean}} input
 * @param {{mode: string, autoDisableAt: string, autoUpgrade: boolean}} config
 * @param {string} name plugin name (for the protected list)
 */
export function decideAction({ signal, depsWorst, review, isSelf }, config, name) {
  const enforce = config.mode === 'enforce';
  const protectedTarget = isSelf || isProtected(name, config);

  if (review?.verdict === 'malicious') {
    // audit P1-10: a low-confidence malicious verdict must not disable —
    // that contradicts the skill's own standard ("prefer suspicious when
    // evidence is thin"). Only high confidence reaches enforcement.
    if (review.confidence !== 'high') {
      return { action: 'review', reason: 'agent-malicious-low-confidence', detail: `malicious verdict at ${review.confidence} confidence is not enough to disable — re-verify evidence first` };
    }
    if (config.autoDisableAt === 'never') {
      return { action: 'review', reason: 'agent-malicious-auto-disable-off', detail: review.reason ?? 'automatic disabling is off' };
    }
    return protectedTarget
      ? { action: 'review', reason: 'agent-malicious-protected', detail: 'malicious verdict on a protected/self plugin — surface to the user, never auto-disable' }
      : { action: enforce ? 'disable' : 'review', reason: 'agent-malicious', detail: review.reason ?? '' };
  }
  if (review?.verdict === 'suspicious') {
    // audit P1-10: the middle tier was inert — give it explicit semantics:
    // always a human decision, never auto-disable, whatever the mode
    return { action: 'review', reason: 'agent-suspicious', detail: `suspicious (${review.confidence ?? 'unrated'}): ${review.reason ?? 'needs human review'}` };
  }
  if (review?.verdict === 'benign' && review.confidence === 'high') {
    // a confident benign review overrides static noise; deps facts stand
    return depsWorst !== 'none'
      ? { action: enforce && config.autoUpgrade ? 'upgrade' : 'allow', reason: 'benign-reviewed-deps-only', detail: 'agent reviewed benign; dependency advisories remain' }
      : { action: 'allow', reason: 'benign-reviewed', detail: review.reason ?? '' };
  }

  if (signal?.level && signal.level !== 'none' && !protectedTarget) {
    return { action: 'review', reason: `static-${signal.level}`, detail: `static evidence needs contextual review: ${signal.triggers.map((t) => t.ruleId).join(', ')}` };
  }
  if (signal?.level && signal.level !== 'none' && protectedTarget) {
    return { action: 'review', reason: `static-${signal.level}-protected`, detail: 'protected/self plugin: surfaced, not auto-disabled' };
  }
  if (ladderAtLeast(depsWorst, 'high')) {
    return { action: config.autoUpgrade ? 'upgrade' : 'review', reason: `deps-${depsWorst}`, detail: 'dependency advisories with fixes available' };
  }
  if (depsWorst !== 'none' || (signal && signal.level !== 'none')) {
    return { action: 'review', reason: 'advisory-findings', detail: 'below thresholds: report only' };
  }
  return { action: 'allow', reason: 'clean', detail: 'no signals' };
}

// ---------------------------------------------------------------------------
// profile bundles editing (the disable/enable surface)

function readProfileManifest(profileRoot) {
  const file = join(profileRoot, 'package.json');
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  return { file, raw };
}

function writeProfileManifestAtomic(file, doc) {
  // keep a rolling snapshot chain (audit P2-6): first backup keeps the
  // stable name, every write adds a timestamped one, last 5 are kept
  if (existsSync(file)) {
    if (!existsSync(`${file}.security-bak`)) copyFileSync(file, `${file}.security-bak`);
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      copyFileSync(file, `${file}.security-bak-${ts}`);
      const dir = dirname(file);
      const chain = readdirSync(dir).filter((n) => n.startsWith('package.json.security-bak-')).sort();
      for (const stale of chain.slice(0, Math.max(0, chain.length - 5))) {
        try { unlinkSync(join(dir, stale)); } catch { /* best effort */ }
      }
    } catch { /* best effort */ }
  }
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
  // verify the rewrite parses before it replaces the real manifest
  JSON.parse(readFileSync(tmp, 'utf8'));
  renameSync(tmp, file);
}

function bundlesListOf(raw) {
  const shape = raw?.dsh?.profile;
  if (Array.isArray(shape?.bundles)) return shape.bundles;
  if (Array.isArray(shape?.bundle?.bundles)) return shape.bundle.bundles;
  return null;
}

function bundlesAssign(raw, list) {
  if (Array.isArray(raw?.dsh?.profile?.bundles)) raw.dsh.profile.bundles = list;
  else if (Array.isArray(raw?.dsh?.profile?.bundle?.bundles)) raw.dsh.profile.bundle.bundles = list;
  return raw;
}

const QUARANTINE_SUFFIX = '.security-quarantined';

/**
 * Disable one plugin: remove its name from the profile bundles array AND
 * quarantine the package directory by renaming it in place (audit P2-6 —
 * removal from bundles alone leaves the code importable and revivable by
 * another patch row). The rename is best-effort: if it fails (EBUSY…), the
 * bundles removal still stands.
 * Returns `{ disabled, quarantined, restartRequired }` or a reason string.
 */
export function disablePluginInProfile(profileRoot, name, pluginDir) {
  const { file, raw } = readProfileManifest(profileRoot);
  const list = bundlesListOf(raw);
  if (list === null) return { disabled: false, reason: 'no-bundles-array' };
  if (!list.includes(name)) return { disabled: false, reason: 'not-in-bundles' };
  writeProfileManifestAtomic(file, bundlesAssign(raw, list.filter((n) => n !== name)));
  let quarantined = false;
  if (typeof pluginDir === 'string' && pluginDir.length > 0 && existsSync(pluginDir)) {
    try {
      renameSync(pluginDir, `${pluginDir}${QUARANTINE_SUFFIX}`);
      quarantined = true;
    } catch {
      quarantined = false;
    }
  }
  return { disabled: true, quarantined, restartRequired: true };
}

/** Re-enable one plugin: add its name back to the profile bundles array. */
export function enablePluginInProfile(profileRoot, name, pluginDir) {
  const { file, raw } = readProfileManifest(profileRoot);
  const list = bundlesListOf(raw);
  if (list === null) return { enabled: false, reason: 'no-bundles-array' };
  // release the quarantine regardless of the bundles outcome
  let released = false;
  const candidate = typeof pluginDir === 'string' && pluginDir.length > 0
    ? `${pluginDir}${QUARANTINE_SUFFIX}`
    : null;
  if (candidate !== null && existsSync(candidate)) {
    try {
      renameSync(candidate, pluginDir);
      released = true;
    } catch {
      released = false;
    }
  }
  if (list.includes(name)) return { enabled: true, alreadyPresent: true, released };
  const next = [...list, name].sort((a, b) => (a < b ? -1 : 1));
  writeProfileManifestAtomic(file, bundlesAssign(raw, next));
  return { enabled: true, restartRequired: true, released };
}

/**
 * Build the upgrade suggestion for a plugin. Pure.
 *
 * @param {string} pluginName
 * @param {string|null} pluginVersion
 * @param {Array<{dep: string, fixedIn: string|null}>} advisories flattened advisory list
 * @param {{latest: string}|null} registryMeta the plugin's own registry info
 * @returns `{ upgrade, command, targets, kind }` — kind: 'deps' | 'plugin' | 'none'
 */
export function upgradeSuggestion(pluginName, pluginVersion, advisories, registryMeta) {
  const list = Array.isArray(advisories) ? advisories : [];
  const fixable = list.filter((a) => a.fixedIn !== null && a.fixedIn !== undefined);
  if (fixable.length === 0) {
    // no dependency fix — maybe the plugin itself has a newer release
    if (registryMeta?.latest && registryMeta.latest !== pluginVersion) {
      return { upgrade: true, command: `pnpm add ${pluginName}@${registryMeta.latest}`, targets: [`${pluginName}@${registryMeta.latest}`], kind: 'plugin' };
    }
    return { upgrade: false, command: null, targets: [], kind: 'none' };
  }
  const targets = [...new Set(fixable.map((a) => `${a.dep}@${a.fixedIn}`))].sort();
  return { upgrade: true, command: `pnpm add ${targets.join(' ')}`, targets, kind: 'deps' };
}
