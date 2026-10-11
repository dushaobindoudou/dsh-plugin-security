/** Static evidence collection and review priority, never a malware verdict.
 * Ordinary API matches are capability observations. Bounded source analysis
 * adds local data/execution links; only a contextual review can authorize
 * automatic enforcement. No scanned source is executed here.
 */

import { runRules, RULE_DEFS, SEVERITY_ORDER } from './rules.js';
import { behaviorChains, classifyFindings, evidenceScopes } from './behavior.js';

export const SCREENING_REVISION = 'risk-status-4';

export { RULE_DEFS, SEVERITY_ORDER };

/** Append local source/sink evidence; co-occurrence alone never escalates. */
export function correlateFindings(findings, target) {
  const list = Array.isArray(findings) ? findings : [];
  // Co-occurring capabilities do not establish a data or execution link.
  return target ? [...list, ...behaviorChains(target, evidenceScopes(target))] : list;
}

/** Extract high-priority review signals; static signals cannot auto-disable. */
export function dispositionSignal(findings) {
  const level = { value: 'none', order: 0 };
  const triggers = [];
  for (const finding of correlateFindings(findings)) {
    const order = SEVERITY_ORDER[finding.severity] ?? 0;
    if (order >= SEVERITY_ORDER.high) {
      triggers.push({ ruleId: finding.ruleId, severity: finding.severity, correlation: finding.extra?.correlation });
      if (order > level.order) {
        level.value = finding.severity;
        level.order = order;
      }
    }
  }
  return { level: level.value, triggers };
}

/** Legacy config helper: does the signal reach the static review threshold? */
export function signalRequiresDisable(signal, autoDisableAt) {
  if (autoDisableAt === 'never' || signal === undefined || signal === null) return false;
  if (autoDisableAt === 'high') return signal.level === 'critical' || signal.level === 'high';
  if (autoDisableAt === 'critical') return signal.level === 'critical';
  return false;
}

/**
 * Group findings into the five evidence families the skill review walks
 * through — gives the agent a checklist order instead of a flat list.
 */
export function reviewFamilies(findings) {
  const FAMILY_OF = {
    'install-scripts': 'lifecycle',
    'dep-source': 'identity',
    'scope-impersonation': 'identity',
    metadata: 'identity',
    'code-exec': 'execution',
    'client-risk': 'execution',
    'module-hijack': 'execution',
    obfuscation: 'execution',
    'net-egress': 'egress',
    'patch-config': 'egress',
    'fs-sensitive': 'sensitive-access',
    'secret-env': 'sensitive-access',
    'dep-tree-scripts': 'lifecycle',
    'inject-surface': 'host-surface',
    'tool-surface': 'host-surface',
    'patch-semantics': 'host-surface',
    'prompt-injection': 'host-surface',
  };
  const families = {};
  for (const finding of findings ?? []) {
    const family = FAMILY_OF[finding.ruleId] ?? 'other';
    (families[family] ??= []).push(finding);
  }
  return families;
}

/**
 * Build the agent-facing evidence pack for one target.
 *
 * @param {object} target a collected target (see collect.js)
 * @param {object} ctx scan context (`officialNames`, `listPluginsExtras`)
 * @param {{audit?: object}} [extras] dependency audit result for the pack
 */
export function screenTarget(target, ctx, extras = {}) {
  const scopeOf = evidenceScopes(target);
  const findings = correlateFindings(classifyFindings(target, runRules(target, ctx), scopeOf), target);
  const signal = dispositionSignal(findings);
  return {
    name: target.name,
    version: target.version ?? null,
    source: target.source,
    self: target.self === true,
    findings,
    families: reviewFamilies(findings),
    signal,
    depsAudit: extras.audit ?? null,
    defs: Object.fromEntries(
      (Object.keys(RULE_DEFS)).map((id) => [id, { id, title: RULE_DEFS[id].title, advice: RULE_DEFS[id].advice }]),
    ),
  };
}
