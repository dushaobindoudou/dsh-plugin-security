/**
 * Orchestrate the security pass: collect targets, skip the ones already
 * scanned at the same content and rule revision, screen + audit the rest,
 * decide by contextual review, and write back to the scan state.
 *
 * Scan-once contract: a plugin@version that already has a scan record is
 * reused while content and rules match (unless `force`); it carries the summary,
 * dependency audit, agent review and disposition forward.
 *
 * @module dsh-plugin-security/scan
 */

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { collectTargets, fingerprintOf } from './collect.js';
import { RULE_DEFS, SEVERITY_ORDER, SEVERITY_WEIGHT, SEVERITIES } from './rules.js';
import { screenTarget, SCREENING_REVISION } from './screen.js';
import { auditDependencies, maxLadder } from './audit.js';
import { openState, scanKey, isFresh } from './state.js';
import { decideAction, disablePluginInProfile, upgradeSuggestion, isProtected } from './disposition.js';

export { officialDeepseekNames };

/**
 * The official `@deepseek-ai/*` package set, taken from the dsh install
 * itself — the reference for the scope-impersonation rule.
 */
function officialDeepseekNames(globalRoot) {
  const names = new Set();
  const bases = [
    join(globalRoot, 'node_modules', '@deepseek-ai'),
    join(globalRoot, 'node_modules', '@deepseek-ai', 'dsh', 'node_modules', '@deepseek-ai'),
  ];
  for (const base of bases) {
    let entries;
    try {
      entries = readdirSync(base);
    } catch {
      continue;
    }
    for (const entry of entries) names.add(`@deepseek-ai/${entry}`);
  }
  return [...names];
}

// One in-flight scan promise per host process so concurrent callers share it.
let inflight = null;

/** The last completed report (process memory), or null. */
let lastReport = null;

/**
 * Resolve the deps of a target to `name@version` pairs actually installed.
 * Lookup order: the package's own node_modules, then the profile/global
 * roots (audit P1-6 follow-up: flat-hoisted installs keep the dependency at
 * the parent level, and previously the audit silently saw no deps). A
 * declared range with no real install anywhere is skipped — never guessed.
 */
export function resolveInstalledDeps(target, roots = []) {
  const manifest = target.manifest;
  const out = [];
  const names = new Set([
    ...Object.keys(manifest?.dependencies ?? {}),
    ...Object.keys(manifest?.peerDependencies ?? {}),
  ]);
  const local = target.dir !== null && target.dir !== undefined ? [join(target.dir, 'node_modules'), ...roots.map((r) => join(r, 'node_modules'))] : roots.map((r) => join(r, 'node_modules'));
  for (const name of names) {
    for (const base of local) {
      try {
        const pkgJson = JSON.parse(readFileSync(join(base, name, 'package.json'), 'utf8'));
        if (typeof pkgJson.version === 'string') {
          out.push({ name, version: pkgJson.version });
          break;
        }
      } catch {
        /* not installed here — try the next root, never guess */
      }
    }
  }
  return out;
}

function gradeOf(score, worstSeverity) {
  if (worstSeverity === 'critical') return 'F';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 45) return 'C';
  return 'D';
}

/** Score one target's findings: worst severity + weighted score + grade. */
export function assessFindings(findings) {
  const worst = worstSeverityOf(findings);
  const score = scoreOf(findings);
  return { worst, score, grade: gradeOf(score, worst) };
}

function worstSeverityOf(findings) {
  let worst = 'info';
  for (const f of findings ?? []) {
    if ((SEVERITY_ORDER[f.severity] ?? 0) > (SEVERITY_ORDER[worst] ?? 0)) worst = f.severity;
  }
  return worst;
}

function scoreOf(findings) {
  let score = 100;
  const worstByRule = new Map();
  for (const f of findings ?? []) {
    if (f.kind === 'capability') continue;
    const key = f.ruleId ?? f;
    if ((SEVERITY_ORDER[f.severity] ?? 0) > (SEVERITY_ORDER[worstByRule.get(key)] ?? -1)) worstByRule.set(key, f.severity);
  }
  for (const severity of worstByRule.values()) score -= SEVERITY_WEIGHT[severity] ?? 0;
  return Math.max(0, score);
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const bySeverity = (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0);
    if (bySeverity !== 0) return bySeverity;
    return a.ruleId < b.ruleId ? -1 : 1;
  });
}

/**
 * Decide + record the disposition for an already-scanned entry, without
 * rescanning sources. Used when an agent review lands via security_review.
 */
export function redecideEntry(entry, config, profileRoot) {
  const decision = decideAction(
    { signal: entry.screening.signal, depsWorst: entry.deps?.worst ?? 'none', review: entry.review ?? null, isSelf: entry.self === true },
    config,
    entry.name,
  );
  const shouldExecute = decision.action === 'disable' && config.mode === 'enforce' && !(entry.self || isProtected(entry.name, config));
  let execution = null;
  if (shouldExecute) {
    const result = disablePluginInProfile(profileRoot, entry.name, entry.dir);
    execution = { attempted: 'disable', ...result };
  }
  const advisories = Array.isArray(entry.deps?.advisories)
    ? entry.deps.advisories
    : Object.values(entry.deps?.results ?? {}).flatMap((r) => r.advisories ?? []);
  const upgrade = decision.action === 'upgrade'
    ? upgradeSuggestion(entry.name, entry.version, advisories, null)
    : null;
  return {
    ...entry,
    disposition: { ...decision, executed: shouldExecute, restartRequired: shouldExecute ? Boolean(execution?.restartRequired) : false, execution },
    upgrade,
  };
}

/**
 * Run the security pass over the profile.
 *
 * @param {object} env { profileRoot, globalRoot, dshHome }
 * @param {object} [extras] forwarded to collectTargets (listPlugins rows)
 * @param {object} [options] { force?: boolean, fetchImpl?: Function }
 */
export async function scanProfile(env, extras = {}, options = {}) {
  const state = openState(env.dshHome);
  const config = state.readConfig();

  if (config.mode === 'off') {
    return {
      schema: 'dsh-plugin-security/report@1',
      generatedAt: new Date().toISOString(),
      mode: 'off',
      config,
      summary: { targets: 0, fresh: 0, cached: 0, trusted: 0, dispositions: { disable: 0, upgrade: 0, review: 0, allow: 0 }, deps: { critical: 0, high: 0, medium: 0, low: 0, none: 0 } },
      plugins: [],
      notes: {
        zh: '安全门处于关闭（off）模式：不扫描、不处置。请在设置页切换到「只提示」或「处置」模式。',
        en: 'The security gate is OFF: no scanning, no enforcement. Switch to report-only or enforce in the settings page.',
      },
    };
  }

  const started = Date.now();
  const { targets, rows } = await collectTargets(env, extras);
  const ctx = { officialNames: officialDeepseekNames(env.globalRoot) };
  const force = options.force === true;
  const fetchImpl = options.fetchImpl ?? fetch;

  const plugins = [];
  const summary = {
    targets: 0,
    fresh: 0,
    cached: 0,
    trusted: 0,
    dispositions: { disable: 0, upgrade: 0, review: 0, allow: 0 },
    deps: { critical: 0, high: 0, medium: 0, low: 0, none: 0 },
  };

  for (const target of targets) {
    summary.targets += 1;
    // user-managed whitelist (request #6): trusted plugins skip screening
    // AND the dependency audit entirely — they are listed, not scanned.
    // The default protection seats (self, official scope, family) share the
    // semantics: trust by construction, not by inspection.
    if (isProtected(target.name, config)) {
      summary.trusted += 1;
      plugins.push({
        name: target.name,
        version: target.version,
        source: target.source,
        self: target.self === true,
        trusted: true,
        cached: true,
        rowStatus: target.rowStatus === null ? null : { status: target.rowStatus.status, id: target.rowStatus.id },
        screening: { signal: { level: 'none', triggers: [] }, worst: 'info', score: 100, grade: 'A', families: null },
        findings: [],
        deps: { worst: 'none', results: {}, errors: [] },
        depsAdvisories: [],
        review: null,
        disposition: { action: 'allow', reason: 'whitelisted', detail: 'on the trusted list — scanning skipped by config' },
        upgrade: null,
      });
      summary.dispositions.allow += 1;
      summary.deps.none += 1;
      continue;
    }
    // audit P1-9: the cache key carries a content fingerprint so a package
    // that pins its version but swaps code gets rescanned
    const fp = target.dir !== null ? fingerprintOf(target) : undefined;
    const key = scanKey(target.name, target.version, fp);
    const recorded = state.getScan(key);

    if (!force && recorded?.screeningRevision === SCREENING_REVISION && isFresh(recorded, target.name, target.version, fp)) {
      summary.cached += 1;
      const entry = recorded;
      const findings = Array.isArray(entry.screening?.findings) ? entry.screening.findings : [];
      const plugin = {
        name: entry.name,
        version: entry.version,
        source: entry.source,
        self: entry.self === true,
        dir: null,
        rowStatus: null,
        clientEntry: null,
        files: null,
        filesTruncated: entry.filesTruncated === true,
        scannedAt: entry.scannedAt,
        cached: true,
        screening: {
          signal: entry.screening?.signal ?? { level: 'none', triggers: [] },
          worst: entry.screening?.worst ?? 'info',
          score: entry.screening?.score ?? 100,
          grade: entry.screening?.grade ?? 'A',
          families: null,
          findingsHint: 'cached-record-all-scopes',
        },
        findings,
        deps: { worst: entry.deps?.worst ?? 'none', results: entry.deps?.unknown ? { audit: { unknown: true } } : {}, errors: entry.deps?.errors ?? [] },
        depsAdvisories: Array.isArray(entry.deps?.advisories) ? entry.deps.advisories : [],
        review: entry.review ?? null,
        disposition: entry.disposition ?? { action: 'review', reason: 'no-disposition', detail: '' },
        upgrade: entry.upgrade ?? null,
      };
      summary.dispositions[plugin.disposition?.action in summary.dispositions ? plugin.disposition.action : 'review'] += 1;
      if (plugin.deps.worst) summary.deps[plugin.deps.worst] = (summary.deps[plugin.deps.worst] ?? 0) + 1;
      plugins.push(plugin);
      continue;
    }

    // ---- fresh scan --------------------------------------------------------
    const pack = screenTarget(target, ctx);
    const deps = resolveInstalledDeps(target, [env.profileRoot, env.globalRoot].filter((r) => typeof r === 'string'));
    const audit = deps.length > 0
      ? await auditDependencies(deps, { fetchImpl })
      : { results: {}, worst: 'none', errors: [] };

    // audit P2-7: the grade covers dependency findings too — a plugin with a
    // critical advisory must not wear an A
    const worst = maxLadder(worstSeverityOf(pack.findings), audit.worst === 'none' ? 'info' : audit.worst);
    const entry = {
      schema: 'dsh-plugin-security/entry@1',
      name: target.name,
      version: target.version,
      dir: target.dir,
      fingerprint: fp,
      source: target.source,
      self: target.self === true,
      rowStatus: target.rowStatus === null ? null : { status: target.rowStatus.status, id: target.rowStatus.id },
      clientEntry: target.clientEntry?.rel ?? null,
      files: target.files.length,
      filesTruncated: target.filesTruncated === true,
      scannedAt: new Date().toISOString(),
      screening: {
        findings: sortFindings(pack.findings),
        signal: pack.signal,
        families: pack.families,
        worst: worstSeverityOf(pack.findings),
        score: scoreOf(pack.findings),
        grade: gradeOf(scoreOf(pack.findings), worst),
      },
      deps: { results: audit.results, worst: audit.worst, errors: audit.errors },
      review: !force && recorded?.fingerprint === fp && isFresh(recorded, target.name, target.version, fp) ? recorded.review ?? null : null,
      upgrade: null,
      disposition: null,
    };

    const decided = redecideEntry(entry, config, env.profileRoot);
    // Keep capability, support and runtime evidence on cached views too.
    const keptFindings = decided.screening.findings;
    const depsAdvisories = Object.values(decided.deps.results ?? {})
      .flatMap((r) => r.advisories ?? [])
      .map((a) => ({ dep: a.dep, id: a.id, severity: a.severity, fixedIn: a.fixedIn, title: a.title, cvss: a.cvss }));
    state.putScan(key, {
      name: decided.name, version: decided.version, source: decided.source, self: decided.self,
      dir: decided.dir, fingerprint: fp,
      filesTruncated: decided.filesTruncated === true,
      screeningRevision: SCREENING_REVISION,
      scannedAt: decided.scannedAt,
      screening: {
        signal: decided.screening.signal, worst: decided.screening.worst, score: decided.screening.score, grade: decided.screening.grade,
        findings: keptFindings,
      },
      deps: { worst: decided.deps.worst, advisories: depsAdvisories, errors: decided.deps.errors ?? [], unknown: Object.values(decided.deps.results ?? {}).some((result) => result.unknown) },
      review: decided.review,
      disposition: { action: decided.disposition.action, reason: decided.disposition.reason, detail: decided.disposition.detail, executed: decided.disposition.executed },
      upgrade: decided.upgrade,
    });
    // audit P2-9: enforcement actions leave an append-only trail
    if (decided.disposition.executed) {
      state.audit({ kind: 'auto-disable', name: decided.name, version: decided.version, reason: decided.disposition.reason, fingerprint: fp });
    }

    summary.fresh += 1;
    summary.dispositions[decided.disposition.action in summary.dispositions ? decided.disposition.action : 'review'] += 1;
    summary.deps[decided.deps.worst] = (summary.deps[decided.deps.worst] ?? 0) + 1;
    plugins.push({
      ...decided,
      findings: decided.screening.findings,
      depsResults: decided.deps.results,
      depsAdvisories,
      cached: false,
    });
  }

  plugins.sort((a, b) => {
    const actionOrder = { disable: 0, upgrade: 1, review: 2, allow: 3 };
    const byAction = (actionOrder[a.disposition?.action] ?? 3) - (actionOrder[b.disposition?.action] ?? 3);
    if (byAction !== 0) return byAction;
    const bySignal = (SEVERITY_ORDER[b.screening?.signal?.level] ?? 0) - (SEVERITY_ORDER[a.screening?.signal?.level] ?? 0);
    if (bySignal !== 0) return bySignal;
    return a.name < b.name ? -1 : 1;
  });

  const report = {
    schema: 'dsh-plugin-security/report@1',
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    mode: config.mode,
    config,
    env: { profileRoot: env.profileRoot, globalRoot: env.globalRoot },
    rows: rows.length,
    summary,
    rules: RULE_DEFS,
    ruleCount: Object.keys(RULE_DEFS).length,
    severities: SEVERITIES,
    plugins,
    notes: {
      zh: '静态初筛只读源码，不执行插件；能力匹配与局部数据联系均需结合用途审读，不是恶意判定。依赖漏洞来自 npm advisory（OSV 补齐修复版本）。内容或规则版本变化会重扫。只提示模式不修改被扫插件；处置模式仅对 high 置信 malicious 审读结论自动禁用并隔离（保护名单除外，重启后生效，可撤销）。网络失败标记为未知。',
      en: 'Static screening reads sources without executing plugins. Capability matches and local data links need contextual review; they are not malware verdicts. Dependency advisories come from npm, with fix versions from OSV. Content or rule revision changes invalidate the cache. Report-only does not modify scanned plugins; enforce disables and quarantines only high-confidence malicious reviews (protected names exempt, reversible after restart). Network failures are unknown.',
    },
  };
  lastReport = report;
  return report;
}

/**
 * Scan with in-flight dedup; `force` rescans everything.
 */
export async function scanCached(env, extras = {}, { force = false, fetchImpl } = {}) {
  if (force !== true && inflight !== null) return inflight;
  const run = scanProfile(env, extras, { force, fetchImpl })
    .then((report) => {
      inflight = null;
      return report;
    })
    .catch((error) => {
      inflight = null;
      throw error;
    });
  inflight = run;
  return run;
}

/** The last report produced in this host process. */
export function cachedReport() {
  return lastReport;
}
