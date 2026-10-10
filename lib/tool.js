/**
 * The agent-facing tools.
 *
 * `security_scan` — run (or reuse) the gate pass and render the disposition
 * report: which plugins to disable / upgrade / keep, with evidence.
 *
 * `security_review` — write an agent review verdict (see SKILL.md) back for
 * one plugin; the disposition is immediately re-decided from the stored scan
 * record (no rescan), and the verdict persists across restarts via the scan
 * state. A `malicious` verdict outranks every static signal; a confident
 * `benign` verdict overrides static noise (dependency facts still stand).
 *
 * @module tool
 */

import { resolveEnv } from './paths.js';
import { scanCached, redecideEntry } from './scan.js';
import { listPluginsExtras } from './collect.js';
import { RULE_DEFS, SEVERITY_ORDER } from './rules.js';
import { openState, scanKey } from './state.js';

const ACTION_LABEL = { disable: '建议停用', upgrade: '建议升级', review: '待复核', allow: '无需处置' };

/** Render the gate report as compact disposition-first text for the model. */
export function renderReportText(report, { packageFilter = null, withEvidence = true } = {}) {
  const plugins = (report.plugins ?? []).filter((p) => packageFilter === null || p.name.includes(packageFilter));
  const s = report.summary ?? {};
  const lines = [];
  lines.push(`插件安全门 · ${report.generatedAt} · 模式 ${report.mode ?? report.config?.mode ?? '?'}`);
  lines.push(`插件 ${s.targets ?? plugins.length} 个（本次新扫 ${s.fresh ?? '?'} / 复用记录 ${s.cached ?? '?'}）；处置：停用 ${s.dispositions?.disable ?? 0} / 升级 ${s.dispositions?.upgrade ?? 0} / 复核 ${s.dispositions?.review ?? 0} / 放行 ${s.dispositions?.allow ?? 0}`);
  lines.push('');

  for (const p of plugins) {
    const action = p.disposition?.action ?? 'review';
    const verdictTag = p.review ? `已审读:${p.review.verdict} (${p.review.confidence ?? 'unknown'})` : '未审读';
    lines.push(`${ACTION_LABEL[action] ?? '待复核'} ${p.name}${p.version ? `@${p.version}` : ''} · ${verdictTag} · 复核优先级 ${p.screening?.signal?.level ?? 'none'} · 依赖 ${p.deps?.worst ?? 'none'}${p.cached ? '（沿用扫描记录）' : ''}`);
    if (p.disposition?.reason) lines.push(`    处置依据: ${p.disposition.reason}${p.disposition.detail ? `（${p.disposition.detail}）` : ''}`);
    if (p.upgrade?.upgrade && p.upgrade.command) lines.push(`    升级命令: ${p.upgrade.command}`);
    const advisories = Array.isArray(p.depsAdvisories)
      ? p.depsAdvisories
      : Object.values(p.depsResults ?? {}).flatMap((d) => d.advisories ?? []);
    for (const a of advisories.slice(0, 4)) {
      lines.push(`    依赖 ${a.dep}@${a.fixedIn ? `→${a.fixedIn}` : '无修复'} [${a.severity}] ${a.id} ${a.title}`);
    }
    if (withEvidence) {
      const findings = (p.findings ?? p.screening?.findings ?? []).filter((f) => (SEVERITY_ORDER[f.severity] ?? 0) >= SEVERITY_ORDER.high);
      for (const f of findings.slice(0, 6)) {
        const def = RULE_DEFS[f.ruleId];
        lines.push(`    [${f.severity}] ${def?.title?.zh ?? f.ruleId}`);
        for (const e of (f.evidence ?? []).slice(0, 2)) lines.push(`        ${e.ref}: ${e.snippet}`);
      }
    }
  }
  lines.push('');
  lines.push(report.notes?.zh ?? '');
  return lines.join('\n');
}

/**
 * Register both tools on the host tool registry.
 * @returns the registry disposer, or null when tools are unavailable.
 */
export function registerSecurityTools(ctx) {
  const tools = typeof ctx?.get === 'function' ? ctx.get('tools') : undefined;
  if (tools === undefined || typeof tools.register !== 'function') return null;
  const hostCtx = ctx;
  const disposers = [];

  disposers.push(tools.register({
    name: 'security_scan',
    description:
      '运行 dsh 插件安全门：依赖漏洞审计（npm advisory 源）+ 恶意行为静态初筛，输出处置建议（停用/升级/复核/放行）。' +
      '每个插件@版本只扫一次（记录持久化），force 可强制重扫。' +
      '适合：安装新插件后体检、用户询问某插件是否安全、定期巡检。' +
      '要深度审读一个插件的证据并给出恶意性判定，请先调用本工具拿到证据包，再按 dsh-plugin-security skill 的方法论审读。',
    parameters: {
      type: 'object',
      properties: {
        package: { type: 'string', description: '只看名称包含该子串的插件（可选）' },
        force: { type: 'boolean', description: '强制重扫（默认沿用已扫记录）' },
        evidence: { type: 'boolean', description: '在输出里附带 high 及以上的证据行（默认 true）' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (args, value) => [{ type: 'text', text: value.text }] },
    timeoutMs: 90000, // audit P2-10: OSV follow-ups were capped at 160s serial; 90s fits the concurrency-capped path
    async execute(args) {
      const resolved = resolveEnv();
      if (resolved.error !== undefined) return { error: resolved.error, text: `安全门运行失败：${resolved.error}` };
      const report = await scanCached(resolved.env, listPluginsExtras(hostCtx), { force: args?.force === true });
      const text = renderReportText(report, {
        packageFilter: typeof args?.package === 'string' && args.package.length > 0 ? args.package : null,
        withEvidence: args?.evidence !== false,
      });
      return { generatedAt: report.generatedAt, summary: report.summary, mode: report.mode, text };
    },
  }));

  disposers.push(tools.register({
    name: 'security_review',
    description:
      '为某个插件写回恶意性审读结论（配合 dsh-plugin-security skill 的审读方法论使用）。' +
      '只有 high 置信度 malicious 在 enforce 模式下会自动移除并隔离该插件，重启生效；静态匹配和低置信结论仅复核；' +
      'high 置信度的 benign 会覆盖静态误报噪声（依赖漏洞事实不受影响）。' +
      '结论持久化在该插件@版本的扫描记录里，后续扫描直接沿用。',
    parameters: {
      type: 'object',
      properties: {
        package: { type: 'string', description: '插件包名（必须与扫描报告里的名称一致）' },
        verdict: { type: 'string', enum: ['malicious', 'suspicious', 'benign'], description: '恶意性判定' },
        confidence: { type: 'string', enum: ['high', 'medium', 'low'], description: '置信度，默认 medium' },
        reason: { type: 'string', description: '一句话判定理由（引用关键证据）' },
      },
      required: ['package', 'verdict'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (args, value) => [{ type: 'text', text: value.text }] },
    timeoutMs: 15000,
    async execute(args) {
      const resolved = resolveEnv();
      if (resolved.error !== undefined) return { error: resolved.error, text: `审读写回失败：${resolved.error}` };
      const pkg = typeof args?.package === 'string' ? args.package : '';
      if (pkg.length === 0) return { error: 'package is required', text: '缺少 package 参数' };
      const state = openState(resolved.env.dshHome);
      const config = state.readConfig();
      const index = state.readScanIndex();
      const key = Object.keys(index).find((k) => index[k].name === pkg) ?? null;
      if (key === null) {
        return { error: 'no-scan-record', text: `没有 ${pkg} 的扫描记录——先跑一次 security_scan` };
      }
      const verdict = args?.verdict;
      if (!['malicious', 'suspicious', 'benign'].includes(verdict)) {
        return { error: 'invalid-verdict', text: `verdict 必须是 malicious/suspicious/benign` };
      }
      const entry = {
        ...index[key],
        review: {
          verdict,
          confidence: ['high', 'medium', 'low'].includes(args?.confidence) ? args.confidence : 'medium',
          reason: typeof args?.reason === 'string' ? args.reason.slice(0, 500) : '',
          by: 'agent',
          at: new Date().toISOString(),
        },
      };
      const redecided = redecideEntry(entry, config, resolved.env.profileRoot);
      // audit P2-3: write back the FULL record (spread the original entry) —
      // dropping deps.advisories erased the upgrade hint on the next review
      state.putScan(scanKey(redecided.name, redecided.version, index[key]?.fingerprint), {
        ...index[key],
        name: redecided.name, version: redecided.version, source: redecided.source, self: redecided.self,
        dir: redecided.dir ?? index[key]?.dir,
        fingerprint: index[key]?.fingerprint,
        scannedAt: redecided.scannedAt,
        screening: {
          ...index[key]?.screening,
          signal: redecided.screening.signal, worst: redecided.screening.worst, score: redecided.screening.score, grade: redecided.screening.grade,
        },
        deps: { ...index[key]?.deps, worst: redecided.deps.worst },
        review: redecided.review,
        disposition: { action: redecided.disposition.action, reason: redecided.disposition.reason, detail: redecided.disposition.detail, executed: redecided.disposition.executed },
        upgrade: redecided.upgrade,
      });
      if (redecided.disposition.executed) {
        state.audit({ kind: 'agent-review-disable', name: pkg, verdict, confidence: entry.review.confidence, fingerprint: index[key]?.fingerprint });
      }
      const lowConfidenceNote = verdict === 'malicious' && redecided.disposition.reason === 'agent-malicious-low-confidence'
        ? '（置信度不足以自动禁用——补充证据后用 high 置信重判，或走设置页人工处置）'
        : '';
      const executionNote = redecided.disposition.executed
        ? '（已从 profile bundles 移除并隔离包目录，重启宿主后生效；可在设置页撤销）'
        : '';
      const text = `已记录 ${pkg} 的审读结论：${verdict}/${entry.review.confidence}。` +
        `处置：${ACTION_ICON[redecided.disposition.action] ?? redecided.disposition.action}${lowConfidenceNote}${executionNote}` +
        (redecided.upgrade?.upgrade ? `；升级建议：${redecided.upgrade.command}` : '');
      return { ok: true, package: pkg, disposition: redecided.disposition, upgrade: redecided.upgrade, text };
    },
  }));

  return () => { for (const d of disposers) { try { d(); } catch { /* dispose best-effort */ } } };
}
