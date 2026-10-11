import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

function client(overrides = {}) {
  let exports;
  const react = { createElement: (type, props, ...children) => ({ type, props: props ?? {}, children: children.flat(Infinity) }), ...overrides };
  runInNewContext(readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8'), {
    window: { __ModuleLoader__: { load: ({ factory }) => { exports = factory((name) => { assert.equal(name, 'react'); return react; }); } } },
    setTimeout: () => 0,
  });
  return exports;
}
function render(node) {
  if (node === null || node === undefined || node === false) return '';
  if (typeof node !== 'object') return String(node);
  if (typeof node.type === 'function') return render(node.type(node.props));
  return `<${node.type} class="${node.props.className ?? ''}">${node.children.map(render).join('')}</${node.type}>`;
}
const plugin = { name: 'example-plugin', version: '1', source: 'profile', rowStatus: null, findings: [],
  deps: { worst: 'none' }, screening: { grade: 'F', score: 0, signal: { level: 'critical' } }, disposition: { action: 'review' }, review: null };

test('an unreviewed F cache entry renders its real review state with SVG icons, without a grade or safety score', () => {
  const c = client();
  const html = render(c.PluginCard((key) => c.locales.zh[key] ?? key, {}, false, plugin, false));
  assert.match(html, /未审读/);
  assert.match(html, /有风险/);
  assert.match(html, /<svg/);
  assert.doesNotMatch(html, /ps-grade|ps-score|⛔|🔁|⚠|✅/);
});

test('capability observations identify their source without calling a test fixture a severe vulnerability', () => {
  const c = client();
  const html = render(c.Finding((key) => c.locales.zh[key] ?? key, { rules: {} }, false,
    { ruleId: 'code-exec', kind: 'capability', scope: 'support', severity: 'info', evidence: [{ ref: 'test/example.js:1', snippet: 'new Function(code)' }] }));
  assert.match(html, /能力记录/);
  assert.match(html, /ps-finding-capability/);
  assert.match(html, /测试 \/ 文档/);
  assert.doesNotMatch(html, /高危|严重|优先核实/);
});

test('only a high-confidence benign review displays a legitimate-use conclusion', () => {
  const c = client();
  const t = (key) => c.locales.zh[key] ?? key;
  const low = render(c.PluginCard(t, {}, false, { ...plugin, review: { verdict: 'benign', confidence: 'low' } }, false));
  const high = render(c.PluginCard(t, {}, false, { ...plugin, review: { verdict: 'benign', confidence: 'high' } }, false));
  assert.doesNotMatch(low, /已审读 · 用途合理/);
  assert.match(high, /已审读 · 用途合理/);
});

function nodes(node) {
  if (!node || typeof node !== 'object') return [];
  if (typeof node.type === 'function') return nodes(node.type(node.props));
  return [node, ...node.children.flatMap(nodes)];
}
function pageHarness() {
  let report = { mode: 'report-only', generatedAt: '2026-10-10', durationMs: 1,
    config: { mode: 'report-only', autoDisableAt: 'critical', autoUpgrade: false, protectedNames: [] },
    summary: { targets: 3, fresh: 3, cached: 0 }, notes: { zh: '', en: '' }, rules: {},
    plugins: [
      { ...plugin, name: 'alpha-plugin', screening: { signal: { level: 'none' } } },
      { ...plugin, name: 'beta-plugin', deps: { worst: 'high' } },
      { ...plugin, name: '@deepseek-ai/dsh-base', trusted: true },
    ] };
  const states = [null, report, false, false, '', '', 'all', new Set(), '', '', false];
  let hook = 0;
  const c = client({ useMemo: (fn) => fn(), useCallback: (fn) => fn, useEffect: () => {},
    useState: () => { const i = hook++; return [states[i], (value) => { states[i] = typeof value === 'function' ? value(states[i]) : value; }]; } });
  const calls = [];
  c.apply({ get: (key) => key === 'connection' ? { rpc: { call: async (_base, method, payload) => {
    const request = payload.args.request;
    calls.push({ method, request });
    if (method === 'security/policy') {
      const policy = request.decision === null ? null : { decision: request.decision, version: '1', by: 'settings' };
      report = { ...report, plugins: report.plugins.map((p) => p.name === request.name ? { ...p, policy } : p) };
      return { ok: true, value: { ok: true, name: request.name, policy } };
    }
    if (method === 'security/configure') {
      report = { ...report, config: { ...report.config, ...request } };
      report.mode = report.config.mode;
      return { ok: true, value: { config: report.config } };
    }
    return { ok: true, value: { ...report, plugins: report.plugins.map((p) => ({ ...p,
      trusted: p.name.startsWith('@deepseek-ai/') || report.config.protectedNames.includes(p.name) })) } };
  } } } : undefined });
  const tree = () => { hook = 0; return c.SecurityPage({ t: (key, params) => String(c.locales.zh[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => params?.[k] ?? '') }); };
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  return { c, tree, calls, settle };
}

test('restored config, export toolbar, risk tabs and compact per-plugin actions render in the actual page', () => {
  const h = pageHarness();
  const tree = h.tree();
  const html = render(tree);
  assert.match(html, /自动停用阈值/);
  assert.match(html, /自动升级建议/);
  assert.doesNotMatch(html, /autoUpgradeLabel|ps-threats|ps-wl/);
  assert.ok(html.indexOf('导出 JSON') < html.indexOf('ps-tabs'));
  const tabs = nodes(tree).filter((n) => n.props.role === 'tab');
  assert.equal(tabs.length, 8);
  for (const label of ['全部', '高危', '有风险', '无风险', '已禁用', '停用', '升级', '白名单']) assert.ok(tabs.some((n) => render(n).includes(label)));
  const head = nodes(tree).find((n) => n.props.className === 'ps-card-head');
  assert.match(render(head), /alpha-plugin.*加入白名单.*卸载/);
  assert.ok(nodes(head).some((n) => n.type === 'button' && n.props.className.includes('ps-btn-small')));
});

test('tab switching and search combine to filter actual plugin rows', () => {
  const h = pageHarness();
  nodes(h.tree()).find((n) => n.props.id === 'ps-tab-high').props.onClick();
  let tree = h.tree();
  let list = nodes(tree).find((n) => n.props.id === 'ps-plugin-list');
  assert.match(render(list), /beta-plugin/);
  assert.doesNotMatch(render(list), /alpha-plugin|@deepseek-ai/);
  nodes(tree).find((n) => n.props.type === 'search').props.onChange({ target: { value: 'ALPHA' } });
  list = nodes(h.tree()).find((n) => n.props.id === 'ps-plugin-list');
  assert.doesNotMatch(render(list), /beta-plugin/);
  nodes(h.tree()).find((n) => n.props.id === 'ps-tab-none').props.onClick();
  list = nodes(h.tree()).find((n) => n.props.id === 'ps-plugin-list');
  assert.match(render(list), /alpha-plugin/);
  assert.doesNotMatch(render(list), /beta-plugin/);
});

test('row whitelist add/remove round-trips through configure and refresh; default protection is not removable', async () => {
  const h = pageHarness();
  const head = nodes(h.tree()).find((n) => n.props.className === 'ps-card-head');
  nodes(head).find((n) => n.type === 'button' && render(n).includes('加入白名单')).props.onClick();
  await h.settle();
  assert.deepEqual(Array.from(h.calls.find((call) => call.method === 'security/configure').request.protectedNames), ['alpha-plugin']);
  nodes(h.tree()).find((n) => n.props.id === 'ps-tab-whitelist').props.onClick();
  const list = nodes(h.tree()).find((n) => n.props.id === 'ps-plugin-list');
  assert.match(render(list), /alpha-plugin.*移出白名单/);
  const protectedRow = nodes(list).filter((n) => n.props.className === 'ps-card-head').find((n) => render(n).includes('@deepseek-ai'));
  const defaultButton = nodes(protectedRow).find((n) => n.type === 'button' && render(n).includes('默认保护'));
  assert.equal(defaultButton.props.disabled, true);
  nodes(list).find((n) => n.type === 'button' && render(n).includes('移出白名单')).props.onClick();
  await h.settle();
  const nextList = nodes(h.tree()).find((n) => n.props.id === 'ps-plugin-list');
  assert.doesNotMatch(render(nextList), /alpha-plugin/);
  assert.match(render(nextList), /@deepseek-ai/);
});

test('whitelist tab selection adds the selected installed plugin', async () => {
  const h = pageHarness();
  nodes(h.tree()).find((n) => n.props.id === 'ps-tab-whitelist').props.onClick();
  nodes(h.tree()).find((n) => n.type === 'select').props.onChange({ target: { value: 'beta-plugin' } });
  const picker = nodes(h.tree()).find((n) => n.props.className === 'ps-whitelist-picker');
  nodes(picker).find((n) => n.type === 'button').props.onClick();
  await h.settle();
  assert.ok(h.calls.some((call) => call.method === 'security/configure' && call.request.protectedNames.includes('beta-plugin')));
});

test('risk labels do not turn capabilities or incomplete dependency checks into a clean bill of health', () => {
  const c = client();
  const normal = { ...plugin, screening: { signal: { level: 'none' } }, findings: [{ kind: 'capability', severity: 'medium' }] };
  assert.equal(c.pluginRisk(normal).level, 'none');
  assert.equal(c.pluginRisk({ ...normal, deps: { worst: 'none', results: { dep: { unknown: true } } } }).level, 'risk');
  assert.equal(c.pluginRisk({ ...normal, filesTruncated: true }).level, 'risk');
  assert.equal(c.pluginRisk({ ...normal, deps: { worst: 'high' } }).level, 'high');
  assert.equal(c.pluginRisk({ ...normal, review: { verdict: 'malicious', confidence: 'high' } }).level, 'high');
  assert.equal(c.pluginRisk({ ...normal, review: { verdict: 'benign', confidence: 'low' } }).level, 'risk');
  assert.equal(c.matchesFilter({ ...normal, trusted: true }, 'none', {}), false);
  const report = { plugins: [], config: { protectedNames: ['not-installed'] } };
  assert.equal(c.listPlugins(report)[0].notInstalled, true);
});

test('restored config controls persist threshold and upgrade settings through the existing RPC contract', async () => {
  const h = pageHarness();
  const configRow = nodes(h.tree()).find((n) => n.props.className === 'ps-config-row' && render(n).includes('自动停用阈值'));
  nodes(configRow).find((n) => n.type === 'button' && render(n).includes('从不')).props.onClick();
  await h.settle();
  assert.ok(h.calls.some((call) => call.method === 'security/configure' && call.request.autoDisableAt === 'never'));
  const upgradeRow = nodes(h.tree()).find((n) => n.props.className === 'ps-config-row' && render(n).includes('自动升级建议'));
  nodes(upgradeRow).find((n) => n.type === 'button' && render(n).includes('开启')).props.onClick();
  await h.settle();
  assert.ok(h.calls.some((call) => call.method === 'security/configure' && call.request.autoUpgrade === true));
  const nextRow = nodes(h.tree()).find((n) => n.props.className === 'ps-config-row' && render(n).includes('自动停用阈值'));
  assert.equal(nodes(nextRow).find((n) => n.type === 'button' && render(n).includes('从不')).props['aria-pressed'], 'true');
});

test('settings enable / disable / reset drive the per-plugin call gate through security/policy', async () => {
  const h = pageHarness();
  const row = () => nodes(h.tree()).filter((n) => n.props.className === 'ps-card').find((n) => render(n).includes('beta-plugin'));
  const buttons = (node) => nodes(node).filter((n) => n.type === 'button').map((n) => ({ n, text: render(n).replace(/<[^>]+>/g, '') }));
  const press = (text) => buttons(row()).find((b) => b.text === text).n.props.onClick();
  // high risk without a decision: both enable (pre-approve) and disable are offered
  assert.deepEqual(buttons(row()).map((b) => b.text).filter((t) => ['启用', '禁用', '恢复默认'].includes(t)), ['启用', '禁用']);
  press('禁用');
  await h.settle();
  assert.deepEqual(JSON.parse(JSON.stringify(h.calls.at(-1))), { method: 'security/policy', request: { name: 'beta-plugin', decision: 'block' } });
  assert.match(render(row()), /调用已禁用/);
  assert.match(render(row()), /所有工具调用都会被拦截/);
  assert.deepEqual(buttons(row()).map((b) => b.text).filter((t) => ['启用', '禁用', '恢复默认'].includes(t)), ['启用', '恢复默认']);
  nodes(h.tree()).find((n) => n.props.id === 'ps-tab-blocked').props.onClick();
  assert.match(render(nodes(h.tree()).find((n) => n.props.id === 'ps-plugin-list')), /beta-plugin/);
  nodes(h.tree()).find((n) => n.props.id === 'ps-tab-all').props.onClick();
  press('启用');
  await h.settle();
  assert.deepEqual(JSON.parse(JSON.stringify(h.calls.at(-1).request)), { name: 'beta-plugin', decision: 'allow' });
  press('恢复默认');
  await h.settle();
  assert.deepEqual(JSON.parse(JSON.stringify(h.calls.at(-1).request)), { name: 'beta-plugin', decision: null });
  // whitelisted / protected rows skip the gate: no switch
  const protectedRow = nodes(h.tree()).filter((n) => n.props.className === 'ps-card').find((n) => render(n).includes('@deepseek-ai'));
  assert.ok(!buttons(protectedRow).some((b) => ['启用', '禁用'].includes(b.text)));
});

test('the page prefers the host-recorded risk level', () => {
  const c = client();
  const normal = { ...plugin, screening: { signal: { level: 'none' } }, findings: [] };
  assert.equal(c.pluginRisk({ ...normal, risk: { level: 'high', reason: 'riskAdvisory' } }).level, 'high');
  assert.equal(c.pluginRisk({ ...normal, deps: { worst: 'none', unknown: true } }).level, 'risk');
});

test('a bundle disabled on the native Plugins page shows as disabled here, with Enable', () => {
  const c = client();
  const t = (key) => c.locales.zh[key] ?? key;
  const disabled = { ...plugin, screening: { signal: { level: 'none' } }, bundle: { enabled: false } };
  const html = render(c.PluginCard(t, {}, false, disabled, false, null, null, null, null, null, null, false, () => {}));
  assert.match(html, /已禁用（插件管理）/);
  assert.match(html, /与「插件」页同步/);
  assert.match(html, />启用</);
  assert.equal(c.matchesFilter(disabled, 'blocked', {}), true);
  assert.equal(c.matchesFilter({ ...disabled, bundle: { enabled: true } }, 'blocked', {}), false);
});
