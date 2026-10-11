/**
 * Call-time gate: tool attribution, the decision table, the three-option
 * question, stored decisions, on-demand scans and failure fallbacks.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  packageOfModule, ownerOfContext, createToolOwners, installToolAttribution, decideGate,
  createCallGate, choiceOf, buildQuestion, CHOICE_LABELS, QUESTION_ID, createSourceIndex, functionSourceOf,
  localeOf, uiLocalePreference,
} from '../lib/gate.js';
import { openState } from '../lib/state.js';
import { toolNamesOf } from '../lib/behavior.js';
import { riskOf } from '../lib/risk.js';
import { scanProfile } from '../lib/scan.js';
import { registerSecurityTools } from '../lib/tool.js';
import { _clearAuditCache } from '../lib/audit.js';

const HIGH = { level: 'high', reason: 'riskAdvisory' };
const NONE = { level: 'none', reason: 'riskClear' };

function freshState() {
  return openState(mkdtempSync(join(tmpdir(), 'security-gate-')));
}

function record(state, name, version, risk, extra = {}) {
  state.putScan(`${name}@${version}`, {
    name, version, risk, review: null, deps: { worst: risk.level === 'high' ? 'high' : 'none', advisories: [] },
    screening: { signal: { level: 'none' } }, ...extra,
  }, { replaceName: true });
}

const answer = (label) => ({ answers: [{ id: QUESTION_ID, selected: [label] }] });

/** A gate over a real state file with scripted user answers. */
function harness({ answers = [], version = '1.0.0', owner = 'risky-plugin', userQuestions } = {}) {
  const state = freshState();
  const owners = createToolOwners();
  owners.record({ name: 'risky_tool' }, owner);
  const asked = [];
  const scans = [];
  let currentVersion = version;
  const gate = createCallGate({
    state,
    owners,
    installedVersion: () => currentVersion,
    scan: async (name) => { scans.push(name); },
    userQuestions: userQuestions ?? (() => ({
      ask: async (request) => {
        asked.push(request);
        const next = answers.shift();
        if (next instanceof Error) throw next;
        return answer(next);
      },
    })),
    lang: 'zh',
  });
  const call = (name = 'risky_tool', extra = {}) => gate.handle(
    { name, callId: 'c1', agent: { id: 'agent' }, signal: new AbortController().signal, ...extra },
    async () => ({ kind: 'allow', via: 'next' }),
  );
  return { state, gate, call, asked, scans, setVersion: (v) => { currentVersion = v; } };
}

test('module specifiers map to package names; loader entries are found up the fiber chain', () => {
  assert.equal(packageOfModule('dsh-bots'), 'dsh-bots');
  assert.equal(packageOfModule('dsh-bots/lib/host.js'), 'dsh-bots');
  assert.equal(packageOfModule('@scope/pkg/lib/x'), '@scope/pkg');
  assert.equal(packageOfModule('./local.js'), null);
  assert.equal(packageOfModule('/abs/path.js'), null);
  const root = { fiber: null };
  const entryFiber = { entry: { options: { name: 'evil-plugin/lib/index.js' } }, parent: root };
  root.fiber = { parent: root };
  const child = { fiber: { parent: { fiber: { parent: { fiber: entryFiber } } } } };
  assert.equal(ownerOfContext(child), 'evil-plugin');
  assert.equal(ownerOfContext({ fiber: { parent: root } }), null);
  assert.equal(ownerOfContext(undefined), null);
});

test('register() attribution records the caller plugin and restores the registry on dispose', () => {
  class FakeRuntime {
    constructor() { this.defs = []; this.ctx = { fiber: { entry: { options: { name: '@deepseek-ai/dsh-tools' } } } }; }
    register(definition) { this.defs.push([definition.name, this.ctx]); return () => {}; }
  }
  const original = FakeRuntime.prototype.register;
  const tools = new FakeRuntime();
  const owners = createToolOwners();
  const dispose = installToolAttribution(tools, owners);
  // Cordis calls service methods with `this.ctx` bound to the caller context
  const caller = { fiber: { entry: { options: { name: 'evil-plugin' } } } };
  const shadow = Object.assign(Object.create(tools), { ctx: caller });
  const definition = { name: 'steal' };
  tools.register.call(shadow, definition);
  assert.equal(owners.ownerOf('steal', definition), 'evil-plugin');
  assert.equal(tools.defs.length, 1, 'the original register still runs');
  // a second install shares the wrapper; disposing both restores the method
  const second = installToolAttribution(tools, createToolOwners());
  dispose();
  assert.notEqual(FakeRuntime.prototype.register, original);
  second();
  assert.equal(FakeRuntime.prototype.register, original);
  assert.equal(installToolAttribution({}, owners), null);
});

test('the decision table: off, protected, blocked, unscanned, risk levels and version-bound allow', () => {
  const config = { mode: 'report-only', protectedNames: ['trusted-one'] };
  const entry = { name: 'p', version: '1.0.0', risk: HIGH };
  assert.equal(decideGate({ owner: 'p', config: { mode: 'off' }, policy: null, entry, version: '1.0.0' }).kind, 'pass');
  assert.equal(decideGate({ owner: null, config, policy: null, entry, version: '1.0.0' }).kind, 'pass');
  assert.equal(decideGate({ owner: '@deepseek-ai/dsh-base', config, policy: { decision: 'block' }, entry, version: '1' }).kind, 'pass');
  assert.equal(decideGate({ owner: 'trusted-one', config, policy: null, entry, version: '1.0.0' }).kind, 'pass');
  assert.equal(decideGate({ owner: 'p', config, policy: { decision: 'block' }, entry: null, version: '1.0.0' }).kind, 'deny');
  assert.equal(decideGate({ owner: 'p', config, policy: null, entry: null, version: '1.0.0' }).kind, 'scan');
  assert.equal(decideGate({ owner: 'p', config, policy: null, entry: { ...entry, risk: { level: 'risk', reason: 'x' } }, version: '1.0.0' }).kind, 'pass');
  assert.equal(decideGate({ owner: 'p', config, policy: null, entry, version: '1.0.0' }).kind, 'ask');
  assert.equal(decideGate({ owner: 'p', config, policy: { decision: 'allow', version: '1.0.0' }, entry, version: '1.0.0' }).kind, 'pass');
  assert.equal(decideGate({ owner: 'p', config, policy: { decision: 'allow', version: '0.9.0' }, entry, version: '1.0.0' }).kind, 'ask');
  // records written before risk was stored are classified on the fly
  assert.equal(decideGate({ owner: 'p', config, policy: null, entry: { name: 'p', deps: { worst: 'critical' } }, version: '1' }).kind, 'ask');
});

test('the question offers 允许一次 / 允许 / 禁用 with the risk evidence; answers parse in either language', () => {
  const entry = { deps: { advisories: [{ dep: 'minimist', severity: 'critical', title: 'Prototype Pollution', fixedIn: '1.2.6' }] } };
  const q = buildQuestion({ owner: 'evil-plugin', tool: 'steal', version: '9.9.9', entry, risk: HIGH }, 'zh');
  assert.deepEqual(q.options.map((o) => o.label), ['允许一次', '允许', '禁用']);
  assert.match(q.question, /evil-plugin@9\.9\.9.*steal/);
  assert.match(q.detail, /高危依赖漏洞/);
  assert.match(q.detail, /minimist: Prototype Pollution（修复于 1\.2\.6）/);
  assert.equal(q.multiSelect, false);
  const en = buildQuestion({ owner: 'evil-plugin', tool: 'steal', version: null, entry: null, risk: HIGH }, 'en');
  assert.deepEqual(en.options.map((o) => o.label), Object.values(CHOICE_LABELS.en));
  assert.equal(choiceOf(answer('允许一次')), 'once');
  assert.equal(choiceOf(answer('Allow')), 'allow');
  assert.equal(choiceOf(answer('禁用')), 'block');
  assert.equal(choiceOf({ answers: [{ id: QUESTION_ID, selected: [], custom: 'maybe' }] }), null);
});

test('allow once runs this call only and asks again next time', async () => {
  const h = harness({ answers: ['允许一次', '允许一次'] });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  assert.equal((await h.call()).via, 'next');
  assert.equal((await h.call()).via, 'next');
  assert.equal(h.asked.length, 2);
  assert.equal(h.state.getPolicy('risky-plugin'), null);
  assert.deepEqual(h.asked[0].agent, { id: 'agent' }, 'the question is routed to the calling agent');
});

test('allow is remembered for the installed version; a new version asks again', async () => {
  const h = harness({ answers: ['允许', '允许一次'] });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  assert.equal((await h.call()).via, 'next');
  assert.equal((await h.call()).via, 'next');
  assert.equal(h.asked.length, 1);
  assert.equal(h.state.getPolicy('risky-plugin').version, '1.0.0');
  h.setVersion('2.0.0');
  record(h.state, 'risky-plugin', '2.0.0', HIGH);
  await h.call();
  assert.equal(h.asked.length, 2);
  assert.ok(h.state.readAuditLog().some((e) => e.kind === 'policy-allow' && e.by === 'user-prompt'));
});

test('disable blocks this and every later call of the plugin until it is enabled again', async () => {
  const h = harness({ answers: ['禁用'] });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  const first = await h.call();
  assert.equal(first.kind, 'deny');
  assert.equal(first.info.code, 'PLUGIN_BLOCKED');
  assert.match(first.reason, /不要重试/);
  const second = await h.call();
  assert.equal(second.kind, 'deny');
  assert.equal(h.asked.length, 1);
  // a block holds across versions and even when the risk is gone
  h.setVersion('2.0.0');
  record(h.state, 'risky-plugin', '2.0.0', NONE);
  assert.equal((await h.call()).kind, 'deny');
  // the settings switch clears it
  h.state.setPolicy('risky-plugin', null);
  assert.equal((await h.call()).via, 'next');
});

test('an unanswered or free-text reply denies the call without storing anything', async () => {
  const h = harness({ answers: [undefined] });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  const denied = await h.call();
  assert.equal(denied.info.code, 'PLUGIN_NOT_ALLOWED');
  assert.equal(h.state.getPolicy('risky-plugin'), null);
});

test('low-risk, unattributed and protected calls pass without a question', async () => {
  const h = harness();
  record(h.state, 'risky-plugin', '1.0.0', NONE);
  assert.equal((await h.call()).via, 'next');
  assert.equal((await h.call('builtin_tool')).via, 'next');
  h.state.writeConfig({ mode: 'off' });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  assert.equal((await h.call()).via, 'next');
  assert.equal(h.asked.length, 0);
});

test('an unscanned plugin is scanned on demand before the decision', async () => {
  const h = harness({ answers: ['允许一次'] });
  const scanned = [];
  const gate = createCallGate({
    state: h.state, owners: (() => { const o = createToolOwners(); o.record({ name: 't' }, 'new-plugin'); return o; })(),
    installedVersion: () => '1.0.0',
    scan: async (name) => { scanned.push(name); record(h.state, name, '1.0.0', HIGH); },
    userQuestions: () => ({ ask: async () => answer('允许一次') }),
  });
  const result = await gate.handle({ name: 't', agent: {}, signal: new AbortController().signal }, async () => ({ via: 'next' }));
  assert.deepEqual(scanned, ['new-plugin']);
  assert.equal(result.via, 'next');
});

test('a plugin no scan can record is never passed silently: the user decides', async () => {
  const state = freshState();
  const asked = [];
  const owners = createToolOwners();
  owners.record({ name: 't' }, 'ghost');
  const gate = createCallGate({
    state, owners, installedVersion: () => '2.0.0', scan: async () => {},
    userQuestions: () => ({ ask: async (request) => { asked.push(request.questions[0]); return answer(asked.length === 1 ? '允许一次' : '允许'); } }),
  });
  const exec = () => ({ name: 't', agent: {}, signal: new AbortController().signal });
  assert.equal((await gate.handle(exec(), async () => ({ via: 'next' }))).via, 'next');
  assert.match(asked[0].question, /未完成安全检查的插件 ghost@2\.0\.0/);
  assert.match(asked[0].detail, /尚未完成安全检查/);
  // 允许 is remembered for this version even without a scan record
  await gate.handle(exec(), async () => ({ via: 'next' }));
  assert.equal((await gate.handle(exec(), async () => ({ via: 'next' }))).via, 'next');
  assert.equal(asked.length, 2);
  // without a question channel it falls back to host approval, not a pass
  const headless = createCallGate({ state: freshState(), owners, installedVersion: () => undefined, scan: async () => {}, userQuestions: () => undefined });
  assert.equal((await headless.handle({ name: 't', signal: new AbortController().signal }, async () => ({ via: 'next' }))).kind, 'ask');
});

test('an audit that ended unknown is retried at call time, at most once per window', async () => {
  const state = freshState();
  record(state, 'offline-plugin', '1.0.0', { level: 'risk', reason: 'riskIncomplete' }, { deps: { worst: 'none', unknown: true, advisories: [] } });
  const owners = createToolOwners();
  owners.record({ name: 't' }, 'offline-plugin');
  let clock = 0;
  let scans = 0;
  let online = false;
  const gate = createCallGate({
    state, owners, installedVersion: () => '1.0.0', now: () => clock, auditRetryMs: 1000,
    scan: async () => {
      scans += 1;
      if (online) record(state, 'offline-plugin', '1.0.0', HIGH, { deps: { worst: 'critical', unknown: false, advisories: [] } });
    },
    userQuestions: () => ({ ask: async () => answer('禁用') }),
  });
  const call = () => gate.handle({ name: 't', agent: {}, signal: new AbortController().signal }, async () => ({ via: 'next' }));
  assert.equal((await call()).via, 'next', 'still offline: risk, not high');
  await call();
  assert.equal(scans, 1, 'no second retry inside the window');
  clock = 2000;
  online = true;
  assert.equal((await call()).kind, 'deny', 'the retried audit found the advisory and the user disabled it');
  assert.equal(scans, 2);
});

test('tools registered before the gate started are attributed from scan-record tool names', async () => {
  const h = harness({ answers: ['禁用'] });
  record(h.state, 'early-plugin', '1.0.0', HIGH, { tools: ['early_tool'] });
  const gate = createCallGate({
    state: h.state, owners: createToolOwners(), installedVersion: () => '1.0.0', scan: async () => {},
    userQuestions: () => ({ ask: async () => answer('禁用') }),
  });
  assert.equal(await gate.ownerOf({ name: 'early_tool' }), 'early-plugin');
  assert.equal((await gate.handle({ name: 'early_tool', agent: {}, signal: new AbortController().signal }, async () => ({}))).kind, 'deny');
  // a name claimed by two packages is ambiguous and not attributed
  record(h.state, 'other-plugin', '1.0.0', NONE, { tools: ['early_tool'] });
  assert.equal(await gate.ownerOf({ name: 'early_tool' }), null);
});

test('tools registered before the gate are attributed by their execute source, before any scan record exists', async () => {
  const definition = {
    name: 'late_seen_tool',
    async execute(args) { return { echo: String(args?.text ?? '') + 'unique-marker-7' }; },
  };
  const source = functionSourceOf(definition);
  let loads = 0;
  const index = createSourceIndex(async () => {
    loads += 1;
    return [
      { name: 'fresh-plugin', texts: [`export const tool = { name: 'late_seen_tool', ${source} };`] },
      { name: 'unrelated', texts: ['export const x = 1;'] },
    ];
  });
  assert.equal(await index.ownerOf(definition), 'fresh-plugin');
  assert.equal(await index.ownerOf(definition), 'fresh-plugin');
  assert.equal(loads, 1, 'the package index is built once');
  assert.equal(functionSourceOf({ execute: Math.max }), null, 'native code never matches');
  assert.equal(functionSourceOf({ execute: () => 1 }), null, 'trivial bodies are too short to attribute');
  const ambiguous = createSourceIndex(async () => [{ name: 'a', texts: [source] }, { name: 'b', texts: [source] }]);
  assert.equal(await ambiguous.ownerOf(definition), null);
  index.invalidate();
  await index.ownerOf(definition);
  assert.equal(loads, 2);

  // end to end through the gate: no wrapper record, no scan record → scan, then ask
  const state = freshState();
  const scanned = [];
  const gate = createCallGate({
    state, owners: createToolOwners(), lookup: () => definition, sources: index,
    installedVersion: () => '1.0.0',
    scan: async (name) => { scanned.push(name); record(state, name, '1.0.0', HIGH); },
    userQuestions: () => ({ ask: async () => answer('禁用') }),
  });
  const result = await gate.handle({ name: 'late_seen_tool', agent: {}, signal: new AbortController().signal }, async () => ({ via: 'next' }));
  assert.deepEqual(scanned, ['fresh-plugin']);
  assert.equal(result.kind, 'deny');
});

test('允许一次 admits only the call that asked; concurrent calls each get their own answer', async () => {
  let asks = 0;
  const gates = [];
  const h = harness({ userQuestions: () => ({ ask: async () => {
    asks += 1;
    await new Promise((resolve) => gates.push(resolve));
    return answer('允许一次');
  } }) });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  const pending = [h.call('risky_tool', { callId: 'a' }), h.call('risky_tool', { callId: 'b' }), h.call('risky_tool', { callId: 'c' })];
  // release questions one at a time as they appear
  for (let i = 0; i < 3; i += 1) {
    while (gates.length === 0) await new Promise((r) => setImmediate(r));
    gates.shift()();
  }
  const results = await Promise.all(pending);
  assert.equal(asks, 3, 'one question per call');
  assert.ok(results.every((r) => r.via === 'next'));
  assert.equal(h.state.getPolicy('risky-plugin'), null);
});

test('a stored 允许 settles every call that waited on the same question', async () => {
  let release;
  const gateOpen = new Promise((resolve) => { release = resolve; });
  let asks = 0;
  const h = harness({ userQuestions: () => ({ ask: async () => { asks += 1; await gateOpen; return answer('允许'); } }) });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  const pending = [h.call(), h.call(), h.call()];
  release();
  const results = await Promise.all(pending);
  assert.equal(asks, 1);
  assert.ok(results.every((r) => r.via === 'next'));
});

test('without a question channel the gate falls back to the host approval prompt; aborts cancel', async () => {
  const delegated = Object.assign(new Error('owned child'), { code: 'DELEGATED_CALLER' });
  const h = harness({ answers: [delegated] });
  record(h.state, 'risky-plugin', '1.0.0', HIGH);
  const fallback = await h.call();
  assert.equal(fallback.kind, 'ask');
  assert.match(fallback.displayReason.zh, /允许|高危/);
  assert.match(fallback.displayReason.en, /High-risk plugin risky-plugin/);
  const none = harness({ userQuestions: () => undefined });
  record(none.state, 'risky-plugin', '1.0.0', HIGH);
  assert.equal((await none.call()).kind, 'ask');
  const controller = new AbortController();
  const aborted = harness({ userQuestions: () => ({ ask: async () => { controller.abort(); throw Object.assign(new Error('aborted'), { code: 'ASK_ABORTED' }); } }) });
  record(aborted.state, 'risky-plugin', '1.0.0', HIGH);
  assert.equal((await aborted.call('risky_tool', { signal: controller.signal })).kind, 'cancel');
});

test('internal failures fail open, but a stored block still denies', async () => {
  const h = harness();
  const broken = createCallGate({
    state: { ...h.state, readScanIndex: () => ({}), readConfig: () => { throw new Error('disk'); }, getPolicy: h.state.getPolicy.bind(h.state) },
    owners: (() => { const o = createToolOwners(); o.record({ name: 't' }, 'p'); return o; })(),
    installedVersion: () => '1', scan: async () => {}, userQuestions: () => undefined,
  });
  const exec = { name: 't', signal: new AbortController().signal };
  assert.equal((await broken.handle(exec, async () => ({ via: 'next' }))).via, 'next');
  h.state.setPolicy('p', { decision: 'block' });
  assert.equal((await broken.handle(exec, async () => ({ via: 'next' }))).kind, 'deny');
});

test('tool names are extracted from register()/defineTool() shapes in the package own code', () => {
  const target = { files: [
    { rel: 'lib/index.js', text: "ctx.tools.register({ name: 'send_report', description: 'x', parameters: {}, async execute() {} });\nconst meta = { name: 'not-a-tool' };" },
    { rel: 'lib/more.js', text: 'export default defineTool({ name: `fetch_data`, parameters: {}, execute: () => 1 })' },
    { rel: 'node_modules/dep/index.js', text: "x({ name: 'vendor_tool', description: '', execute() {} })" },
  ] };
  const scope = (rel) => rel.startsWith('node_modules/') ? 'dependency' : 'runtime';
  assert.deepEqual(toolNamesOf(target, scope), ['fetch_data', 'send_report']);
});

test('host and page agree on the three-level risk rule', async () => {
  const { readFileSync } = await import('node:fs');
  const { runInNewContext } = await import('node:vm');
  let page;
  runInNewContext(readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8'), {
    window: { __ModuleLoader__: { load: ({ factory }) => { page = factory(() => ({ createElement: () => null })); } } },
    setTimeout: () => 0,
  });
  const base = { name: 'p', screening: { signal: { level: 'none' } }, findings: [], deps: { worst: 'none' }, review: null };
  const cases = [
    base,
    { ...base, deps: { worst: 'high' } },
    { ...base, depsAdvisories: [{ severity: 'critical' }] },
    { ...base, deps: { worst: 'low' } },
    { ...base, deps: { worst: 'none', unknown: true } },
    { ...base, deps: { worst: 'none', errors: ['x'] } },
    { ...base, filesTruncated: true },
    { ...base, review: { verdict: 'malicious', confidence: 'high' } },
    { ...base, review: { verdict: 'malicious', confidence: 'low' } },
    { ...base, review: { verdict: 'benign', confidence: 'high' }, screening: { signal: { level: 'high' } } },
    { ...base, screening: { signal: { level: 'high' } } },
    { ...base, findings: [{ kind: 'capability', severity: 'high' }] },
    { ...base, findings: [{ kind: 'behavior', scope: 'runtime', severity: 'critical' }] },
  ];
  for (const plugin of cases) assert.equal(page.pluginRisk(plugin).level, riskOf(plugin).level, JSON.stringify(plugin));
});

// ---------------------------------------------------------------------------
// scan + tool integration

function makeProfile() {
  const home = mkdtempSync(join(tmpdir(), 'security-gate-int-'));
  const profileRoot = join(home, 'profiles', 'fixture');
  const globalRoot = join(home, 'global');
  mkdirSync(join(globalRoot, 'node_modules', '@deepseek-ai'), { recursive: true });
  mkdirSync(profileRoot, { recursive: true });
  writeFileSync(join(profileRoot, 'package.json'), JSON.stringify({ name: 'p', version: '0.0.0', dsh: { profile: { bundles: ['tool-plugin', 'other-plugin'] } } }));
  const write = (name, files) => {
    const dir = join(profileRoot, 'node_modules', name);
    mkdirSync(join(dir, 'lib'), { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', main: 'lib/index.js', dependencies: { minimist: '^1.0.0' } }));
    for (const [rel, text] of Object.entries(files)) writeFileSync(join(dir, rel), text);
    mkdirSync(join(dir, 'node_modules', 'minimist'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'minimist', 'package.json'), JSON.stringify({ name: 'minimist', version: '1.2.0' }));
  };
  write('tool-plugin', { 'lib/index.js': "export function apply(ctx) { ctx.tools.register({ name: 'plugin_tool', description: 'd', parameters: {}, async execute() { return 1; } }); }" });
  write('other-plugin', { 'lib/index.js': 'export const x = 1;' });
  return { profileRoot, globalRoot, dshHome: join(home, '.dsh') };
}

const criticalFetch = async (url) => String(url).includes('/advisories/bulk')
  ? { ok: true, status: 200, json: async () => ({ minimist: [{ id: 1, url: 'https://github.com/advisories/GHSA-x', title: 'Prototype Pollution', severity: 'critical', vulnerable_versions: '<1.2.6' }] }) }
  : { ok: false, status: 404, json: async () => ({}) };

test('scan records the risk level, declared tools and policy; only= scans one plugin without a full report', async () => {
  _clearAuditCache();
  const env = makeProfile();
  const state = openState(env.dshHome);
  const partial = await scanProfile(env, {}, { only: ['tool-plugin'], fetchImpl: criticalFetch });
  assert.deepEqual(partial.plugins.map((p) => p.name), ['tool-plugin']);
  const entry = state.findScan('tool-plugin', '1.0.0');
  assert.equal(entry.risk.level, 'high');
  assert.deepEqual(entry.tools, ['plugin_tool']);
  state.setPolicy('tool-plugin', { decision: 'block' });
  const full = await scanProfile(env, {}, { fetchImpl: criticalFetch });
  const row = full.plugins.find((p) => p.name === 'tool-plugin');
  assert.equal(row.cached, true);
  assert.equal(row.risk.level, 'high');
  assert.equal(row.policy.decision, 'block');
  assert.equal(full.summary.risk.high, 2);
});

test('a forced rescan keeps the agent review of unchanged content; security_review reports the risk level', async () => {
  _clearAuditCache();
  const env = makeProfile();
  const saved = { DSH_HOME: process.env.DSH_HOME, DSH_PROFILE_DIR: process.env.DSH_PROFILE_DIR, DSH_GLOBAL_ROOT: process.env.DSH_GLOBAL_ROOT };
  process.env.DSH_HOME = env.dshHome;
  process.env.DSH_PROFILE_DIR = env.profileRoot;
  process.env.DSH_GLOBAL_ROOT = env.globalRoot;
  try {
    await scanProfile(env, {}, { fetchImpl: criticalFetch });
    const registered = [];
    registerSecurityTools({ get: (key) => key === 'tools' ? { register: (def) => { registered.push(def); return () => {}; } } : undefined });
    const review = registered.find((d) => d.name === 'security_review');
    const result = await review.execute({ package: 'other-plugin', verdict: 'benign', confidence: 'high', reason: 'checked' });
    assert.equal(result.ok, true, result.text);
    assert.match(result.text, /风险：高危/, 'dependency advisories keep the plugin high risk after a benign review');
    const state = openState(env.dshHome);
    assert.equal(state.findScan('other-plugin').review.verdict, 'benign');
    await scanProfile(env, {}, { force: true, fetchImpl: criticalFetch });
    assert.equal(state.findScan('other-plugin').review?.verdict, 'benign', 'force re-screens but keeps the review');
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test('the bundled review skill registers with the host skill registry', async () => {
  const { registerBundledSkill, parseSkill, SKILL_PATH } = await import('../lib/skill.js');
  const registered = [];
  const dispose = registerBundledSkill({ register: (skill) => { registered.push(skill); return () => {}; } });
  assert.equal(typeof dispose, 'function');
  assert.equal(registered[0].name, 'dsh-plugin-security');
  assert.equal(registered[0].source, 'runtime');
  assert.equal(registered[0].path, SKILL_PATH);
  assert.match(registered[0].description, /security_review/);
  assert.match(registered[0].content, /## 五问/);
  assert.doesNotMatch(registered[0].content, /^---/);
  assert.equal(registerBundledSkill(undefined), null);
  assert.throws(() => parseSkill('no frontmatter'));
});

test('host text follows DSH_LOCALE, then the dsh UI language, then the process locale', async () => {
  const loader = (preference) => ({ *entries() {
    yield { options: { id: 'other', name: 'x', config: {} } };
    yield { options: { id: 'locale', name: '@deepseek-ai/dsh-client-locale', config: preference === undefined ? {} : { preference } } };
  } });
  assert.equal(uiLocalePreference(loader('zh')), 'zh');
  assert.equal(uiLocalePreference(loader(undefined)), undefined);
  assert.equal(uiLocalePreference({ entries() { throw new Error('gone'); } }), undefined);
  assert.equal(uiLocalePreference(undefined), undefined);
  assert.equal(localeOf({ LANG: 'en_US.UTF-8' }, 'zh'), 'zh', 'the UI preference beats the process locale');
  assert.equal(localeOf({ LANG: 'zh_CN.UTF-8' }, 'en'), 'en');
  assert.equal(localeOf({ DSH_LOCALE: 'en', LANG: 'zh_CN.UTF-8' }, 'zh'), 'en', 'DSH_LOCALE overrides everything');
  assert.equal(localeOf({ LANG: 'zh_CN.UTF-8' }), 'zh');
  // read per question, so a switch in Settings applies to the next one
  let current = 'en';
  const asked = [];
  const state = freshState();
  record(state, 'p', '1', HIGH);
  const owners = createToolOwners();
  owners.record({ name: 't' }, 'p');
  const gate = createCallGate({ state, owners, installedVersion: () => '1', scan: async () => {}, lang: () => current,
    userQuestions: () => ({ ask: async (r) => { asked.push(r.questions[0].options[0].label); return answer(asked.length === 1 ? 'Allow once' : '允许一次'); } }) });
  const call = () => gate.handle({ name: 't', agent: {}, signal: new AbortController().signal }, async () => ({ via: 'next' }));
  await call();
  current = 'zh';
  await call();
  assert.deepEqual(asked, ['Allow once', '允许一次']);
});
