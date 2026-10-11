/**
 * Plugin-manager sync: disable / enable / uninstall go through the same host
 * service as the native Plugins page, and its bundle selection is what the
 * gate and the settings page read.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createManagerBridge, setActiveManager, disablePlugin, enablePlugin, removePlugin, reconcileBlocks } from '../lib/manager.js';
import { createCallGate, createToolOwners, decideGate, QUESTION_ID } from '../lib/gate.js';
import { openState } from '../lib/state.js';
import { SecurityRemote } from '../lib/remote.js';

/** In-memory stand-in for ctx.pluginManager with the native call shapes. */
function fakeManager(bundles, { fail = {} } = {}) {
  const calls = [];
  const state = new Map(bundles.map((b) => [b.name, { removable: true, installed: true, ...b }]));
  return {
    calls,
    state,
    async listBundles() { calls.push(['listBundles']); return [...state.values()].map((b) => ({ ...b })); },
    async setBundleEnabled(name, enabled) {
      calls.push(['setBundleEnabled', name, enabled]);
      if (fail[name]) return { changed: false, application: 'failed', stage: 'enable', target: name, error: { code: fail[name] } };
      state.get(name).enabled = enabled;
      return { changed: true, application: 'applied', stage: 'enable', target: name, enabled };
    },
    async removeBundle(name) {
      calls.push(['removeBundle', name]);
      state.delete(name);
      return { changed: true, application: 'restart-required', stage: 'remove', target: name };
    },
  };
}

function profileWith(bundles) {
  const home = mkdtempSync(join(tmpdir(), 'security-manager-'));
  const profileRoot = join(home, 'profiles', 'web');
  mkdirSync(profileRoot, { recursive: true });
  writeFileSync(join(profileRoot, 'package.json'), JSON.stringify({ name: 'p', dsh: { profile: { bundles } } }));
  return { home, profileRoot, globalRoot: join(home, 'global'), dshHome: join(home, '.dsh') };
}

test('the bridge caches the bundle list, maps change results, and refreshes after a change', async () => {
  let clock = 0;
  const manager = fakeManager([{ name: 'a', enabled: true }, { name: 'b', enabled: true }], { fail: { b: 'not-removable' } });
  const bridge = createManagerBridge(manager, { ttlMs: 1000, now: () => clock });
  assert.equal((await bridge.bundleOf('a')).enabled, true);
  await bridge.bundleOf('a');
  assert.equal(manager.calls.filter(([c]) => c === 'listBundles').length, 1, 'cached within the TTL');
  assert.deepEqual(await bridge.setEnabled('a', false), { ok: true, application: 'applied', restartRequired: false, error: null });
  assert.equal((await bridge.bundleOf('a')).enabled, false, 'a change invalidates the cache');
  assert.equal((await bridge.setEnabled('b', false)).ok, false);
  clock = 5000;
  await bridge.bundles();
  assert.equal(await bridge.bundleOf('missing'), null);
  assert.equal(createManagerBridge(undefined), null);
});

test('disable / enable / uninstall use the plugin manager for its bundles and fall back otherwise', async () => {
  const env = profileWith(['managed', 'legacy']);
  const manager = fakeManager([{ name: 'managed', enabled: true }]);
  const reset = setActiveManager(createManagerBridge(manager));
  try {
    const off = await disablePlugin(env.profileRoot, 'managed', undefined);
    assert.equal(off.via, 'plugin-manager');
    assert.equal(off.disabled, true);
    assert.deepEqual(manager.calls.find(([c]) => c === 'setBundleEnabled'), ['setBundleEnabled', 'managed', false]);
    assert.deepEqual(JSON.parse(readFileSync(join(env.profileRoot, 'package.json'), 'utf8')).dsh.profile.bundles, ['managed', 'legacy'],
      'the manager owns the profile edit; nothing is written behind its back');
    assert.equal((await disablePlugin(env.profileRoot, 'managed', undefined)).alreadyDisabled, true);
    // an old quarantine rename is released before enabling through the manager
    const dir = join(env.home, 'node_modules', 'managed');
    mkdirSync(`${dir}.security-quarantined`, { recursive: true });
    const on = await enablePlugin(env.profileRoot, 'managed', dir);
    assert.equal(on.via, 'plugin-manager');
    assert.equal(on.released, true);
    assert.ok(existsSync(dir));
    assert.equal(manager.state.get('managed').enabled, true);
    // not a manager bundle → legacy profile edit
    const legacy = await disablePlugin(env.profileRoot, 'legacy', undefined);
    assert.equal(legacy.via, 'profile-file');
    assert.deepEqual(JSON.parse(readFileSync(join(env.profileRoot, 'package.json'), 'utf8')).dsh.profile.bundles, ['managed']);
    assert.equal(await removePlugin('legacy'), null);
    const removed = await removePlugin('managed');
    assert.deepEqual(removed, { removed: true, application: 'restart-required', restartRequired: true, reason: null, via: 'plugin-manager' });
  } finally {
    reset();
  }
});

test('the gate denies a bundle deselected on the native page, even with a stored allow', () => {
  const config = { mode: 'report-only' };
  const entry = { name: 'p', version: '1', risk: { level: 'none', reason: 'riskClear' } };
  assert.equal(decideGate({ owner: 'p', config, policy: { decision: 'allow', version: '1' }, entry, version: '1', bundle: { enabled: false } }).kind, 'deny');
  assert.equal(decideGate({ owner: 'p', config, policy: null, entry, version: '1', bundle: { enabled: true } }).kind, 'pass');
  assert.equal(decideGate({ owner: '@deepseek-ai/x', config, policy: null, entry, version: '1', bundle: { enabled: false } }).kind, 'pass');
});

test('禁用 in the question disables through the plugin manager; the gate block is only the fallback', async () => {
  const high = { level: 'high', reason: 'riskAdvisory' };
  const run = async (disable) => {
    const state = openState(mkdtempSync(join(tmpdir(), 'security-manager-gate-')));
    state.putScan('p@1', { name: 'p', version: '1', risk: high, deps: { advisories: [] } });
    const owners = createToolOwners();
    owners.record({ name: 't' }, 'p');
    let bundle = { enabled: true };
    const disabled = [];
    const gate = createCallGate({
      state, owners, installedVersion: () => '1', scan: async () => {},
      bundleOf: async () => bundle,
      disable: async (name) => { disabled.push(name); const r = await disable(); if (r.disabled) bundle = { enabled: false }; return r; },
      userQuestions: () => ({ ask: async () => ({ answers: [{ id: QUESTION_ID, selected: ['禁用'] }] }) }),
    });
    const exec = { name: 't', agent: {}, signal: new AbortController().signal };
    const first = await gate.handle(exec, async () => ({ via: 'next' }));
    const second = await gate.handle(exec, async () => ({ via: 'next' }));
    return { state, disabled, first, second };
  };
  const native = await run(async () => ({ disabled: true, via: 'plugin-manager' }));
  assert.deepEqual(native.disabled, ['p']);
  assert.equal(native.first.kind, 'deny');
  assert.equal(native.second.kind, 'deny', 'the deselected bundle keeps being denied');
  assert.equal(native.state.getPolicy('p'), null, 'no duplicate gate record when the manager disabled it');
  assert.ok(native.state.readAuditLog().some((e) => e.kind === 'gate-disable' && e.via === 'plugin-manager'));
  const fallback = await run(async () => ({ disabled: false, via: 'plugin-manager', reason: 'not-removable' }));
  assert.equal(fallback.state.getPolicy('p').decision, 'block');
  assert.equal(fallback.second.kind, 'deny');
});

test('settings policy and uninstall RPCs call the native plugin manager', async () => {
  const env = profileWith(['fixture']);
  mkdirSync(env.globalRoot, { recursive: true });
  const saved = { DSH_HOME: process.env.DSH_HOME, DSH_PROFILE_DIR: process.env.DSH_PROFILE_DIR, DSH_GLOBAL_ROOT: process.env.DSH_GLOBAL_ROOT };
  Object.assign(process.env, { DSH_HOME: env.dshHome, DSH_PROFILE_DIR: env.profileRoot, DSH_GLOBAL_ROOT: env.globalRoot });
  const manager = fakeManager([{ name: 'fixture', enabled: true }]);
  const reset = setActiveManager(createManagerBridge(manager));
  const rpc = (method, request) => SecurityRemote.prototype[method].call({}, request);
  try {
    const block = await rpc('policy', { name: 'fixture', decision: 'block' });
    assert.equal(block.ok, true);
    assert.equal(block.bundle.enabled, false);
    assert.equal(block.policy, null);
    assert.equal(manager.state.get('fixture').enabled, false);
    const allow = await rpc('policy', { name: 'fixture', decision: 'allow' });
    assert.equal(allow.ok, true);
    assert.equal(manager.state.get('fixture').enabled, true, '启用 re-selects the bundle natively');
    assert.equal(allow.policy.decision, 'allow');
    await rpc('policy', { name: 'fixture', decision: 'block' });
    const reset_ = await rpc('policy', { name: 'fixture', decision: null });
    assert.equal(manager.state.get('fixture').enabled, true, '恢复默认 re-selects it too');
    assert.equal(reset_.policy, null);
    const protectedBlock = await rpc('policy', { name: 'dsh-plugin-security', decision: 'block' });
    assert.equal(protectedBlock.reason, 'protected');
    const removed = await rpc('uninstall', { name: 'fixture' });
    assert.equal(removed.via, 'plugin-manager');
    assert.equal(removed.ok, true);
    assert.deepEqual(manager.calls.at(-1), ['removeBundle', 'fixture']);
    assert.equal(openState(env.dshHome).getPolicy('fixture'), null);
  } finally {
    reset();
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test('gate blocks stored before the sync move onto the plugin manager at startup', async () => {
  const state = openState(mkdtempSync(join(tmpdir(), 'security-manager-reconcile-')));
  state.setPolicy('old-block', { decision: 'block', by: 'user-prompt' });
  state.setPolicy('already-off', { decision: 'block', by: 'settings' });
  state.setPolicy('not-a-bundle', { decision: 'block', by: 'settings' });
  state.setPolicy('stubborn', { decision: 'block', by: 'settings' });
  state.setPolicy('allowed', { decision: 'allow', version: '1' });
  const manager = fakeManager([
    { name: 'old-block', enabled: true }, { name: 'already-off', enabled: false }, { name: 'stubborn', enabled: true }, { name: 'allowed', enabled: true },
  ], { fail: { stubborn: 'read-only' } });
  assert.deepEqual(await reconcileBlocks(state, () => false), [], 'nothing happens without a manager');
  const reset = setActiveManager(createManagerBridge(manager));
  try {
    assert.deepEqual(await reconcileBlocks(state, () => false), ['old-block', 'already-off']);
    assert.equal(manager.state.get('old-block').enabled, false);
    assert.equal(state.getPolicy('old-block'), null);
    assert.equal(state.getPolicy('already-off'), null);
    assert.equal(state.getPolicy('not-a-bundle').decision, 'block', 'non-bundles keep the gate block');
    assert.equal(state.getPolicy('stubborn').decision, 'block', 'a failed native disable keeps the gate block');
    assert.equal(state.getPolicy('allowed').decision, 'allow');
    assert.ok(state.readAuditLog().some((e) => e.kind === 'policy-moved-to-plugin-manager' && e.name === 'old-block'));
  } finally {
    reset();
  }
});
