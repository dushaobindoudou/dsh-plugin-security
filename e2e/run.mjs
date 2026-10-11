/**
 * End-to-end test of the call gate against a real dsh install.
 *
 * Builds an isolated DSH_HOME (never the user's), creates a profile from the
 * shipped headless template, installs this package plus two fixtures from
 * packed tarballs, routes the agent to a local deterministic fake model
 * (e2e/fake-llm.mjs), and drives `dsh e2e --json` through each scenario.
 *
 * Fixtures:
 *   - dsh-security-e2e-fixture  harmless echo tool, high risk on purpose
 *     (critical minimist advisory, dead risky-looking code)
 *   - dsh-security-e2e-answerer answers the gate question from E2E_ANSWER,
 *     standing in for a person clicking the question card
 *
 * Needs the global `dsh` launcher and network access to the npm registry
 * (fixture install + the real advisory audit).
 *
 * usage: node e2e/run.mjs [--keep]
 */

import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repo = fileURLToPath(new URL('..', import.meta.url));
const keep = process.argv.includes('--keep');
const work = mkdtempSync(join(tmpdir(), 'dsh-security-e2e-'));
const home = join(work, 'home');
const profile = join(home, 'profiles', 'e2e');
const pkgs = join(work, 'pkgs');
const questionLog = join(work, 'questions.jsonl');
mkdirSync(pkgs, { recursive: true });

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n      ${detail}`}\n`);
}

function sh(cmd, args, options = {}) {
  const out = spawnSync(cmd, args, { encoding: 'utf8', ...options, env: { ...process.env, DSH_HOME: home, ...(options.env ?? {}) } });
  if (out.status !== 0 && options.allowFail !== true) {
    throw new Error(`${cmd} ${args.join(' ')} failed (${out.status}):\n${out.stdout}\n${out.stderr}`);
  }
  return out;
}

async function startFakeModel() {
  const child = spawn(process.execPath, [join(repo, 'e2e', 'fake-llm.mjs'), '0', join(work, 'llm.jsonl')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((resolve, reject) => {
    child.stdout.once('data', (d) => resolve(Number(String(d).trim())));
    child.once('exit', (code) => reject(new Error(`fake model exited ${code}`)));
  });
  return { child, port };
}

/** The installed plugin's own state module, so the test edits state exactly as the plugin does. */
async function pluginState() {
  const mod = await import(pathToFileURL(join(profile, 'node_modules', 'dsh-plugin-security', 'lib', 'state.js')).href);
  return mod.openState(home);
}

/** One headless run; returns the gated tool's result event. */
function runTask(env = {}) {
  const out = sh('dsh', ['e2e', '--json', 'call the echo tool'], { cwd: work, env: { FAKE_LLM_KEY: 'e2e-placeholder', E2E_QUESTION_LOG: questionLog, DSH_LOCALE: 'zh', ...env }, allowFail: true });
  const events = out.stdout.split('\n').filter(Boolean).flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } });
  const result = events.find((e) => e.type === 'tool_result');
  return { status: out.status, result, results: events.filter((e) => e.type === 'tool_result'), events, stderr: out.stderr };
}

const ran = (run) => run.result?.status === 'completed' && /E2E_FIXTURE_ECHO:hello-e2e/.test(String(run.result?.result));
const questions = () => existsSync(questionLog) ? readFileSync(questionLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];

const fake = await startFakeModel();
try {
  // ---- isolated profile -------------------------------------------------
  sh('dsh', ['e2e', '--from-default-profile', 'headless', '--help'], { cwd: work });
  for (const dir of [repo, join(repo, 'e2e', 'fixture-plugin'), join(repo, 'e2e', 'answerer-plugin')]) {
    sh('npm', ['pack', '--pack-destination', pkgs], { cwd: dir });
  }
  const version = JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8')).version;
  sh('dsh', ['plugin', '--profile', 'e2e', 'add',
    join(pkgs, `dsh-plugin-security-${version}.tgz`),
    join(pkgs, 'dsh-security-e2e-fixture-1.0.0.tgz'),
    join(pkgs, 'dsh-security-e2e-answerer-1.0.0.tgz')], { cwd: work });
  const manifestPath = join(profile, 'package.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  for (const bundle of ['dsh-plugin-security', 'dsh-security-e2e-fixture', 'dsh-security-e2e-answerer']) {
    if (!manifest.dsh.profile.bundles.includes(bundle)) manifest.dsh.profile.bundles.push(bundle);
  }
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(profile, 'cordis.patch.yml'), [
    '- id: llm-pi-ai',
    "  name: '@deepseek-ai/dsh-llm-pi-ai'",
    '  config:',
    '    providers:',
    '      fake:',
    '        apiKeyEnv: FAKE_LLM_KEY',
    '        api: openai-completions',
    `        baseURL: http://127.0.0.1:${fake.port}/v1`,
    '        models:',
    '          - id: fake-model',
    '            name: fake-model',
    '- id: agent-default-model',
    "  name: '@deepseek-ai/dsh-agent-default-model'",
    '  config:',
    '    provider: fake',
    '    model: fake-model',
    '',
  ].join('\n'));

  // ---- 1. fresh install: first call, no scan record yet ----------------
  const first = runTask();
  const state = await pluginState();
  const entry = state.findScan('dsh-security-e2e-fixture', '1.0.0');
  check('first call into a never-scanned high-risk plugin is gated, not executed', first.result !== undefined && !ran(first),
    JSON.stringify(first.result));
  check('the plugin was scanned on demand / at startup and recorded as high risk', entry?.risk?.level === 'high', JSON.stringify(entry?.risk));
  check('the dependency audit found the critical minimist advisory', entry?.deps?.worst === 'critical', JSON.stringify(entry?.deps));
  check('static screening reported the dead risky code', ['high', 'critical'].includes(entry?.screening?.signal?.level), JSON.stringify(entry?.screening?.signal));
  check('the declared tool name was extracted', JSON.stringify(entry?.tools) === JSON.stringify(['e2e_fixture_echo']), JSON.stringify(entry?.tools));
  check('without an answer the gate falls back to host approval (headless has none)', /approval/i.test(String(first.result?.result)),
    String(first.result?.result));
  const asked = questions()[0];
  check('the gate asked through the real user-questions channel with the calling agent', asked?.hasAgent === true, JSON.stringify(asked));
  check('the question offers 允许一次 / 允许 / 禁用', JSON.stringify(asked?.question?.options?.map((o) => o.label)) === JSON.stringify(['允许一次', '允许', '禁用']),
    JSON.stringify(asked?.question?.options));
  check('the question names the plugin, version and tool', /dsh-security-e2e-fixture@1\.0\.0.*e2e_fixture_echo/.test(asked?.question?.question ?? ''), asked?.question?.question);

  // ---- 2. 允许一次 -------------------------------------------------------
  const once = runTask({ E2E_ANSWER: '允许一次' });
  check('允许一次 runs this call', ran(once), JSON.stringify(once.result));
  check('允许一次 stores no decision', state.getPolicy('dsh-security-e2e-fixture') === null, JSON.stringify(state.getPolicy('dsh-security-e2e-fixture')));
  const afterOnce = runTask();
  check('the next call asks again (and is refused without an answer)', !ran(afterOnce), JSON.stringify(afterOnce.result));

  // ---- 2b. 允许一次 is exact: two calls in one step get two questions -----
  const askedBeforePair = questions().length;
  const setCalls = (calls) => fetch(`http://127.0.0.1:${fake.port}/__control`, { method: 'POST', body: JSON.stringify({ calls }) });
  await setCalls(2);
  const pair = runTask({ E2E_ANSWER: '允许一次' });
  await setCalls(1);
  check('two calls in one step: 允许一次 is asked per call and both run',
    pair.results.length === 2 && pair.results.every((r) => /E2E_FIXTURE_ECHO:hello-e2e/.test(String(r.result))) && questions().length - askedBeforePair === 2,
    JSON.stringify({ results: pair.results, asked: questions().length - askedBeforePair }));

  // ---- 3. 允许 ------------------------------------------------------------
  const allow = runTask({ E2E_ANSWER: '允许' });
  const allowPolicy = state.getPolicy('dsh-security-e2e-fixture');
  check('允许 runs the call', ran(allow), JSON.stringify(allow.result));
  check('允许 is remembered for version 1.0.0', allowPolicy?.decision === 'allow' && allowPolicy.version === '1.0.0', JSON.stringify(allowPolicy));
  const before = questions().length;
  const remembered = runTask();
  check('a remembered allow runs without asking', ran(remembered) && questions().length === before, JSON.stringify(remembered.result));

  // ---- 4. 禁用 → the native plugin manager deselects the bundle ------------
  const selected = () => JSON.parse(readFileSync(manifestPath, 'utf8')).dsh.profile.bundles.includes('dsh-security-e2e-fixture');
  state.setPolicy('dsh-security-e2e-fixture', null);
  const block = runTask({ E2E_ANSWER: '禁用' });
  check('禁用 denies the call', !ran(block) && /禁用|disabled/i.test(String(block.result?.result)), JSON.stringify(block.result));
  check('禁用 deselects the bundle through the plugin manager (same as the native Plugins page)', !selected());
  check('the dependency stays installed, as with a native disable',
    Object.hasOwn(JSON.parse(readFileSync(manifestPath, 'utf8')).dependencies, 'dsh-security-e2e-fixture'));
  check('no duplicate gate block is stored when the manager disabled it', state.getPolicy('dsh-security-e2e-fixture') === null,
    JSON.stringify(state.getPolicy('dsh-security-e2e-fixture')));
  const asksBefore = questions().length;
  const disabledRun = runTask({ E2E_ANSWER: '允许一次' });
  check('a disabled plugin is not loaded: its tool cannot run and nothing is asked', !ran(disabledRun) && questions().length === asksBefore,
    JSON.stringify(disabledRun.result));
  // re-enable as the native Plugins page would
  const restored = JSON.parse(readFileSync(manifestPath, 'utf8'));
  restored.dsh.profile.bundles.push('dsh-security-e2e-fixture');
  writeFileSync(manifestPath, `${JSON.stringify(restored, null, 2)}\n`);
  const reenabled = runTask();
  check('after a native re-enable the plugin loads again and is gated (asked, not run)', !ran(reenabled) && questions().length > asksBefore,
    JSON.stringify(reenabled.result));

  // ---- 5. settings switch, whitelist and mode off -------------------------
  state.setPolicy('dsh-security-e2e-fixture', { decision: 'allow', version: '1.0.0', by: 'settings' });
  check('settings 启用 (allow) re-enables the plugin', ran(runTask()));
  state.setPolicy('dsh-security-e2e-fixture', null);
  state.writeConfig({ protectedNames: ['dsh-security-e2e-fixture'] });
  check('a whitelisted plugin is not gated', ran(runTask()));
  state.writeConfig({ protectedNames: [], mode: 'off' });
  check('mode off disables the gate', ran(runTask()));
  state.writeConfig({ mode: 'report-only' });

  const log = state.readAuditLog();
  check('prompt answers and policy changes are in the audit log',
    log.some((e) => e.kind === 'gate-ask' && e.choice === 'once') && log.some((e) => e.kind === 'gate-disable' && e.via === 'plugin-manager'),
    JSON.stringify(log.slice(-6)));
} catch (error) {
  check('e2e harness', false, error?.stack ?? String(error));
} finally {
  fake.child.kill();
  const failed = results.filter((r) => !r.ok).length;
  process.stdout.write(`\n${results.length - failed}/${results.length} passed${keep || failed ? ` — work dir kept at ${work}` : ''}\n`);
  if (!keep && failed === 0) rmSync(work, { recursive: true, force: true });
  process.exitCode = failed === 0 ? 0 : 1;
}
