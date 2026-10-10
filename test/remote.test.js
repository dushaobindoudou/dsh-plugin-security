import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Context } from '@deepseek-ai/cordis';
import { TypertRegistry } from '@deepseek-ai/dsh-typert-registry';
import { TypertGatewayService } from '@deepseek-ai/dsh-api-gateway';
import { HostConnectionService } from '@deepseek-ai/dsh-client-connection';
import * as security from '../lib/index.js';
import { installSecurityTypertContract } from '../lib/remote.js';
import { openState } from '../lib/state.js';

const methods = ['info', 'status', 'configure', 'reenable', 'uninstall', 'upgrade'];
const settle = () => new Promise((resolve) => setImmediate(resolve));

function statusRequest(method = 'security/status', body) {
  return new Request('http://localhost/api/security/status', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: body ?? JSON.stringify({
      type: 'client-request', rpcId: 'security-regression', method,
      payload: { args: { request: { force: false } } },
    }),
  });
}

async function host(t, { connection = true } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'security-rpc-'));
  const profileRoot = join(home, 'profiles', 'test');
  const globalRoot = join(home, 'global');
  mkdirSync(profileRoot, { recursive: true });
  mkdirSync(globalRoot);
  writeFileSync(join(profileRoot, 'package.json'), JSON.stringify({ dsh: { profile: { bundles: [] } } }));
  writeFileSync(join(globalRoot, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh' }));
  const env = { DSH_HOME: home, DSH_PROFILE_DIR: profileRoot, DSH_GLOBAL_ROOT: globalRoot };
  const saved = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  openState(home).writeConfig({ mode: 'off' }); // No network or enforcement in transport tests.
  const ctx = new Context();
  t.after(async () => {
    await ctx.fiber.dispose();
    await settle();
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(home, { recursive: true, force: true });
  });
  ctx.reflect.provide('tools', { register: () => () => {} });
  ctx.reflect.provide('pluginManager', { listPlugins: () => [] });
  const registry = new TypertRegistry(ctx);
  const gateway = new TypertGatewayService(ctx, TypertGatewayService.Config({}));
  const addConnection = () => new HostConnectionService(ctx, [], { isAuthenticated: () => true });
  const carrier = connection ? addConnection() : null;
  const fiber = ctx.plugin(security);
  await fiber;
  await settle();
  return { ctx, registry, gateway, carrier, fiber, addConnection };
}

test('security RPC contribution registers in the real host registry and withdraws cleanly', async (t) => {
  const ctx = new Context();
  t.after(() => ctx.fiber.dispose());
  const registry = new TypertRegistry(ctx);
  const dispose = installSecurityTypertContract(ctx);
  for (const method of methods) assert.ok(registry.local.get(`security/${method}`));
  assert.equal(registry.getPackage('dsh-plugin-security').face, 'host');
  dispose();
  for (const method of methods) assert.equal(registry.local.get(`security/${method}`), undefined);
});

test('POST /api/security/status succeeds through the real gateway with no exact-route fallback', async (t) => {
  const { registry, gateway, carrier } = await host(t);
  // Force the gateway path so a fallback cannot hide a broken contribution.
  carrier.fetchRoutes.clear();
  const response = await carrier.createSharedFetchHandler('/api').fetch(statusRequest());
  assert.equal(response.status, 200, 'security/status must not return HTTP 404');
  assert.ok(registry.local.get('security/status'));
  assert.equal(gateway.claimsEndpoint('security/status'), true);
  const envelope = await response.json();
  assert.equal(envelope.type, 'server-response');
  assert.equal(envelope.rpcId, 'security-regression');
  assert.equal(envelope.result.ok, true, JSON.stringify(envelope.result));
  assert.equal(envelope.result.value.config.mode, 'off');
});

test('exact security routes follow late Connection startup, replacement, and plugin disposal', async (t) => {
  const { ctx, fiber, addConnection } = await host(t, { connection: false });
  assert.ok(ctx.get('security'), 'headless startup does not depend on Connection');
  const connectionOwner = ctx.plugin({ inject: [], apply(c) {
    new HostConnectionService(c, [], { isAuthenticated: () => true });
  } });
  await connectionOwner;
  await settle();
  const first = ctx.get('connection');
  for (const method of methods) assert.ok(first.fetchRoutes.has(`/api/security/${method}`));
  // Disable the gateway interceptor to exercise the exact-route channel alone.
  first.interceptors.clear();
  const response = await first.createSharedFetchHandler('/api').fetch(statusRequest());
  assert.equal(response.status, 200);
  assert.equal((await response.json()).result.ok, true);
  await connectionOwner.dispose();
  await settle();
  assert.equal(first.fetchRoutes.size, 0);
  const replacement = addConnection();
  await settle();
  for (const method of methods) assert.ok(replacement.fetchRoutes.has(`/api/security/${method}`));
  await fiber.dispose();
  await settle();
  assert.equal(replacement.fetchRoutes.size, 0);
});

test('exact routes reject malformed RPC messages and preserve RPC error envelopes', async (t) => {
  const { carrier } = await host(t);
  assert.ok(carrier.fetchRoutes.has('/api/security/status'));
  const handler = carrier.createSharedFetchHandler('/api');
  for (const request of [statusRequest('security/uninstall'), statusRequest('security/status', '{')]) {
    const response = await handler.fetch(request);
    const envelope = await response.json();
    assert.equal(envelope.type, 'server-response');
    assert.equal(envelope.result.ok, false);
    assert.equal(envelope.result.error.code, 'gateway/bad-request');
  }
});
