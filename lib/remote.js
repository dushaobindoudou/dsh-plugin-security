/**
 * Host Remote namespace `security` — the settings-page channel.
 *
 * Same contract as dsh-recovery's `doctor` namespace: the browser half calls
 * `connection.rpc.call('/api', 'security/<method>', …)` and receives the
 * method's return value as the RPC envelope's `value`. Methods return plain
 * JSON; failures are `{ error }` values, not thrown errors.
 *
 * @module remote
 */

import { Remote, TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol';
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { resolveEnv } from './paths.js';
import { scanCached, cachedReport } from './scan.js';
import { listPluginsExtras, resolvePackageDir } from './collect.js';
import { openState, MODES, AUTO_DISABLE_LEVELS, POLICY_DECISIONS } from './state.js';
import { enablePluginInProfile, disablePluginInProfile, isProtected } from './disposition.js';
import { RULE_DEFS } from './rules.js';

/**
 * Run one pnpm command in the profile root, asynchronously and bounded.
 * Only ever called with argument arrays built from recorded scan data —
 * never with strings supplied over RPC.
 */
function runPnpm(args, cwd, timeoutMs = 180000) {
  return new Promise((resolve) => {
    const child = spawn('pnpm', args, { cwd, env: process.env });
    let output = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => { output += String(d); });
    child.stderr.on('data', (d) => { output += String(d); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, code: null, output: `spawn failed: ${err?.message ?? err}` });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, code, output: output.slice(-4000) });
    });
  });
}

/**
 * Apply one `@Remote(method)` marker without decorator syntax — the same shim
 * dsh-recovery uses to mimic the decorator context the marker initializer
 * expects.
 */
function markRemoteMethod(prototype, method) {
  const decorator = Remote(method);
  decorator(undefined, {
    name: method,
    private: false,
    static: false,
    addInitializer(fn) { fn.call(Object.create(prototype)); },
  });
}

/** The `security` Remote namespace. */
export class SecurityRemote extends TypertRemoteService {
  constructor(ctx) {
    super(ctx, 'security');
  }

  /** Environment + config + rule metadata + whether a report exists. */
  async info() {
    const resolved = resolveEnv();
    const state = openState(resolved.env?.dshHome);
    return {
      env: resolved.error === undefined ? resolved.env : null,
      error: resolved.error === undefined ? null : resolved.error,
      config: state.readConfig(),
      rules: Object.entries(RULE_DEFS).map(([id, def]) => ({ id, title: def.title })),
      hasReport: cachedReport() !== null,
      generatedAt: cachedReport()?.generatedAt ?? null,
    };
  }

  /** Run (or reuse) the scan and return the full report. */
  async status(request) {
    const resolved = resolveEnv();
    if (resolved.error !== undefined) return { error: resolved.error };
    const force = request !== null && typeof request === 'object' && request.force === true;
    return scanCached(resolved.env, listPluginsExtras(this.ctx), { force });
  }

  /**
   * Read/write the gate config. Pass a patch to write, nothing to read.
   * Invalid values are normalised (never an error), and the effective config
   * is always returned.
   */
  async configure(request) {
    const resolved = resolveEnv();
    if (resolved.error !== undefined) return { error: resolved.error };
    const state = openState(resolved.env.dshHome);
    const patch = request !== null && typeof request === 'object' ? request : {};
    const clean = {};
    if (patch.mode !== undefined) {
      if (!MODES.includes(patch.mode)) return { error: `mode must be one of ${MODES.join(', ')}` };
      clean.mode = patch.mode;
    }
    if (patch.autoDisableAt !== undefined) {
      if (!AUTO_DISABLE_LEVELS.includes(patch.autoDisableAt)) return { error: `autoDisableAt must be one of ${AUTO_DISABLE_LEVELS.join(', ')}` };
      clean.autoDisableAt = patch.autoDisableAt;
    }
    if (patch.autoUpgrade !== undefined) clean.autoUpgrade = patch.autoUpgrade === true;
    if (Array.isArray(patch.protectedNames)) clean.protectedNames = patch.protectedNames.filter((n) => typeof n === 'string');
    const config = Object.keys(clean).length > 0 ? state.writeConfig(clean) : state.readConfig();
    return { config };
  }

  /**
   * Undo an enforcement disable (or force one for a package the user picks).
   * `enable: true` re-adds the name to the profile bundles array;
   * `enable: false` removes it. Both take effect after a host restart.
   *
   * audit P2-5: the protected list is enforced server-side — a client-side
   * RPC can never disable the gate itself, its family, or official plugins.
   * Every mutation lands in the append-only audit trail.
   */
  async reenable(request) {
    const resolved = resolveEnv();
    if (resolved.error !== undefined) return { error: resolved.error };
    const name = request?.name;
    if (typeof name !== 'string' || name.length === 0) return { error: 'name is required' };
    const state = openState(resolved.env.dshHome);
    const config = state.readConfig();
    const enabling = request?.enable !== false;
    if (!enabling && isProtected(name, config)) {
      state.audit({ kind: 'reenable-rejected-protected', name, enable: false });
      return { ok: false, name, reason: 'protected', error: `${name} is on the protected list and cannot be disabled through this channel` };
    }
    // audit P2-6: pass the recorded dir so the package directory is released
    // from (or moved into) quarantine together with the bundles edit
    const recorded = state.findScan(name);
    const dir = typeof recorded?.dir === 'string' ? recorded.dir : undefined;
    const result = enabling
      ? enablePluginInProfile(resolved.env.profileRoot, name, dir)
      : disablePluginInProfile(resolved.env.profileRoot, name, dir);
    state.audit({ kind: enabling ? 'reenable' : 'manual-disable', name, result });
    if (result.enabled === true || result.disabled === true) {
      return { ok: true, name, ...result };
    }
    return { ok: false, name, ...result };
  }

  /**
   * Set the call-gate decision for one plugin from the settings page:
   * `allow` (enable: its calls run without the high-risk prompt, for the
   * installed version), `block` (disable: every tool call is denied), or
   * `null` (default: high-risk calls ask again). Takes effect on the next
   * call, no restart. Protected plugins cannot be blocked.
   */
  async policy(request) {
    const resolved = resolveEnv();
    if (resolved.error !== undefined) return { error: resolved.error };
    const name = request?.name;
    if (typeof name !== 'string' || !/^(@[a-z0-9][a-z0-9-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(name)) return { error: 'name is required' };
    const decision = request?.decision ?? null;
    if (decision !== null && !POLICY_DECISIONS.includes(decision)) return { error: `decision must be one of ${POLICY_DECISIONS.join(', ')} or null` };
    const state = openState(resolved.env.dshHome);
    if (decision === 'block' && isProtected(name, state.readConfig())) {
      state.audit({ kind: 'policy-rejected-protected', name });
      return { ok: false, name, reason: 'protected', error: `${name} is protected and cannot be disabled through this channel` };
    }
    const installed = resolvePackageDir(name, [resolved.env.profileRoot, resolved.env.globalRoot].filter((r) => typeof r === 'string'));
    const version = typeof installed?.manifest?.version === 'string' ? installed.manifest.version : state.findScan(name)?.version ?? null;
    const policy = state.setPolicy(name, decision === null ? null : { decision, version, by: 'settings' });
    return { ok: true, name, policy };
  }

  /**
   * Uninstall one threatened plugin (user-confirmed from the threats panel):
   * `pnpm remove <name>` in the profile (drops dependencies + node_modules),
   * then the usual disable (bundles removal; the quarantine rename is a
   * no-op once the directory is gone). Protected list is enforced; every
   * attempt is audited with the command output tail.
   */
  async uninstall(request) {
    const resolved = resolveEnv();
    if (resolved.error !== undefined) return { error: resolved.error };
    const name = request?.name;
    if (typeof name !== 'string' || name.length === 0) return { error: 'name is required' };
    const state = openState(resolved.env.dshHome);
    const config = state.readConfig();
    if (isProtected(name, config)) {
      state.audit({ kind: 'uninstall-rejected-protected', name });
      return { ok: false, name, reason: 'protected', error: `${name} is protected and cannot be uninstalled through this channel` };
    }
    const removed = await runPnpm(['remove', name], resolved.env.profileRoot);
    // bundles removal stands even if pnpm failed (package dir may be gone
    // already, or pnpm may be unavailable)
    const disabled = disablePluginInProfile(resolved.env.profileRoot, name, undefined);
    // drop stale scan records so a future reinstall gets rescanned
    const index = state.readScanIndex();
    for (const key of Object.keys(index)) {
      if (index[key]?.name === name) state.deleteScan(key);
    }
    state.audit({ kind: 'uninstall', name, pnpmOk: removed.ok, pnpmCode: removed.code, bundlesRemoved: disabled.disabled === true });
    return {
      ok: removed.ok || disabled.disabled === true,
      name,
      pnpm: { ok: removed.ok, code: removed.code },
      bundlesRemoved: disabled.disabled === true,
      output: removed.output,
    };
  }

  /**
   * Upgrade one plugin's vulnerable dependencies (user-confirmed): runs the
   * recorded `pnpm add dep@fixed …` command in the profile, then drops the
   * scan records for the plugin so the next scan re-audits the new tree.
   * Only recorded targets are used — RPC callers cannot smuggle arguments.
   */
  async upgrade(request) {
    const resolved = resolveEnv();
    if (resolved.error !== undefined) return { error: resolved.error };
    const name = request?.name;
    if (typeof name !== 'string' || name.length === 0) return { error: 'name is required' };
    const state = openState(resolved.env.dshHome);
    const index = state.readScanIndex();
    const recorded = state.findScan(name);
    const targets = Array.isArray(recorded?.upgrade?.targets) ? recorded.upgrade.targets.filter((t) => typeof t === 'string' && /^[@a-z0-9-][^\\s;|&`$]*$/i.test(t)) : [];
    if (targets.length === 0) {
      return { ok: false, name, reason: 'no-upgrade-targets', error: 'no upgrade targets recorded for this plugin' };
    }
    const added = await runPnpm(['add', ...targets], resolved.env.profileRoot);
    if (added.ok) {
      for (const key of Object.keys(index)) {
        if (index[key]?.name === name) state.deleteScan(key);
      }
    }
    state.audit({ kind: 'upgrade', name, targets, pnpmOk: added.ok, pnpmCode: added.code });
    return { ok: added.ok, name, targets, pnpm: { ok: added.ok, code: added.code }, output: added.output };
  }
}

/**
 * Mark the methods and register the service on `ctx`; null when `ctx` is not
 * a Cordis context (a plain test double should not have to emulate it).
 *
 * After the fiber settles, one diagnostic probe is written to
 * `<dshHome>/plugin-security/remote-diag.json`: whether the service is
 * visible through `ctx.reflect.get` under both the loose and the strict
 * (fiber-state-2) semantics the gateway actually uses. This is the one
 * decisive answer to "why does /api/security/status 404" if it ever does.
 */
export function installSecurityRemote(ctx) {
  if (ctx === undefined || ctx === null || ctx.reflect === undefined) return null;
  for (const method of ['info', 'status', 'configure', 'reenable', 'policy', 'uninstall', 'upgrade']) markRemoteMethod(SecurityRemote.prototype, method);
  const service = new SecurityRemote(ctx);
  // fire once after startup ordering settles; failures must never break boot
  const timer = setTimeout(() => {
    const probe = { at: new Date().toISOString() };
    try {
      const loose = ctx.reflect.get('security', false);
      const strict = ctx.reflect.get('security', true);
      probe.loose = loose === undefined ? 'missing' : 'present';
      probe.strict = strict === undefined ? 'missing' : 'present';
      probe.fiberState = ctx.fiber?.state;
      probe.rootFiberState = ctx.root?.fiber?.state;
      probe.propsHasSecurity = ctx.reflect.props?.security?.type ?? 'absent';
      const typert = ctx.typert;
      probe.typertService = typert === undefined ? 'no-service' : typeof typert.register;
      try {
        const hit = typert?.local?.get?.('security/status');
        probe.typertLocal = hit !== undefined ? 'registered' : 'missing-endpoint';
      } catch (e) {
        probe.typertLocal = 'probe-error: ' + String(e?.message ?? e);
      }
      // Diagnostics only observe registrations; replaying one here would
      // mutate the registry and can mask the original startup failure.
      const connection = ctx.get('connection');
      probe.connectionType = connection === undefined ? 'undefined' : typeof connection;
      try {
        probe.fetchRoute = connection?.fetchRoutes?.has?.('/api/security/status') === true ? 'registered' : 'missing';
      } catch (e) {
        probe.fetchRoute = 'probe-error: ' + String(e?.message ?? e);
      }
    } catch (error) {
      probe.error = String(error?.message ?? error);
    }
    try {
      const resolved = resolveEnv();
      if (resolved.error === undefined) {
        mkdirSync(join(resolved.env.dshHome, 'plugin-security'), { recursive: true });
        writeFileSync(join(resolved.env.dshHome, 'plugin-security', 'remote-diag.json'), JSON.stringify(probe, null, 2));
      }
    } catch {
      // diagnostics are best-effort
    }
  }, 3000);
  ctx.fiber?.effect?.(() => () => clearTimeout(timer));
  return service;
}

/**
 * Register the security RPC contract as a strict typert definition.
 *
 * The gateway checks `ctx.typert.local` before source-mode discovery. Remote
 * markers live in protocol-module private state, so a separately installed
 * plugin's markers may be invisible to the host. Explicit descriptors avoid
 * that dependency; `src-json` codecs preserve the client's `args.request`.
 */
export function buildSecurityInvocations() {
  return ['info', 'status', 'configure', 'reenable', 'policy', 'uninstall', 'upgrade'].map((method) => ({
    id: `dsh-plugin-security/${method}`,
    service: 'security',
    namespace: 'security',
    method,
    invocation: { kind: 'direct' },
    parameters: [{ name: 'request', wire: 'request', source: 'json', codec: { mode: 'src-json' } }],
    result: { mode: 'src-json' },
  }));
}

export function installSecurityTypertContract(ctx) {
  if (ctx === undefined || ctx === null) return null;
  const typert = ctx.typert;
  if (typert === undefined || typert === null || typeof typert.register !== 'function') return null;
  return typert.register({
    package: 'dsh-plugin-security',
    face: 'host',
    model: { services: [], events: [], objects: [] },
    schemas: [],
    invocations: buildSecurityInvocations(),
  });
}

/**
 * Deterministic fallback channel: exact fetch routes for every security RPC
 * endpoint. `connection.fetchRoutes` is consulted before the RPC interceptor,
 * so these routes bypass source-mode discovery entirely. The wire format is the
 * same envelope the gateway speaks: `{type:'client-request', rpcId, method,
 * payload:{args:{request}}}` in, `{type:'server-response', rpcId,
 * result:{ok,value}}` out. Authentication still happens at the webServer
 * layer, outside this handler.
 */
const SECURITY_METHODS = ['info', 'status', 'configure', 'reenable', 'policy', 'uninstall', 'upgrade'];

export function installSecurityFetchRoutes(ctx, service) {
  if (ctx === undefined || ctx === null || service === null || service === undefined) return null;
  const fetch = ctx.connection?.fetch;
  if (typeof fetch?.register !== 'function') return null;
  const disposers = [];
  for (const method of SECURITY_METHODS) {
    const disposer = fetch.register({
      path: `/api/security/${method}`,
      methods: ['POST'],
      requestBody: 'buffered',
      fetch: async (request) => {
        let message;
        try {
          message = await request.json();
        } catch {
          return Response.json({ type: 'server-response', rpcId: 'invalid', result: { ok: false, error: { code: 'gateway/bad-request', message: 'body is not JSON', details: { issues: [] } } } });
        }
        const rpcId = typeof message?.rpcId === 'string' ? message.rpcId : 'invalid';
        const endpoint = `security/${method}`;
        if (message?.method !== endpoint) {
          return Response.json({ type: 'server-response', rpcId, result: { ok: false, error: { code: 'gateway/bad-request', message: `method ${JSON.stringify(message?.method)} does not match endpoint ${JSON.stringify(endpoint)}`, details: { issues: [] } } } });
        }
        try {
          const request_ = message?.payload?.args?.request === undefined ? null : message.payload.args.request;
          const value = await service[method](request_);
          return Response.json({ type: 'server-response', rpcId, result: { ok: true, value } });
        } catch (error) {
          return Response.json({ type: 'server-response', rpcId, result: { ok: false, error: { code: 'gateway/internal', message: String(error?.message ?? error), details: { issues: [] } } } });
        }
      },
    });
    if (typeof disposer === 'function') disposers.push(disposer);
  }
  return () => { for (const dispose of disposers) dispose(); };
}
