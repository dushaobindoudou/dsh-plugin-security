/**
 * dsh-plugin-security — host half.
 *
 * Installs the `security` Remote namespace (settings page), the
 * `security_scan` / `security_review` agent tools, and the call-time gate on
 * `tools/pre-execute` (see gate.js). The screening pass only reads manifests,
 * patches and source text — target code is never executed. The only writes
 * are this plugin's own state file and, in enforce mode, the reversible
 * profile bundles edit (with backup + protected list).
 *
 * Scan triggers: once after this plugin starts (its first start is the first
 * full scan), after every plugin-manager change (install, remove, enable),
 * and on demand when the gate meets a plugin with no record for its version.
 * The scan-once cache keeps the repeated passes cheap.
 *
 * @module dsh-plugin-security
 */

import { installSecurityRemote, installSecurityTypertContract, installSecurityFetchRoutes } from './remote.js';
import { registerSecurityTools } from './tool.js';
import { resolveEnv } from './paths.js';
import { scanCached } from './scan.js';
import { listPluginsExtras } from './collect.js';
import { installCallGate } from './gate.js';

export const name = 'plugin-security';

/**
 * Services this row needs injected. Cordis activates the fiber only for rows
 * that declare their injections (an empty array works too — dsh-bots ships
 * `inject = []`); without this export the row stays mounted but never starts
 * (fiberPhase: null), which is exactly the "installed but no tools" bug.
 *
 * `tools` registers the agent tools; `pluginManager` feeds listPluginsExtras
 * with the live loader rows for source attribution.
 *
 * `typert` owns the explicit host RPC contract. Connection is injected in a
 * child fiber so web routes can follow its lifetime without blocking the
 * agent tools and RPC contract in headless profiles.
 */
export const inject = ['tools', 'pluginManager', 'typert'];

/**
 * @param ctx - the Cordis plugin context.
 * @returns cleanup for everything this plugin registered.
 */
export function apply(ctx) {
  const disposers = [];
  const warn = (stage, error) => {
    ctx.logger?.warn?.(`plugin-security: ${stage} failed: ${error?.message ?? error}`);
  };
  // Explicit descriptors work even when the host and this plugin import
  // separate protocol modules with separate private Remote marker tables.
  try {
    const disposer = installSecurityTypertContract(ctx);
    if (typeof disposer === 'function') disposers.push(disposer);
  } catch (error) {
    warn('RPC contract registration', error);
  }
  try {
    const remote = installSecurityRemote(ctx);
    if (remote !== null && typeof remote.dispose === 'function') disposers.push(() => remote.dispose());
    if (remote !== null) {
      const routes = ctx.inject(['connection'], (connectionCtx) => {
        try {
          return installSecurityFetchRoutes(connectionCtx, remote);
        } catch (error) {
          warn('Fetch route registration', error);
        }
      });
      disposers.push(() => routes.dispose());
    }
  } catch (error) {
    warn('Remote service registration', error);
  }
  try {
    const disposer = registerSecurityTools(ctx);
    if (typeof disposer === 'function') disposers.push(disposer);
  } catch (error) {
    warn('agent tool registration', error);
  }
  // Background scans never block boot or the caller; failures are logged.
  const scanInBackground = (why) => {
    try {
      const resolved = resolveEnv();
      if (resolved.error !== undefined) return;
      scanCached(resolved.env, listPluginsExtras(ctx), {})
        .catch((error) => warn(`${why} scan`, error));
    } catch (error) {
      warn(`${why} scan`, error);
    }
  };
  try {
    const resolved = resolveEnv();
    if (resolved.error === undefined) {
      const disposer = installCallGate(ctx, {
        env: resolved.env,
        scan: (name) => scanCached(resolved.env, listPluginsExtras(ctx), { only: [name] }),
      });
      if (typeof disposer === 'function') disposers.push(disposer);
    }
  } catch (error) {
    warn('call gate installation', error);
  }
  // audit P0-1: the gate must not wait for someone to press a button. Scan
  // once per start, after the host settles; force is never set here.
  const bootScan = setImmediate(() => scanInBackground('startup'));
  disposers.push(() => clearImmediate(bootScan));
  // A newly installed or re-enabled plugin is scanned right away; bursts of
  // manager events collapse into one pass.
  let changeTimer = null;
  try {
    const off = ctx.on('plugin-manager/changed', () => {
      if (changeTimer !== null) clearTimeout(changeTimer);
      changeTimer = setTimeout(() => {
        changeTimer = null;
        scanInBackground('plugin change');
      }, 1000);
    });
    disposers.push(() => {
      if (changeTimer !== null) clearTimeout(changeTimer);
      if (typeof off === 'function') off();
    });
  } catch (error) {
    warn('plugin change listener', error);
  }
  return () => {
    for (const d of [...disposers].reverse()) {
      try { d(); } catch { /* best-effort */ }
    }
  };
}
