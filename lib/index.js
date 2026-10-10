/**
 * dsh-plugin-security — host half.
 *
 * Installs the `security` Remote namespace (settings page) and the
 * `security_scan` / `security_review` agent tools. The screening pass only
 * reads manifests, patches and source text — target code is never executed.
 * The only writes are this plugin's own scan-state file and, in enforce mode,
 * the reversible profile bundles edit (with backup + protected list).
 *
 * @module dsh-plugin-security
 */

import { installSecurityRemote, installSecurityTypertContract, installSecurityFetchRoutes } from './remote.js';
import { registerSecurityTools } from './tool.js';
import { resolveEnv } from './paths.js';
import { scanCached } from './scan.js';
import { listPluginsExtras } from './collect.js';

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
  // audit P0-1 (lightweight mitigation): the gate must not wait for someone
  // to press a button. Scan once per boot, after the host settles. The
  // scan-once cache keeps this cheap; force is never set here. Failures are
  // silent — the boot must never depend on the guard.
  const bootScan = setImmediate(() => {
    try {
      const resolved = resolveEnv();
      if (resolved.error !== undefined) return;
      scanCached(resolved.env, listPluginsExtras(ctx), {})
        .catch(() => { /* boot-time scan is best-effort */ });
    } catch {
      /* best-effort */
    }
  });
  disposers.push(() => clearImmediate(bootScan));
  return () => {
    for (const d of [...disposers].reverse()) {
      try { d(); } catch { /* best-effort */ }
    }
  };
}
