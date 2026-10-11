/**
 * Bridge to the host plugin manager (`ctx.pluginManager`) — the service behind
 * the native Plugins page. Disabling, enabling and uninstalling go through it
 * so this plugin and the native page always show the same state:
 *
 *   - disable   → `setBundleEnabled(name, false)` (keeps the dependency)
 *   - enable    → `setBundleEnabled(name, true)`
 *   - uninstall → `removeBundle(name)`
 *
 * A bundle's saved selection is the single source of truth for "disabled":
 * the call gate denies calls into a deselected bundle that is still loaded
 * until restart, and a bundle enabled again on the native page is enabled
 * here too. Plugins the manager does not own as bundles fall back to the
 * profile-file edits in disposition.js.
 *
 * @module dsh-plugin-security/manager
 */

import { existsSync, renameSync } from 'node:fs';
import { disablePluginInProfile, enablePluginInProfile, QUARANTINE_SUFFIX } from './disposition.js';

const APPLIED = new Set(['applied', 'restart-required']);

/**
 * @param {object} manager the host `ctx.pluginManager`
 * @param {{ttlMs?: number, now?: () => number}} [options] bundle-list cache lifetime
 * @returns the bridge, or null when the manager is missing
 */
export function createManagerBridge(manager, { ttlMs = 5000, now = Date.now } = {}) {
  if (manager === undefined || manager === null || typeof manager.setBundleEnabled !== 'function' ||
    typeof manager.listBundles !== 'function') return null;
  let cache = null;
  const outcome = (result) => ({
    ok: result?.error === undefined && APPLIED.has(result?.application),
    application: result?.application ?? null,
    restartRequired: result?.application === 'restart-required',
    error: result?.error?.code ?? null,
  });
  const bridge = {
    /** name → `{ enabled, installed, removable, optional, readOnlyReason, error }` */
    async bundles() {
      if (cache !== null && now() - cache.at < ttlMs) return cache.map;
      const list = await manager.listBundles();
      const map = new Map((Array.isArray(list) ? list : []).filter((b) => typeof b?.name === 'string').map((b) => [b.name, {
        enabled: b.enabled === true,
        installed: b.installed === true,
        removable: b.removable === true,
        optional: b.optional === true,
        readOnlyReason: b.readOnlyReason ?? null,
        error: b.error?.code ?? null,
      }]));
      cache = { at: now(), map };
      return map;
    },
    async bundleOf(name) {
      try { return (await bridge.bundles()).get(name) ?? null; } catch { return null; }
    },
    invalidate() { cache = null; },
    async setEnabled(name, enabled) {
      try { return outcome(await manager.setBundleEnabled(name, enabled)); } catch (error) {
        return { ok: false, application: null, restartRequired: false, error: String(error?.message ?? error) };
      } finally { bridge.invalidate(); }
    },
    async remove(name) {
      try { return outcome(await manager.removeBundle(name)); } catch (error) {
        return { ok: false, application: null, restartRequired: false, error: String(error?.message ?? error) };
      } finally { bridge.invalidate(); }
    },
  };
  return bridge;
}

let active = null;

/** Make `bridge` the one every disable/enable/uninstall uses; returns the reset. */
export function setActiveManager(bridge) {
  active = bridge;
  return () => { if (active === bridge) active = null; };
}

export function activeManager() {
  return active;
}

/** Undo a quarantine rename left by an older version, so the manager sees the package again. */
function releaseQuarantine(dir) {
  if (typeof dir !== 'string' || dir.length === 0 || existsSync(dir) || !existsSync(`${dir}${QUARANTINE_SUFFIX}`)) return false;
  try {
    renameSync(`${dir}${QUARANTINE_SUFFIX}`, dir);
    return true;
  } catch {
    return false;
  }
}

/**
 * Disable one plugin: through the plugin manager when it owns the plugin as a
 * bundle, else by editing the profile bundles list (legacy path).
 *
 * @returns `{ disabled, via, restartRequired?, alreadyDisabled?, reason? }`
 */
export async function disablePlugin(profileRoot, name, dir) {
  const bundle = await active?.bundleOf(name);
  if (bundle) {
    if (!bundle.enabled) return { disabled: true, alreadyDisabled: true, via: 'plugin-manager' };
    const result = await active.setEnabled(name, false);
    return result.ok
      ? { disabled: true, restartRequired: result.restartRequired, application: result.application, via: 'plugin-manager' }
      : { disabled: false, reason: result.error ?? result.application ?? 'manager-failed', via: 'plugin-manager' };
  }
  return { ...disablePluginInProfile(profileRoot, name, dir), via: 'profile-file' };
}

/** Enable one plugin again, mirroring {@link disablePlugin}. */
export async function enablePlugin(profileRoot, name, dir) {
  const released = releaseQuarantine(dir);
  const bundle = await active?.bundleOf(name);
  if (bundle) {
    if (bundle.enabled) return { enabled: true, alreadyPresent: true, released, via: 'plugin-manager' };
    const result = await active.setEnabled(name, true);
    return result.ok
      ? { enabled: true, restartRequired: result.restartRequired, application: result.application, released, via: 'plugin-manager' }
      : { enabled: false, reason: result.error ?? result.application ?? 'manager-failed', released, via: 'plugin-manager' };
  }
  return { ...enablePluginInProfile(profileRoot, name, dir), via: 'profile-file' };
}

/**
 * Uninstall through the plugin manager when it owns the bundle.
 * @returns the outcome, or null when the manager cannot handle it (caller falls back)
 */
export async function removePlugin(name) {
  const bundle = await active?.bundleOf(name);
  if (!bundle) return null;
  const result = await active.remove(name);
  return { removed: result.ok, application: result.application, restartRequired: result.restartRequired, reason: result.error, via: 'plugin-manager' };
}

/**
 * Move gate blocks onto the plugin manager: a block recorded for a plugin the
 * manager owns as a bundle (for example one stored before disables went
 * through the manager) becomes a native disable, so the Plugins page shows
 * it. Blocks the manager cannot apply stay as gate blocks.
 *
 * @param {object} state openState() handle
 * @param {(name: string) => boolean} isProtected
 * @returns names moved to the plugin manager
 */
export async function reconcileBlocks(state, isProtected) {
  if (active === null) return [];
  const moved = [];
  for (const [name, policy] of Object.entries(state.readPolicies())) {
    if (policy?.decision !== 'block' || isProtected(name)) continue;
    const bundle = await active.bundleOf(name);
    if (!bundle) continue;
    const result = bundle.enabled ? await active.setEnabled(name, false) : { ok: true, application: 'already-disabled' };
    if (!result.ok) continue;
    state.setPolicy(name, null);
    state.audit({ kind: 'policy-moved-to-plugin-manager', name, application: result.application });
    moved.push(name);
  }
  return moved;
}
