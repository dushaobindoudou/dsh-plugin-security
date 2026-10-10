/**
 * Locate the roots the sentinel scans: the running profile and the global dsh
 * install. Same discovery philosophy as dsh-recovery's paths module — resolve
 * from the running process, every strategy best-effort, null instead of throw.
 *
 * @module paths
 */

import { realpathSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Read a manifest, or null when absent/unparsable. */
function manifest(dir) {
  try {
    return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  } catch {
    return null;
  }
}

/** Walk up from `start`, returning the first dir whose manifest matches. */
function walkUp(start, predicate, limit = 10) {
  let dir = start;
  for (let i = 0; i < limit; i += 1) {
    const pkg = manifest(dir);
    if (pkg !== null && predicate(pkg)) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** The `@deepseek-ai/dsh` package directory (the global install). */
export function resolveGlobalRoot(env = process.env, argv = process.argv, execPath = process.execPath) {
  if (env.DSH_GLOBAL_ROOT) return resolve(env.DSH_GLOBAL_ROOT);
  const entry = argv[1];
  if (typeof entry === 'string' && entry.length > 0) {
    try {
      const found = walkUp(dirname(realpathSync(entry)), (pkg) => pkg.name === '@deepseek-ai/dsh', 8);
      if (found !== null) return found;
    } catch {
      // fall through to the interpreter-relative guess
    }
  }
  try {
    const candidate = join(dirname(dirname(realpathSync(execPath))), 'lib', 'node_modules', '@deepseek-ai', 'dsh');
    const pkg = manifest(candidate);
    if (pkg !== null && pkg.name === '@deepseek-ai/dsh') return candidate;
  } catch {
    // ignore
  }
  return null;
}

/** The dsh home directory holding `settings.yaml` and `profiles/`. */
export function resolveDshHome(env = process.env) {
  if (env.DSH_HOME) return resolve(env.DSH_HOME);
  return join(env.HOME ?? process.cwd(), '.dsh');
}

/**
 * The profile directory of the running process.
 *
 * Layered: DSH_PROFILE_DIR (exported by profile-launched harnesses) →
 * DSH_PROFILE_ROOT → walking up from this module (works for real installs
 * inside the profile's node_modules) → the booted `dsh --profile <name>` /
 * `dsh <alias>` command line. Every candidate is verified against its
 * manifest's `dsh.profile` field before being trusted.
 */
export function resolveProfileRoot(env = process.env, argv = process.argv) {
  const verified = (dir) => {
    if (typeof dir !== 'string' || dir.length === 0) return null;
    const pkg = manifest(dir);
    return pkg !== null && pkg?.dsh?.profile !== undefined ? resolve(dir) : null;
  };

  const fromEnv = verified(env.DSH_PROFILE_DIR) ?? verified(env.DSH_PROFILE_ROOT);
  if (fromEnv !== null) return fromEnv;

  try {
    const found = walkUp(dirname(fileURLToPath(import.meta.url)), (pkg) => pkg?.dsh?.profile !== undefined);
    if (found !== null) return found;
  } catch {
    // fall through to argv
  }

  const home = resolveDshHome(env);
  const asProfile = (candidate) => {
    if (typeof candidate !== 'string' || candidate.length === 0) return null;
    const dir = join(home, 'profiles', candidate);
    return existsSync(join(dir, 'package.json')) ? dir : null;
  };
  const flag = argv.indexOf('--profile');
  if (flag >= 0) return asProfile(argv[flag + 1]);
  for (const arg of argv.slice(2)) {
    if (arg.startsWith('-')) continue;
    return asProfile(arg);
  }
  return null;
}

/** Resolve `{ profileRoot, globalRoot, dshHome }`, or an error string. */
export function resolveEnv(env = process.env, argv = process.argv, execPath = process.execPath) {
  const profileRoot = resolveProfileRoot(env, argv);
  const globalRoot = resolveGlobalRoot(env, argv, execPath);
  const dshHome = resolveDshHome(env);
  if (profileRoot === null) {
    return { error: 'could not locate the profile root (no DSH_PROFILE_DIR and no `dsh.profile` manifest found)' };
  }
  if (globalRoot === null) return { error: 'could not locate the global dsh install' };
  return { env: { profileRoot, globalRoot, dshHome } };
}
