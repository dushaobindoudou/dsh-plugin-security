/**
 * Collect scan targets: every plugin package the profile mounts.
 *
 * A target is a package directory plus everything the rules read — manifest,
 * bundle patch text, client entry, and the bounded set of JS sources. Nothing
 * here executes package code; the only evaluation is `JSON.parse` on manifests
 * and regexes over text.
 *
 * @module collect
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';

const JS_EXTS = new Set(['.js', '.mjs', '.cjs']);
/** audit P0-5: prompt-injection lives in markdown/config, not just JS. */
const TEXT_EXTS = new Set(['.md', '.txt', '.json', '.yml', '.yaml']);
const MAX_FILES = 800; // audit P1-8: raised + selection-order hardened below
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_FILE_BYTES = 512 * 1024;
/** audit P0-4: bundled node_modules IS attack surface — scan it, bounded. */
const VENDOR_MAX_FILES = 200;
const VENDOR_MAX_TOTAL_BYTES = 4 * 1024 * 1024;
const VENDOR_MAX_DEPTH = 3;

/** Read a JSON file, or null. */
export function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

/** Read a text file with a hard cap, or null. */
function readText(path, cap = MAX_FILE_BYTES) {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > cap) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Resolve a package name to a real directory by looking in the given roots'
 * node_modules. Symlinks (pnpm `link:` workspace installs) are resolved so the
 * scanner reads the same bytes the host loaded.
 */
export function resolvePackageDir(name, roots) {
  if (typeof name !== 'string' || name.length === 0) return null;
  for (const root of roots) {
    if (root === null) continue;
    const candidate = join(root, 'node_modules', name);
    const manifest = readJson(join(candidate, 'package.json'));
    if (manifest === null || typeof manifest !== 'object') continue;
    let real = candidate;
    try {
      real = realpathSync(candidate);
    } catch {
      // keep the unresolved path
    }
    return { dir: real, manifest };
  }
  return null;
}

/**
 * Enumerate the readable sources of one package with hard caps (file count,
 * total bytes, per-file bytes) so a huge package can never stall a scan.
 *
 * audit P0-4/P1-8 changes: bundled `node_modules` is no longer skipped
 * wholesale — it is the most comfortable hiding spot — but it gets its own
 * smaller budget (file count / total bytes / depth) so vendored trees cannot
 * crowd out the package's own sources. docs/tests are scanned too: they are
 * require-able and, since text scanning, are prompt-injection carriers.
 *
 * The returned array carries a non-enumerable-ish `truncated` property when
 * a cap was hit (report surfaces it as a coverage caveat).
 */
export function listPackageFiles(pkgDir) {
  const out = [];
  let total = 0;
  let truncated = false;
  // separate vendor budget, consumed only inside node_modules
  const vendor = { files: 0, bytes: 0, over: false };

  const accept = (abs, rel, size, isVendor) => {
    if (size > MAX_FILE_BYTES) return false;
    if (out.length >= MAX_FILES || total + size > MAX_TOTAL_BYTES) {
      truncated = true;
      return false;
    }
    if (isVendor) {
      if (vendor.files >= VENDOR_MAX_FILES || vendor.bytes + size > VENDOR_MAX_TOTAL_BYTES) {
        vendor.over = true;
        truncated = true;
        return false;
      }
      vendor.files += 1;
      vendor.bytes += size;
    }
    total += size;
    out.push({ rel, abs, bytes: size });
    return true;
  };

  const walk = (dir, rel, isVendor, depth) => {
    if (out.length >= MAX_FILES || total >= MAX_TOTAL_BYTES) { truncated = true; return; }
    if (isVendor && depth > VENDOR_MAX_DEPTH) { vendor.over = true; truncated = true; return; }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    // audit P1-8: name-ascending order lets `aaa*.js` padding eat the cap —
    // interleave: process entries in name order but never drop the package's
    // own tree in favour of vendor content (vendor has its own budget)
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      if (out.length >= MAX_FILES || total >= MAX_TOTAL_BYTES) { truncated = true; return; }
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.')) continue;
        // once inside node_modules, everything below stays vendor-budgeted
        const childVendor = isVendor || entry.name === 'node_modules';
        walk(join(dir, entry.name), rel ? `${rel}/${entry.name}` : entry.name, childVendor, isVendor ? depth + 1 : 0);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = extname(entry.name);
      const isCode = JS_EXTS.has(ext);
      const isText = TEXT_EXTS.has(ext);
      if (!isCode && !isText) continue;
      if (entry.name.endsWith('.map') || entry.name.endsWith('.d.ts')) continue;
      const abs = join(dir, entry.name);
      const stat = statSync(abs, { throwIfNoEntry: false });
      if (stat === undefined || stat.size > MAX_FILE_BYTES) continue;
      accept(abs, rel ? `${rel}/${entry.name}` : entry.name, stat.size, isVendor);
    }
  };
  walk(pkgDir, '', false, 0);
  out.truncated = truncated || vendor.over;
  out.truncatedVendor = vendor.over;
  return out;
}

/**
 * audit P1-9: content fingerprint for the scan cache key. `name@version`
 * alone lets a malicious package pin its version and change code freely;
 * this adds the file inventory (path + size) and the manifest, which any
 * real code change disturbs. Cheap: no file bytes are hashed, only the
 * collected inventory — a byte-preserving swap is out of scope for a
 * screening pass (git hash-objects would be the next step).
 */
export function fingerprintOf(target) {
  const hash = createHash('sha256');
  hash.update(String(target.version ?? 'null'));
  hash.update('\u0000');
  hash.update(JSON.stringify(target.manifest ?? {}));
  for (const f of target.files ?? []) {
    hash.update(`${f.rel}:${f.bytes};`);
  }
  return hash.digest('hex').slice(0, 12);
}

/** Resolve the browser entry declared by `dsh.client`, or null. */
export function clientEntryOf(manifest, pkgDir) {
  const client = manifest?.dsh?.client;
  if (client === undefined || client === null) return null;
  const exp = manifest.exports?.['./client'];
  const rel = typeof exp === 'string' ? exp : (exp?.default ?? null);
  const candidates = [];
  if (typeof rel === 'string' && rel.length > 0) candidates.push(join(pkgDir, rel.replace(/^\.\//, '')));
  candidates.push(join(pkgDir, 'lib', 'client.js'));
  candidates.push(join(pkgDir, 'client.js'));
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/** Prefer the entry the loader would import for the host half. */
function hostEntryOf(manifest, pkgDir) {
  const main = typeof manifest?.main === 'string' ? manifest.main : null;
  const dotExport = manifest.exports?.['.'];
  const exported = typeof dotExport === 'string' ? dotExport : (dotExport?.default ?? null);
  for (const rel of [main, exported, 'lib/index.js', 'index.js']) {
    if (typeof rel !== 'string' || rel.length === 0) continue;
    const abs = join(pkgDir, rel.replace(/^\.\//, ''));
    if (existsSync(abs)) return abs;
  }
  return null;
}

/** The bundle patch file a manifest declares, read as text. */
function patchTextOf(manifest, pkgDir) {
  const rel = manifest?.dsh?.bundle?.patch;
  if (typeof rel !== 'string' || rel.length === 0) return null;
  return readText(join(pkgDir, rel));
}

/**
 * The optional `pluginManager.listPlugins` enrichment, resolved defensively
 * from a Cordis context. Returns `{}` (scan proceeds without row status)
 * whenever the service is absent — the file scan never depends on it.
 */
export function listPluginsExtras(ctx) {
  const pluginManager = ctx !== null && typeof ctx === 'object' && typeof ctx.get === 'function'
    ? ctx.get('pluginManager')
    : undefined;
  if (pluginManager === undefined || pluginManager === null || typeof pluginManager.listPlugins !== 'function') {
    return {};
  }
  return { listPlugins: () => pluginManager.listPlugins() };
}

/**
 * Build the scan targets for one profile.
 *
 * @param {object} env { profileRoot, globalRoot, dshHome }
 * @param {object} [extras] { listPlugins?: Promise | array } — live row status
 *   from the host pluginManager, used only to enrich (status chips); the file
 *   scan itself never depends on it.
 */
export async function collectTargets(env, extras = {}) {
  const profileRoot = env.profileRoot;
  const globalRoot = env.globalRoot;
  const roots = [profileRoot, globalRoot];

  const profileManifest = readJson(join(profileRoot, 'package.json')) ?? {};
  // `dsh.profile.bundles` is a name array in current profiles; accept the
  // `{ bundles: [...] }` wrapping too, in case an older/newer layout differs.
  const rawBundles = profileManifest?.dsh?.profile?.bundles;
  const bundleNames = Array.isArray(rawBundles)
    ? rawBundles
    : (Array.isArray(rawBundles?.bundles) ? rawBundles.bundles : []);
  const depSpecs = { ...(profileManifest?.dependencies ?? {}) };

  // Live rows can name packages the profile deps do not (built-ins resolved
  // from the dsh install); fold them in. Rows only ever enrich or add
  // resolved packages — a row that resolves nowhere contributes no target,
  // so ids and aliases cannot manufacture "missing" noise.
  let rows = [];
  try {
    const raw = typeof extras.listPlugins === 'function' ? await extras.listPlugins() : extras.listPlugins;
    if (Array.isArray(raw)) rows = raw.filter((r) => r !== null && typeof r === 'object');
  } catch {
    rows = [];
  }

  const targets = [];
  const seenDirs = new Set();

  /** Build one target from a resolved package. */
  const buildTarget = (name, resolved, extra = {}) => {
    const { dir, manifest } = resolved;
    if (seenDirs.has(dir)) {
      const existing = targets.find((t) => t.dir === dir);
      if (existing !== undefined && extra.rowStatus !== undefined && existing.rowStatus === null) {
        existing.rowStatus = extra.rowStatus;
      }
      return existing;
    }
    seenDirs.add(dir);
    // compare real paths: on macOS /var is a symlink to /private/var, so the
    // realpathed package dir would never sit under the unresolved root
    const profileReal = realpathSyncSafe(profileRoot);
    const globalReal = globalRoot !== null ? realpathSyncSafe(globalRoot) : null;
    const rel = relative(profileReal, dir);
    const inProfile = rel !== '' && !rel.startsWith('..');
    const inGlobal = globalReal !== null && relative(globalReal, dir) !== '' && !relative(globalReal, dir).startsWith('..');
    const listed = listPackageFiles(dir);
    const files = listed.map((f) => ({ ...f, text: readText(f.abs) }));
    const clientAbs = clientEntryOf(manifest, dir);
    const hostEntry = hostEntryOf(manifest, dir);
    const self = dir === realpathSyncSafe(new URL('..', import.meta.url).pathname);
    targets.push({
      name,
      version: typeof manifest?.version === 'string' ? manifest.version : null,
      dir,
      source: inProfile ? 'profile' : (inGlobal ? 'builtin' : 'external'),
      depSpec: depSpecs[name] ?? null,
      manifest,
      files,
      filesTruncated: listed.truncated === true,
      patchText: patchTextOf(manifest, dir),
      clientEntry: clientAbs === null ? null : {
        abs: clientAbs,
        rel: relative(dir, clientAbs),
        text: readText(clientAbs),
      },
      hostEntry: hostEntry === null ? null : relative(dir, hostEntry),
      self,
      rowStatus: extra.rowStatus ?? null,
    });
    return targets[targets.length - 1];
  };

  const profileNames = new Set([
    ...(Array.isArray(bundleNames) ? bundleNames : []),
    ...Object.keys(depSpecs),
  ]);

  for (const name of profileNames) {
    const resolved = resolvePackageDir(name, roots);
    if (resolved === null) {
      targets.push({
        name, version: null, dir: null, source: 'missing', depSpec: depSpecs[name] ?? null,
        manifest: null, files: [], patchText: null, clientEntry: null, hostEntry: null,
        self: false, rowStatus: rowStatusFor(rows, name),
      });
      continue;
    }
    buildTarget(name, resolved, { rowStatus: rowStatusFor(rows, name) });
  }

  for (const row of rows) {
    const status = rowStatusFor(rows, row.id ?? row.name);
    for (const name of [row?.name, row?.id]) {
      if (typeof name !== 'string' || name.length === 0 || name.startsWith('.') || name.includes(':')) continue;
      if (profileNames.has(name)) {
        const existing = targets.find((t) => t.name === name);
        if (existing !== undefined && existing.rowStatus === null) existing.rowStatus = status;
        break;
      }
      const resolved = resolvePackageDir(name, roots);
      if (resolved === null) continue;
      buildTarget(name, resolved, { rowStatus: status });
      break;
    }
  }

  // The profile patch layer as its own pseudo-target: its config rows carry
  // secrets/MCP/exec risk that belongs to no single package.
  const profilePatch = readText(join(profileRoot, 'cordis.patch.yml'));
  if (profilePatch !== null) {
    targets.push({
      name: '<profile cordis.patch.yml>',
      version: profileManifest?.version ?? null,
      dir: profileRoot,
      source: 'profile-patch',
      depSpec: null,
      manifest: profileManifest,
      files: [],
      patchText: profilePatch,
      clientEntry: null,
      hostEntry: null,
      self: false,
      rowStatus: null,
    });
  }

  return { targets, rows, profileManifest };
}

function rowStatusFor(rows, name) {
  const row = rows.find((r) => r?.name === name || r?.id === name);
  if (row === undefined) return null;
  const status = typeof row.status === 'string' ? row.status : undefined;
  return {
    status: status ?? null,
    id: typeof row.id === 'string' ? row.id : null,
    raw: row,
  };
}

function realpathSyncSafe(path) {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}
