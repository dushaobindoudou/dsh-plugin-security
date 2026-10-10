/**
 * Dependency vulnerability audit — the deterministic half of the report.
 *
 * Source of truth: the npm registry bulk advisory endpoint (verified live on
 * 2026-10-09 — no auth, no key):
 *
 *   POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
 *   body: { "<package>": ["<version>", ...], ... }
 *   resp: { "<package>": [ { id, url, title, severity, vulnerable_versions,
 *                            cwe, cvss: { score, vectorString } }, ... ] }
 *
 * The bulk endpoint does NOT say which version fixes an advisory, so for every
 * hit we follow up with OSV by GHSA id (GET /v1/vulns/{id}) and read
 * `affected[].ranges[].events[].fixed` for the npm ecosystem. If OSV is slow
 * or missing, we degrade gracefully: the advisory still reports, the upgrade
 * hint just says "upstream not published / unknown".
 *
 * Privacy: the only thing that leaves the machine is `(package name, version)`
 * tuples. No paths, no code, no local content ever leaves.
 *
 * All network goes through `fetchImpl` so tests can inject a mock. Results are
 * memoised per host process by `name@version` with a 24h TTL.
 *
 * @module dsh-plugin-security/audit
 */

const NPM_BULK_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
/** Batch size for the bulk request; npm tolerates large maps, 50 is polite. */
const BULK_BATCH = 50;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/** npm severity → our uniform ladder (critical > high > medium > low > none). */
export function npmSeverityToLadder(severity) {
  switch (String(severity || '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'moderate': return 'medium';
    case 'low': return 'low';
    default: return 'low';
  }
}

const LADDER_ORDER = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
export function maxLadder(a, b) {
  // parentheses are load-bearing: `a ?? 0 >= b` parsed as `a ?? (0 >= b)`
  // and maxLadder('low','critical') returned 'low' (audit P2-1)
  return (LADDER_ORDER[a] ?? 0) >= (LADDER_ORDER[b] ?? 0) ? a : b;
}
export function ladderAtLeast(level, threshold) {
  return (LADDER_ORDER[level] ?? 0) >= (LADDER_ORDER[threshold] ?? 0);
}

/** In-process memo: name@version → advisory[] (shared per host process). */
const memo = new Map();

function cacheGet(key) {
  const hit = memo.get(key);
  if (!hit) return undefined;
  if (Date.now() - hit.at > CACHE_TTL_MS) {
    memo.delete(key);
    return undefined;
  }
  return hit.value;
}
function cachePut(key, value) {
  memo.set(key, { at: Date.now(), value });
  return value;
}

/**
 * Normalise one npm bulk advisory into the report shape.
 *
 * @param {string} depName
 * @param {object} adv raw npm advisory
 * @param {string} [fixedIn] resolved fix version (may be null)
 */
function normaliseAdvisory(depName, adv, fixedIn) {
  const ghsa = String(adv.url || '').split('/').pop() || `GHSA-${adv.id}`;
  return {
    id: ghsa,
    source: 'npm-advisory',
    title: adv.title ?? ghsa,
    url: adv.url ?? null,
    severity: npmSeverityToLadder(adv.severity),
    cvss: adv.cvss && typeof adv.cvss.score === 'number' ? adv.cvss.score : null,
    cvssVector: adv.cvss?.vectorString ?? null,
    cwe: Array.isArray(adv.cwe) ? adv.cwe : (adv.cwe ? [adv.cwe] : []),
    vulnerableRange: adv.vulnerable_versions ?? null,
    fixedIn: fixedIn ?? null,
    dep: depName,
  };
}

/**
 * Ask OSV for the smallest `fixed` version of one advisory (by GHSA id).
 * Returns null on any failure — the upgrade hint degrades, the report does not.
 */
export async function resolveFixedIn(ghsaId, fetchImpl = fetch, osvUrl = OSV_VULN_URL) {
  try {
    const res = await fetchImpl(osvUrl + encodeURIComponent(ghsaId), {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const vuln = await res.json();
    let best = null;
    for (const affected of vuln.affected ?? []) {
      if (affected.package?.ecosystem && !/npm/i.test(affected.package.ecosystem)) continue;
      for (const range of affected.ranges ?? []) {
        if (range.type && range.type !== 'SEMVER') continue;
        for (const ev of range.events ?? []) {
          if (!ev.fixed) continue;
          if (best === null || compareLoose(ev.fixed, best) < 0) best = ev.fixed;
        }
      }
    }
    return best;
  } catch {
    return null;
  }
}

/** Very small semver-ish compare: [major, minor, patch] numbers, missing = 0. */
function compareLoose(a, b) {
  const pa = String(a).split('.').map((n) => Number.parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

/**
 * Audit a set of dependencies.
 *
 * @param {Array<{name: string, version: string}>} deps unique name@version pairs
 * @param {{fetchImpl?: Function, now?: Function}} [opts]
 * @returns {Promise<Object>} `{ results: { [name]: { version, advisories[] } }, worst: 'critical'|'high'|'medium'|'low'|'none', errors: string[] }`
 */
export async function auditDependencies(deps, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const errors = [];
  const pairs = [];
  for (const d of deps ?? []) {
    if (!d || typeof d.name !== 'string' || typeof d.version !== 'string') continue;
    if (d.version.startsWith('workspace:') || d.version.startsWith('link:')) continue;
    const key = `${d.name}@${d.version}`;
    const cached = cacheGet(key);
    if (cached !== undefined) {
      pairs.push({ name: d.name, version: d.version, advisories: cached });
    } else {
      pairs.push({ name: d.name, version: d.version, advisories: null });
    }
  }

  // only the uncached ones hit the network
  const pending = pairs.filter((p) => p.advisories === null);
  const byName = new Map();
  for (const p of pending) {
    if (!byName.has(p.name)) byName.set(p.name, new Set());
    byName.get(p.name).add(p.version);
  }

  const names = [...byName.keys()];
  for (let i = 0; i < names.length; i += BULK_BATCH) {
    const slice = names.slice(i, i + BULK_BATCH);
    const body = {};
    for (const n of slice) body[n] = [...byName.get(n)];
    try {
      const res = await fetchImpl(NPM_BULK_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) {
        // audit P2-2: an HTTP failure is "unknown", never "clean" — mark the
        // affected packages unknown and do NOT cache empties for 24h
        errors.push(`npm bulk audit HTTP ${res.status}`);
        for (const p of pairs) if (p.advisories === null && slice.includes(p.name)) p.unknown = true;
        continue;
      }
      const payload = await res.json();
      for (const p of pairs) {
        if (p.advisories !== null) continue;
        if (!slice.includes(p.name)) continue;
        const raw = Array.isArray(payload?.[p.name]) ? payload[p.name] : [];
        const normalised = raw.map((adv) => normaliseAdvisory(p.name, adv, null));
        p.advisories = normalised;
        cachePut(`${p.name}@${p.version}`, normalised);
      }
    } catch (err) {
      // same semantics: transport failure = unknown, not clean; leave
      // uncached so the next scan retries
      errors.push(`npm bulk audit failed: ${err?.message ?? err}`);
      for (const p of pairs) {
        if (p.advisories === null && slice.includes(p.name)) p.unknown = true;
      }
    }
  }

  // resolve fixedIn for hits (OSV follow-up, concurrency-capped and
  // failure-tolerant; serial previously cost up to 20×8s vs the tool timeout)
  const hitAdvisories = pairs.flatMap((p) => p.advisories ?? []);
  const needFixed = [...new Set(hitAdvisories.filter((a) => !a.fixedIn).map((a) => a.id))].slice(0, 24);
  const OSV_CONCURRENCY = 5;
  for (let i = 0; i < needFixed.length; i += OSV_CONCURRENCY) {
    const chunk = needFixed.slice(i, i + OSV_CONCURRENCY);
    const fixedList = await Promise.all(chunk.map((ghsa) => resolveFixedIn(ghsa, fetchImpl)));
    for (let j = 0; j < chunk.length; j += 1) {
      if (!fixedList[j]) continue;
      for (const a of hitAdvisories) if (a.id === chunk[j] && !a.fixedIn) a.fixedIn = fixedList[j];
    }
  }

  const results = {};
  let worst = 'none';
  for (const p of pairs) {
    if (p.advisories === null) {
      // never successfully queried (or the query failed): unknown ≠ clean
      results[p.name] = { version: p.version, advisories: [], unknown: true };
      continue;
    }
    results[p.name] = { version: p.version, advisories: p.advisories };
    for (const a of p.advisories) worst = maxLadder(worst, a.severity);
  }
  return { results, worst, errors };
}

/** Test hook: wipe the process memo. */
export function _clearAuditCache() {
  memo.clear();
}
