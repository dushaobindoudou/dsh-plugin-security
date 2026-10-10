/**
 * Persistent state for dsh-plugin-security — scan records and disposition
 * config, stored at `<dshHome>/plugin-security/state.json`.
 *
 * Scan records use name, version and content fingerprint, plus a screening
 * revision checked by scan.js. Content or rule changes invalidate reuse.
 *
 * Config supports off/report-only/enforce and upgrade suggestions. The
 * autoDisableAt controls the review-gated threshold (never disables automation); static evidence
 * never authorizes automatic disabling. Enforcement requires a contextual,
 * high-confidence malicious review and observes the protected-name list.
 *
 * @module dsh-plugin-security/state
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { resolveDshHome } from './paths.js';

export const STATE_VERSION = 1;

/** Default config: the conservative factory settings. */
export const DEFAULT_CONFIG = Object.freeze({
  mode: 'report-only',
  autoDisableAt: 'critical',
  autoUpgrade: false,
});

export const MODES = Object.freeze(['off', 'report-only', 'enforce']);
export const AUTO_DISABLE_LEVELS = Object.freeze(['never', 'critical', 'high']);

const memo = new Map();

/**
 * Open (or create) the state store for a dsh home directory.
 *
 * @param {string} [dshHome] - defaults to `resolveDshHome()`
 * @returns {object} state handle: `{ dir, file, read(), readConfig(), writeConfig(patch), getScan(key), putScan(key, entry), deleteScan(key), readScanIndex() }`
 */
export function openState(dshHome) {
  const home = dshHome ?? resolveDshHome();
  if (memo.has(home)) {
    const existing = memo.get(home);
    if (existing.dir === join(home, 'plugin-security')) return existing;
  }
  const dir = join(home, 'plugin-security');
  const file = join(dir, 'state.json');

  const readRaw = () => {
    try {
      const raw = JSON.parse(readFileSync(file, 'utf8'));
      if (raw && typeof raw === 'object' && typeof raw.scans === 'object' && raw.scans !== null) return raw;
    } catch {
      /* missing or corrupt: fall through to the empty doc */
    }
    return { version: STATE_VERSION, config: { ...DEFAULT_CONFIG }, scans: {}, auditLog: [] };
  };

  const writeRaw = (doc) => {
    // audit P0-2 (lightweight root of trust): 0700 dir + 0600 file so the
    // record base is not world-readable; content-level signing is a
    // documented roadmap item, not pretend-shipped here
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${file}.tmp-${process.pid}`;
    writeFileSync(tmp, `${JSON.stringify(doc, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, file);
  };

  const appendAudit = (doc, event) => {
    doc.auditLog = Array.isArray(doc.auditLog) ? doc.auditLog : [];
    doc.auditLog.push({ at: new Date().toISOString(), ...event });
    if (doc.auditLog.length > 200) doc.auditLog = doc.auditLog.slice(-200);
  };

  const handle = {
    dir,
    file,
    read: readRaw,
    readConfig() {
      const doc = readRaw();
      return normalizeConfig(doc.config);
    },
    writeConfig(patch) {
      const doc = readRaw();
      doc.config = normalizeConfig({ ...doc.config, ...(patch ?? {}) });
      appendAudit(doc, { kind: 'configure', patch: patch ?? {} });
      writeRaw(doc);
      return { ...doc.config };
    },
    getScan(key) {
      const doc = readRaw();
      return doc.scans[key] ?? null;
    },
    putScan(key, entry) {
      const doc = readRaw();
      doc.scans[key] = { ...entry, key, updatedAt: new Date().toISOString() };
      writeRaw(doc);
      return doc.scans[key];
    },
    deleteScan(key) {
      const doc = readRaw();
      delete doc.scans[key];
      writeRaw(doc);
    },
    readScanIndex() {
      return { ...readRaw().scans };
    },
    /** audit P2-9: durable, append-only trail of enforcement decisions. */
    audit(event) {
      const doc = readRaw();
      appendAudit(doc, event);
      writeRaw(doc);
    },
    readAuditLog() {
      return Array.isArray(readRaw().auditLog) ? readRaw().auditLog : [];
    },
  };
  memo.set(home, handle);
  return handle;
}

/** Coerce an arbitrary object into a valid config (unknown values fall back). */
export function normalizeConfig(candidate) {
  const cfg = { ...DEFAULT_CONFIG, ...(candidate ?? {}) };
  if (!MODES.includes(cfg.mode)) cfg.mode = DEFAULT_CONFIG.mode;
  if (!AUTO_DISABLE_LEVELS.includes(cfg.autoDisableAt)) cfg.autoDisableAt = DEFAULT_CONFIG.autoDisableAt;
  if (typeof cfg.autoUpgrade !== 'boolean') cfg.autoUpgrade = DEFAULT_CONFIG.autoUpgrade;
  return cfg;
}

/**
 * The scan-record cache key. audit P1-9: `name@version` alone lets a
 * malicious package pin the version and change code freely, so the key takes
 * an optional content fingerprint (see collect.fingerprintOf). Keys stay
 * compatible: without a fingerprint they degrade to the legacy form.
 */
export function scanKey(name, version, fingerprint) {
  const base = `${name}@${version ?? '0.0.0'}`;
  return fingerprint ? `${base}#${fingerprint}` : base;
}

/** True when the stored entry still matches the live name@version(+fp). */
export function isFresh(entry, name, version, fingerprint) {
  if (!entry || entry.name !== name || entry.version !== version) return false;
  if (fingerprint !== undefined && entry.fingerprint !== undefined && entry.fingerprint !== fingerprint) return false;
  return true;
}

export function stateFilePathFor(dshHome) {
  return join(dshHome ?? resolveDshHome(), 'plugin-security', 'state.json');
}

export { existsSync };
