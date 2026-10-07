/**
 * Supply-chain security gate for DeepSeek Harness.
 * @module dsh-plugin-security
 */

import path from 'node:path'
import fs from 'node:fs/promises'
import z from 'schemastery'

import { scanFile, scanManifest, rollupRisk, permissionProfile, SEVERITIES } from './scanner.js'
import { fetchPackage, fetchMetadata, resolveTarball, DEFAULT_REGISTRY } from './tarball.js'
import { renderAudit, renderDiff } from './report.js'

/** Cordis plugin name; keep stable after publishing. */
export const name = 'dsh-plugin-security'

/** Services that must exist before the plugin is applied. */
export const inject = ['tools']

/** Loader-visible configuration schema and defaults. */
export const Config = z.object({
  registry: z.string().description('npm registry used to resolve packages and tarballs.').default(DEFAULT_REGISTRY),
})

/** JSON-schema node in the subset enforced by the host tool registry. */
function stringSchema(description) {
  return { type: 'string', description }
}

/**
 * Scan a local directory that already sits on disk.
 * @param {string} dir - Plugin directory.
 * @returns {Promise<{files: {path: string, content: string}[], manifest: object}>}
 */
async function readLocalPackage(dir) {
  const absolute = path.resolve(dir)
  const entries = await fs.readdir(absolute, { recursive: true, withFileTypes: true })
  const files = []
  for (const entry of entries) {
    if (!entry.isFile()) continue
    const relative = path.relative(absolute, path.join(entry.parentPath ?? entry.path, entry.name))
    if (relative.split(path.sep).some((part) => part === 'node_modules' || part === '.git')) continue
    const extension = path.extname(relative)
    if (!['.js', '.mjs', '.cjs', '.ts', '.json', '.yml', '.yaml', '.sh'].includes(extension)) continue
    const stat = await fs.stat(path.join(absolute, relative))
    if (stat.size > 2 * 1024 * 1024 || files.length >= 500) continue
    files.push({ path: relative, content: await fs.readFile(path.join(absolute, relative), 'utf8') })
  }
  const manifestPath = files.find((file) => file.path === 'package.json')
  const manifest = manifestPath ? JSON.parse(manifestPath.content) : {}
  return { files, manifest }
}

/**
 * Run the scanner over one package payload and aggregate results.
 * @param {object} payload - { manifest, files } from the registry or disk.
 * @returns {object} Aggregate scan output.
 */
function runScan(payload) {
  const findings = [...scanManifest(payload.manifest)]
  const envVars = new Set()
  const sensitiveEnvVars = new Set()
  const hosts = new Set()
  for (const file of payload.files) {
    const result = scanFile(file.path, file.content)
    findings.push(...result.findings)
    for (const item of result.envVars) envVars.add(item)
    for (const item of result.sensitiveEnvVars) sensitiveEnvVars.add(item)
    for (const item of result.hosts) hosts.add(item)
  }
  return { findings, envVars: [...envVars], sensitiveEnvVars: [...sensitiveEnvVars], hosts: [...hosts] }
}

/** Build the per-severity counts for a findings list. */
function countBySeverity(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]))
  for (const finding of findings) counts[finding.severity] += 1
  return counts
}

/**
 * Audit one package: npm name (any version) or local directory.
 * @param {object} options - { target, version, registry }.
 * @returns {Promise<object>} Audit value for the tool protocol.
 */
async function auditPackage(options) {
  const isPath = options.target.startsWith('.') || options.target.startsWith('/') || options.target.includes(path.sep)
  let payload
  let packageName
  let version
  if (isPath) {
    payload = await readLocalPackage(options.target)
    packageName = payload.manifest?.name ?? path.basename(path.resolve(options.target))
    version = payload.manifest?.version ?? 'unknown'
  } else {
    const fetched = await fetchPackage(options.target, options.version, options.registry)
    payload = fetched
    packageName = fetched.manifest.name ?? options.target
    version = fetched.version
  }

  const scan = runScan(payload)
  const risk = rollupRisk(scan.findings)
  const profile = permissionProfile(scan.findings, scan)
  const counts = countBySeverity(scan.findings)

  const markdown = renderAudit({
    name: packageName,
    version,
    risk,
    filesScanned: payload.files.length,
    findings: scan.findings,
    counts,
    profile,
  })
  return {
    markdown,
    risk,
    filesScanned: payload.files.length,
    findingsCount: scan.findings.length,
    profile,
  }
}

/** Set difference. */
const added = (from, to) => [...to].filter((item) => !from.includes(item))

/**
 * Compare two versions of one npm package by capability profile.
 * @param {object} options - { name, from, to, registry }.
 * @returns {Promise<object>} Diff value for the tool protocol.
 */
async function diffPackage(options) {
  const metadata = await fetchMetadata(options.name, options.registry)
  const from = await fetchPackage(options.name, options.from, options.registry)
  const to = await fetchPackage(options.name, options.to, options.registry)

  const fromScan = runScan(from)
  const toScan = runScan(to)

  const fromCapabilities = [...new Set(fromScan.findings.map((finding) => finding.capability))]
  const toCapabilities = [...new Set(toScan.findings.map((finding) => finding.capability))]
  const addedCapabilities = added(fromCapabilities, toCapabilities)
  const removedCapabilities = added(toCapabilities, fromCapabilities)

  const addedHosts = added(fromScan.hosts, toScan.hosts)
  const addedSensitiveEnv = added(fromScan.sensitiveEnvVars, toScan.sensitiveEnvVars)

  // The delta risk is judged on what the new version introduces, not on
  // capabilities the old version already had and you already accepted.
  let risk = 'clean'
  if (addedCapabilities.includes('install-script') || addedCapabilities.includes('credential-access')) risk = 'block'
  else if (addedCapabilities.some((capability) => ['fs-write', 'subprocess', 'dynamic-exec', 'obfuscation'].includes(capability))) risk = 'review'
  else if (addedCapabilities.length > 0 || addedHosts.length > 0) risk = 'notice'

  const diffFindings = toScan.findings.filter((finding) => {
    return addedCapabilities.includes(finding.capability)
      && !fromScan.findings.some((other) => other.capability === finding.capability)
  })

  const markdown = renderDiff({
    name: options.name,
    from: from.version,
    to: to.version,
    risk,
    added: { capabilities: addedCapabilities, hosts: addedHosts, sensitiveEnvVars: addedSensitiveEnv },
    removed: { capabilities: removedCapabilities, hosts: added(toScan.hosts, fromScan.hosts) },
    findings: diffFindings,
  })

  return {
    markdown,
    risk,
    added: { capabilities: addedCapabilities, hosts: addedHosts, sensitiveEnvVars: addedSensitiveEnv },
  }
}

/** Narrow unknown tool arguments to the audit shape. */
function narrowAuditArgs(args) {
  if (typeof args !== 'object' || args === null) throw new Error('plugin_security expects an object argument')
  const record = args
  if (typeof record.target !== 'string' || record.target.trim() === '') {
    throw new Error('plugin_security requires a non-empty "target" string (npm name or local path)')
  }
  return {
    target: record.target,
    version: typeof record.version === 'string' && record.version !== '' ? record.version : undefined,
  }
}

/** Narrow unknown tool arguments to the diff shape. */
function narrowDiffArgs(args) {
  if (typeof args !== 'object' || args === null) throw new Error('plugin_security_diff expects an object argument')
  const record = args
  for (const key of ['name', 'from', 'to']) {
    if (typeof record[key] !== 'string' || record[key].trim() === '') {
      throw new Error(`plugin_security_diff requires a non-empty "${key}" string`)
    }
  }
  return { name: record.name, from: record.from, to: record.to }
}

/**
 * Cordis activation: register the security tools.
 * @param {object} ctx - Cordis context.
 * @param {object} config - Resolved plugin configuration.
 */
export function apply(ctx, config) {
  const registry = config?.registry ?? DEFAULT_REGISTRY
  const tools = ctx.get('tools')
  if (tools === undefined) {
    throw new Error('dsh-plugin-security requires the "tools" service')
  }

  ctx.effect(() => {
    const unregisterAudit = tools.register({
      name: 'plugin_security',
      description:
        'Audit a DeepSeek Harness plugin BEFORE installing it. Give it an npm package name '
        + '(or a local directory path) and it downloads the shipped tarball, then reports the '
        + 'permission profile: install scripts, filesystem access, subprocess, network hosts, '
        + 'env variables, credential paths, dynamic execution and obfuscation indicators, with '
        + 'file:line evidence. Read-only by construction.',
      parameters: {
        type: 'object',
        properties: {
          target: stringSchema('npm package name, or local plugin directory path'),
          version: { type: 'string', description: 'Optional version to audit; defaults to latest.' },
        },
        required: ['target'],
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            markdown: { type: 'string' },
            risk: { type: 'string' },
            filesScanned: { type: 'number' },
            findingsCount: { type: 'number' },
          },
          required: ['markdown', 'risk', 'filesScanned', 'findingsCount'],
        },
        render: (_args, value) => [{ type: 'text', text: value.markdown }],
      },
      execute: async (args) => {
        const narrowed = narrowAuditArgs(args)
        return auditPackage({ ...narrowed, registry })
      },
      isConcurrencySafe: () => true,
    })

    const unregisterDiff = tools.register({
      name: 'plugin_security_diff',
      description:
        'Compare two versions of an npm plugin by capability profile. Downloads both tarballs, '
        + 'scans the code each version actually ships, and reports what the update ADDS: new install '
        + 'scripts, credential access, filesystem writes, subprocess, dynamic execution, outbound '
        + 'hosts or credential-looking env vars. Use it before accepting a plugin update.',
      parameters: {
        type: 'object',
        properties: {
          name: stringSchema('npm package name'),
          from: stringSchema('version you currently have or trust'),
          to: stringSchema('version you are considering'),
        },
        required: ['name', 'from', 'to'],
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            markdown: { type: 'string' },
            risk: { type: 'string' },
          },
          required: ['markdown', 'risk'],
        },
        render: (_args, value) => [{ type: 'text', text: value.markdown }],
      },
      execute: async (args) => {
        const narrowed = narrowDiffArgs(args)
        return diffPackage({ ...narrowed, registry })
      },
      isConcurrencySafe: () => true,
    })

    ctx.logger.info('dsh-plugin-security loaded: plugin_security and plugin_security_diff tools registered')

    return () => {
      unregisterAudit()
      unregisterDiff()
    }
  })
}
