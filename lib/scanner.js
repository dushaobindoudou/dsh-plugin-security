/**
 * Static capability scanner for dsh-plugin-security.
 * Scans the code a plugin actually ships (not just its source tree)
 * and reports every dangerous capability with file:line evidence.
 * @module dsh-plugin-security/scanner
 */

import path from 'node:path'

/** Finding severities, ordered from harmless to dangerous. */
export const SEVERITIES = ['info', 'notice', 'review', 'critical']

/** Script hooks that run during npm install — the classic supply-chain vector. */
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare']

/** File extensions whose content is scanned as text. */
const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.json', '.yml', '.yaml', '.sh', '.bash'])

/** Directories that never ship meaningful code. */
const SKIP_DIRS = new Set(['node_modules', '.git', '.DS_Store'])

/**
 * Detection rules. Each rule inspects one source line and may emit a finding.
 * Rules are intentionally conservative: they match code that *can* exercise a
 * capability, which is exactly what a pre-install gate needs to surface.
 */
const RULES = [
  {
    capability: 'fs-read',
    severity: 'notice',
    label: 'Filesystem read',
    patterns: [/require\(\s*['"](?:node:)?fs['"]\)/, /from\s+['"](?:node:)?fs['"]/, /\bfs\.(?:readFile|readFileSync|readdir|readdirSync|stat|statSync|open|createReadStream)\b/, /\bfs\.promises\.readFile\b/],
  },
  {
    capability: 'fs-write',
    severity: 'review',
    label: 'Filesystem write',
    patterns: [/\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|rm|rmSync|unlink|unlinkSync|rmdir|mkdir|mkdirSync|rename|renameSync|truncate|createWriteStream|cp|cpSync)\b/, /\bfs\.promises\.(?:writeFile|rm|unlink|mkdir|rename|cp)\b/],
  },
  {
    capability: 'subprocess',
    severity: 'review',
    label: 'Child processes',
    patterns: [/require\(\s*['"](?:node:)?child_process['"]\)/, /from\s+['"](?:node:)?child_process['"]/, /\b(?:execSync|spawnSync|execFileSync|spawn|execFile|exec)\s*\(/, /\bchild_process\./],
  },
  {
    capability: 'network',
    severity: 'notice',
    label: 'Network',
    patterns: [/require\(\s*['"](?:node:)?https?['"]\)/, /from\s+['"](?:node:)?https?['"]/, /\bfetch\s*\(/, /\bhttps?\.request\s*\(/, /\baxios\b/, /\bnode-fetch\b/, /\bundici\b/, /\bgot\s*\(/, /\bXMLHttpRequest\b/, /\bWebSocket\b/],
  },
  {
    capability: 'dynamic-exec',
    severity: 'review',
    label: 'Dynamic code execution',
    patterns: [/\beval\s*\(/, /\bnew\s+Function\s*\(/, /\bvm\.(?:runInContext|runInNewContext|runInThisContext|Script)\b/, /\bFunction\s*\(\s*['"`]/],
  },
  {
    capability: 'env-access',
    severity: 'notice',
    label: 'Environment variables',
    patterns: [/process\.env(?:\.[A-Za-z_$][\w$]*|\[)/],
  },
  {
    capability: 'credential-access',
    severity: 'review',
    label: 'Credential access',
    patterns: [/\.npmrc/, /_authToken/, /\.ssh\b/, /id_rsa/, /id_ed25519/, /\.aws\/credentials/, /(?<!process)\.env\b/, /\.gnupg/, /keychain/i, /credentials\.json/i, /\.kube\/config/, /\.docker\/config\.json/, /service[_-]?account.*\.json/i, /private[_-]?key/i, /\bmnemonic\b/i, /\bwallet\.dat\b/i, /\.wallet\b/],
  },
  {
    capability: 'obfuscation',
    severity: 'review',
    label: 'Possible obfuscation',
    patterns: [/['"][A-Za-z0-9+/=]{120,}['"]/, /\bBuffer\.from\(\s*['"][A-Za-z0-9+/=]{80,}['"]/],
  },
]

/** Environment variable names that carry secrets. */
const SENSITIVE_ENV = /token|secret|password|passwd|api[_-]?key|auth|credential|private|mnemonic|seed|key/i

/** Extract `process.env.NAME` occurrences from a line. */
function extractEnvNames(line) {
  const names = []
  const direct = line.matchAll(/process\.env\.([A-Za-z_$][\w$]*)/g)
  for (const match of direct) names.push(match[1])
  const bracket = line.matchAll(/process\.env\[\s*['"]([^'"]+)['"]\s*\]/g)
  for (const match of bracket) names.push(match[1])
  return names
}

/** Extract likely outbound hosts from a line. */
function extractHosts(line) {
  const hosts = new Set()
  for (const match of line.matchAll(/https?:\/\/([^/\s'"`)]+)/g)) {
    const host = match[1].split('@').pop().split(':')[0]
    const valid = /^[a-z0-9.*-]+$/i.test(host)
    if (host && valid && host.includes('.') && !host.endsWith('.local')) hosts.add(host)
  }
  for (const match of line.matchAll(/hostname\s*[:=]\s*['"]([^'"]+)['"]/g)) {
    if (/^[a-z0-9.*-]+$/i.test(match[1])) hosts.add(match[1])
  }
  return [...hosts]
}

/**
 * Scan one in-memory file.
 * @param {string} file - Path relative to the package root.
 * @param {string} content - File content.
 * @returns {{findings: object[], envVars: string[], sensitiveEnvVars: string[], hosts: string[]}}
 */
export function scanFile(file, content) {
  const findings = []
  const envVars = new Set()
  const sensitiveEnvVars = new Set()
  const hosts = new Set()

  const lines = content.split('\n')
  const scanned = TEXT_EXTENSIONS.has(path.extname(file))

  for (const [index, line] of lines.entries()) {
    const location = `${file}:${index + 1}`
    if (scanned) {
      for (const rule of RULES) {
        for (const pattern of rule.patterns) {
          if (pattern.test(line)) {
            findings.push({
              capability: rule.capability,
              severity: rule.severity,
              location,
              evidence: line.trim().slice(0, 160),
            })
            break
          }
        }
      }
      for (const name of extractEnvNames(line)) {
        envVars.add(name)
        if (SENSITIVE_ENV.test(name)) sensitiveEnvVars.add(name)
      }
      for (const host of extractHosts(line)) hosts.add(host)
    }
  }
  return { findings, envVars: [...envVars], sensitiveEnvVars: [...sensitiveEnvVars], hosts: [...hosts] }
}

/**
 * Analyze a package manifest for install-time code execution and metadata red flags.
 * @param {object} manifest - Parsed package.json.
 * @returns {object[]} Manifest findings.
 */
export function scanManifest(manifest) {
  const findings = []
  const scripts = manifest?.scripts ?? {}
  for (const hook of INSTALL_SCRIPTS) {
    if (typeof scripts[hook] === 'string' && scripts[hook].trim() !== '') {
      findings.push({
        capability: 'install-script',
        severity: 'critical',
        location: 'package.json#scripts.' + hook,
        evidence: scripts[hook].slice(0, 160),
      })
    }
  }
  if (manifest?.peerDependencies?.cordis == null && manifest?.dependencies?.cordis == null) {
    findings.push({
      capability: 'manifest',
      severity: 'info',
      location: 'package.json',
      evidence: 'No cordis peer dependency declared; may not be a dsh plugin.',
    })
  }
  const hasBundle = manifest?.dsh?.bundle?.patch != null
  if (!hasBundle) {
    findings.push({
      capability: 'manifest',
      severity: 'info',
      location: 'package.json#dsh.bundle',
      evidence: 'No dsh.bundle patch declared; plugin may not load in the harness.',
    })
  }
  return findings
}

/**
 * Roll a set of findings into an overall risk level.
 * @param {object[]} findings - All findings.
 * @returns {'clean'|'notice'|'review'|'block'} Risk level.
 */
export function rollupRisk(findings) {
  const capabilities = new Set(findings.map((finding) => finding.capability))

  // The classic npm supply-chain attack: code runs at install time and
  // immediately reaches for credentials, the network, or a shell.
  if (capabilities.has('install-script') && (capabilities.has('network') || capabilities.has('credential-access') || capabilities.has('subprocess') || capabilities.has('fs-write') || capabilities.has('obfuscation'))) {
    return 'block'
  }
  // Obfuscated code that also touches credentials is never legitimate.
  if (capabilities.has('credential-access') && capabilities.has('obfuscation') && capabilities.has('dynamic-exec')) {
    return 'block'
  }
  if (capabilities.has('install-script') || capabilities.has('credential-access')) return 'review'
  if (capabilities.has('fs-write') || capabilities.has('subprocess') || capabilities.has('dynamic-exec') || capabilities.has('obfuscation')) return 'review'
  if (capabilities.has('network') || capabilities.has('env-access') || capabilities.has('fs-read')) return 'notice'
  return 'clean'
}

/**
 * Summarise a scan into a permission profile.
 * @param {object[]} findings - All findings.
 * @param {object} scan - Aggregate scan output.
 * @returns {object} Permission profile.
 */
export function permissionProfile(findings, scan) {
  const has = (capability) => findings.some((finding) => finding.capability === capability)
  return {
    fsRead: has('fs-read'),
    fsWrite: has('fs-write'),
    subprocess: has('subprocess'),
    network: has('network'),
    dynamicExec: has('dynamic-exec'),
    envAccess: has('env-access'),
    credentialAccess: has('credential-access'),
    installScripts: has('install-script'),
    obfuscation: has('obfuscation'),
    hosts: scan.hosts,
    envVars: scan.envVars,
    sensitiveEnvVars: scan.sensitiveEnvVars,
  }
}
