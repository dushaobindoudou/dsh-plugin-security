/**
 * Markdown report rendering for dsh-plugin-security.
 * @module dsh-plugin-security/report
 */

import { SEVERITIES } from './scanner.js'

const SEVERITY_ORDER = Object.fromEntries(SEVERITIES.map((severity, index) => [severity, index]))
const RISK_ADVICE = {
  clean: 'No dangerous capability observed in the shipped files.',
  notice: 'Low-risk capabilities observed; review if it matters to you.',
  review: 'Human review recommended before installing this version.',
  block: 'Do not install without review: this matches a known supply-chain attack shape.',
}

/** Render a boolean as yes/no in bold. */
const yesNo = (value) => (value ? '**yes**' : 'no')

/** Sort findings by severity, most dangerous first. */
function sortBySeverity(findings) {
  return [...findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
}

/**
 * Render an audit report as Markdown.
 * @param {object} audit - Audit result from the orchestrator.
 * @returns {string} Markdown permission card.
 */
export function renderAudit(audit) {
  const lines = []
  lines.push(`## Plugin security: ${audit.name}@${audit.version}`)
  lines.push('')
  lines.push(`**Risk: ${audit.risk.toUpperCase()}** — ${RISK_ADVICE[audit.risk]}`)
  lines.push('')
  lines.push(`> ${audit.filesScanned} shipped files scanned; ${audit.findings.length} findings (${audit.counts.critical} critical, ${audit.counts.review} review, ${audit.counts.notice} notice, ${audit.counts.info} info)`)
  lines.push('')

  const profile = audit.profile
  lines.push('### Permission profile')
  lines.push('')
  lines.push('| Surface | Observed |')
  lines.push('|---|---|')
  lines.push(`| Install scripts | ${yesNo(profile.installScripts)} |`)
  lines.push(`| Filesystem read | ${yesNo(profile.fsRead)} |`)
  lines.push(`| Filesystem write | ${yesNo(profile.fsWrite)} |`)
  lines.push(`| Child processes | ${yesNo(profile.subprocess)} |`)
  lines.push(`| Network | ${yesNo(profile.network)} |`)
  lines.push(`| Dynamic execution | ${yesNo(profile.dynamicExec)} |`)
  lines.push(`| Env variables | ${yesNo(profile.envAccess)} |`)
  lines.push(`| Credential access | ${yesNo(profile.credentialAccess)} |`)
  lines.push(`| Obfuscation indicators | ${yesNo(profile.obfuscation)} |`)
  if (profile.hosts.length > 0) lines.push(`| Outbound hosts | ${profile.hosts.map((host) => `\`${host}\``).join(', ')} |`)
  if (profile.sensitiveEnvVars.length > 0) lines.push(`| Credential-looking env | ${profile.sensitiveEnvVars.map((name) => `\`${name}\``).join(', ')} |`)
  lines.push('')

  if (audit.findings.length > 0) {
    lines.push('### Findings')
    lines.push('')
    lines.push('| severity | capability | location | evidence |')
    lines.push('|---|---|---|---|')
    for (const finding of sortBySeverity(audit.findings).slice(0, 40)) {
      lines.push(`| ${finding.severity} | ${finding.capability} | \`${finding.location}\` | \`${finding.evidence.replace(/\|/g, '\\|')}\` |`)
    }
    lines.push('')
  }

  lines.push('---')
  lines.push('Reported by `dsh-plugin-security` — static evidence, not a verdict. You decide.')
  return lines.join('\n')
}

/**
 * Render a version-diff report as Markdown.
 * @param {object} diff - Diff result from the orchestrator.
 * @returns {string} Markdown capability delta card.
 */
export function renderDiff(diff) {
  const lines = []
  lines.push(`## Plugin security diff: ${diff.name} ${diff.from} → ${diff.to}`)
  lines.push('')
  lines.push(`**Risk: ${diff.risk.toUpperCase()}** — ${RISK_ADVICE[diff.risk]}`)
  lines.push('')

  const added = diff.added
  if (added.capabilities.length === 0 && added.hosts.length === 0 && added.sensitiveEnvVars.length === 0) {
    lines.push('No new dangerous capability introduced in this update.')
    lines.push('')
  } else {
    lines.push('### New in this version')
    lines.push('')
    if (added.capabilities.length > 0) {
      lines.push(`- **Capabilities added:** ${added.capabilities.join(', ')}`)
    }
    if (added.hosts.length > 0) {
      lines.push(`- **New outbound hosts:** ${added.hosts.map((host) => `\`${host}\``).join(', ')}`)
    }
    if (added.sensitiveEnvVars.length > 0) {
      lines.push(`- **New credential-looking env:** ${added.sensitiveEnvVars.map((name) => `\`${name}\``).join(', ')}`)
    }
    lines.push('')
  }

  const removed = diff.removed
  if (removed.capabilities.length > 0 || removed.hosts.length > 0) {
    lines.push('### No longer present')
    lines.push('')
    if (removed.capabilities.length > 0) lines.push(`- Capabilities removed: ${removed.capabilities.join(', ')}`)
    if (removed.hosts.length > 0) lines.push(`- Hosts removed: ${removed.hosts.join(', ')}`)
    lines.push('')
  }

  if (diff.findings.length > 0) {
    lines.push('### New findings')
    lines.push('')
    lines.push('| severity | capability | location | evidence |')
    lines.push('|---|---|---|---|')
    for (const finding of sortBySeverity(diff.findings).slice(0, 30)) {
      lines.push(`| ${finding.severity} | ${finding.capability} | \`${finding.location}\` | \`${finding.evidence.replace(/\|/g, '\\|')}\` |`)
    }
    lines.push('')
  }

  lines.push('---')
  lines.push('Reported by `dsh-plugin-security`. Updates that add install scripts or credential access deserve a human look.')
  return lines.join('\n')
}
