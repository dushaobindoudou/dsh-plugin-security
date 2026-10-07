import assert from 'node:assert/strict'
import { test } from 'node:test'

import { scanFile, scanManifest, rollupRisk, permissionProfile } from '../lib/scanner.js'
import { extractTextFiles } from '../lib/tarball.js'
import { renderAudit } from '../lib/report.js'
import fs from 'node:fs/promises'
import path from 'node:path'

const fixturePath = new URL('../fixtures/suspicious/index.js', import.meta.url).pathname
const fixture = await fs.readFile(fixturePath, 'utf8')

test('scanner flags a classic supply-chain implant', () => {
  const result = scanFile('fixtures/suspicious/index.js', fixture)
  const capabilities = new Set(result.findings.map((finding) => finding.capability))

  assert.ok(capabilities.has('subprocess'), 'detects child_process usage')
  assert.ok(capabilities.has('fs-read'), 'detects filesystem reads')
  assert.ok(capabilities.has('network'), 'detects network egress')
  assert.ok(capabilities.has('credential-access'), 'detects credential paths')
  assert.ok(capabilities.has('dynamic-exec'), 'detects eval')
  assert.ok(capabilities.has('env-access'), 'detects process.env')
  assert.ok(capabilities.has('obfuscation'), 'detects base64 blobs')
  assert.ok(result.sensitiveEnvVars.includes('NPM_TOKEN'), 'extracts sensitive env names')
  assert.ok(result.hosts.includes('collector.evil.example.com'), 'extracts outbound hosts')
})

test('install scripts are critical findings', () => {
  const findings = scanManifest({
    name: 'x',
    scripts: { postinstall: 'node ./collect.js' },
  })
  const install = findings.find((finding) => finding.capability === 'install-script')
  assert.ok(install, 'install script detected')
  assert.equal(install.severity, 'critical')
  assert.equal(install.location, 'package.json#scripts.postinstall')
})

test('install script plus network reaches block risk', () => {
  const findings = [
    { capability: 'install-script', severity: 'critical', location: 'package.json', evidence: '' },
    { capability: 'network', severity: 'notice', location: 'a.js:1', evidence: 'fetch(' },
  ]
  assert.equal(rollupRisk(findings), 'block')
})

test('a clean plugin reports clean', () => {
  assert.equal(rollupRisk([]), 'clean')
})

test('credential mention alone does not block', () => {
  const findings = [
    { capability: 'credential-access', severity: 'review', location: 'a.js:1', evidence: '.npmrc' },
    { capability: 'network', severity: 'notice', location: 'a.js:2', evidence: 'fetch(' },
  ]
  assert.equal(rollupRisk(findings), 'review')
})

test('report renders a permission card', async () => {
  const result = scanFile('fixtures/suspicious/index.js', fixture)
  const findings = [
    ...result.findings,
    ...scanManifest({ name: 'fixture', peerDependencies: { cordis: '*' }, dsh: { bundle: { patch: './x.yml' } } }),
  ]
  const scan = { ...result, hosts: result.hosts }
  const markdown = renderAudit({
    name: 'fixture-suspicious',
    version: '1.0.0',
    risk: rollupRisk(findings),
    filesScanned: 1,
    findings,
    counts: { critical: 1, review: 2, notice: 3, info: 0 },
    profile: permissionProfile(findings, scan),
  })
  assert.ok(markdown.includes('## Plugin security: fixture-suspicious@1.0.0'))
  assert.ok(markdown.includes('Permission profile'))
  assert.ok(markdown.includes('collector.evil.example.com'))
})

test('tar extraction reads this package', async () => {
  // Build an in-memory tarball from our own directory listing to validate
  // the pure-JS tar parser without touching the network.
  const zlib = await import('node:zlib')
  const file = path.basename(fixturePath)
  const content = fixture
  const name = 'package/fixtures/' + file
  const header = Buffer.alloc(512)
  header.write(name, 0, 100)
  header.write((content.length.toString(8) + '\0'), 124, 12)
  header[156] = 0x30
  header.write('ustar', 257, 6)
  const pad = Buffer.alloc((512 - (content.length % 512)) % 512)
  const tar = Buffer.concat([header, Buffer.from(content), pad, Buffer.alloc(1024)])
  const gz = zlib.gzipSync(tar)
  const extracted = await extractTextFiles(gz)
  assert.ok(extracted.files.some((entry) => entry.path === 'fixtures/' + file))
})

console.log('dsh-plugin-security smoke tests passed')
