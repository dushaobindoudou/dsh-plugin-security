/**
 * npm registry access and tarball extraction for dsh-plugin-security.
 * Implemented with node stdlib only: no child processes, no runtime deps.
 * @module dsh-plugin-security/tarball
 */

/** Default npm registry. */
export const DEFAULT_REGISTRY = 'https://registry.npmjs.org/'

/** Safety limits. */
const MAX_FILE_BYTES = 2 * 1024 * 1024
const MAX_TOTAL_BYTES = 64 * 1024 * 1024
const MAX_FILES = 500
const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.json', '.yml', '.yaml', '.sh', '.bash', '.md'])

/** Fetch a URL as a Buffer. */
async function fetchBuffer(url) {
  const response = await fetch(url, { redirect: 'follow' })
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`)
  const arrayBuffer = await response.arrayBuffer()
  return Buffer.from(arrayBuffer)
}

/** Registry-encode a package name for the metadata endpoint. */
function encodeName(name) {
  return name.startsWith('@') ? name.replace('/', '%2f') : name
}

/**
 * Fetch package metadata from the registry.
 * @param {string} name - Package name (scoped names supported).
 * @param {string} [registry] - Registry base URL.
 * @returns {Promise<object>} Parsed metadata document.
 */
export async function fetchMetadata(name, registry = DEFAULT_REGISTRY) {
  const url = new URL(encodeName(name), registry).toString()
  const buffer = await fetchBuffer(url)
  return JSON.parse(buffer.toString('utf8'))
}

/** Resolve the tarball URL for one version, or the dist-tag latest. */
export function resolveTarball(metadata, version) {
  if (version != null && version !== '') {
    const entry = metadata.versions?.[version]
    if (entry?.dist?.tarball == null) {
      throw new Error(`Version ${version} not found for ${metadata.name}`)
    }
    return { version, tarball: entry.dist.tarball, manifest: entry }
  }
  const latest = metadata['dist-tags']?.latest
  const entry = latest != null ? metadata.versions?.[latest] : undefined
  if (entry?.dist?.tarball == null) {
    throw new Error(`No dist-tag latest for ${metadata.name}`)
  }
  return { version: latest, tarball: entry.dist.tarball, manifest: entry }
}

/**
 * Parse a single 512-byte tar header block.
 * @param {Buffer} block - Header block.
 * @returns {{name: string, size: number, typeflag: string}} Parsed fields.
 */
function parseHeader(block) {
  const readString = (offset, length) => {
    let end = offset
    while (end < offset + length && block[end] !== 0) end += 1
    return block.subarray(offset, end).toString('utf8')
  }
  const readOctal = (offset, length) => {
    const raw = readString(offset, length).trim()
    return raw === '' ? 0 : parseInt(raw, 8)
  }
  return {
    name: readString(0, 100),
    size: readOctal(124, 12),
    typeflag: String.fromCharCode(block[156] ?? 0),
  }
}

/**
 * Extract the text files of a tar.gz archive into memory.
 * Only small text files are retained; binaries are skipped after their
 * header is read, so nothing is ever written to disk.
 * @param {Buffer} tarball - Raw .tgz bytes.
 * @returns {Promise<{files: {path: string, content: string}[]}>} Extracted text files.
 */
export async function extractTextFiles(tarball) {
  const zlib = await import('node:zlib')
  const tar = zlib.gunzipSync(tarball)

  const files = []
  let offset = 0
  let pendingLongName = null
  let totalBytes = 0

  while (offset + 512 <= tar.length) {
    const block = tar.subarray(offset, offset + 512)
    if (block.every((byte) => byte === 0)) break

    const { name, size, typeflag } = parseHeader(block)
    const dataStart = offset + 512
    const dataEnd = dataStart + size
    if (dataEnd > tar.length) throw new Error('Truncated tar entry')

    if (typeflag === 'L') {
      pendingLongName = tar.subarray(dataStart, dataEnd - 1).toString('utf8')
    } else if (typeflag === 'x') {
      const pax = tar.subarray(dataStart, dataEnd).toString('utf8')
      const pathMatch = pax.match(/\d+ path=([^\n]+)/)
      if (pathMatch) pendingLongName = pathMatch[1]
    } else if (typeflag === '0' || typeflag === '\0' || typeflag === '') {
      const entryName = pendingLongName ?? name
      pendingLongName = null

      const normalized = entryName.replace(/^package\//, '')
      const parts = normalized.split('/')
      if (normalized !== '' && !parts.some((part) => part === 'node_modules' || part === '.git')) {
        const extension = normalized.slice(normalized.lastIndexOf('.'))
        const isText = TEXT_EXTENSIONS.has(extension)
        if (isText && files.length < MAX_FILES && size <= MAX_FILE_BYTES && totalBytes + size <= MAX_TOTAL_BYTES) {
          files.push({ path: normalized, content: tar.subarray(dataStart, dataEnd).toString('utf8') })
          totalBytes += size
        }
      }
    } else {
      pendingLongName = null
    }

    offset = dataStart + Math.ceil(size / 512) * 512
  }
  return { files }
}

/**
 * Download and extract one package version from the registry.
 * @param {string} name - Package name.
 * @param {string} [version] - Optional version; defaults to latest.
 * @param {string} [registry] - Registry base URL.
 * @returns {Promise<{version: string, manifest: object, files: {path: string, content: string}[]}>}
 */
export async function fetchPackage(name, version, registry = DEFAULT_REGISTRY) {
  const metadata = await fetchMetadata(name, registry)
  const resolved = resolveTarball(metadata, version)
  const buffer = await fetchBuffer(resolved.tarball)
  const { files } = await extractTextFiles(buffer)
  return { version: resolved.version, manifest: resolved.manifest, files }
}
