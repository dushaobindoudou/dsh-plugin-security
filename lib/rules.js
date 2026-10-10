/**
 * The sentinel rule set.
 *
 * Every rule is a pure function over a scan target (see `collect.js`): it
 * reads manifests, patch text and already-loaded file text, and returns
 * findings with concrete evidence (file:line + snippet). Nothing here executes
 * target code, and nothing here mutates the target.
 *
 * Findings carry only `ruleId`, `severity` and `evidence`; human-readable
 * titles and advice live in `RULE_DEFS` so the UI and the agent tool render
 * the same taxonomy, in either language.
 *
 * Content rules dispatch by file kind (`filesOf`): CODE rules only read
 * .js/.mjs/.cjs sources, TEXT rules only read bundled .md/.txt/.json/.yml/.yaml.
 * collect.js is growing past JS sources, so the rules must filter by kind
 * themselves — a README that mentions `eval(` is not code-exec evidence, and
 * skill/locale text is exactly where prompt injection hides.
 *
 * @module rules
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { extname, join } from 'node:path';

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const SEVERITY_WEIGHT = { critical: 45, high: 20, medium: 8, low: 3, info: 0 };
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Rule metadata: stable ids, bilingual titles and advice. UI and agent tool
 * look up by id; findings never carry prose of their own.
 */
export const RULE_DEFS = {
  'install-scripts': {
    title: { zh: 'npm 安装脚本（安装期任意命令执行）', en: 'npm install scripts (arbitrary commands at install time)' },
    advice: {
      zh: '生命周期脚本可能在安装、构建或打包阶段执行命令，触发时机取决于脚本类型与安装方式。先核实实际命令、参数和来源；存在脚本本身不能证明恶意。',
      en: 'Lifecycle scripts can run commands during installation, building or packaging depending on the script and install method. Review their actual commands and origin; their presence alone is not malicious.',
    },
  },
  'dep-source': {
    title: { zh: '依赖来源绕过注册表', en: 'dependency source bypasses the registry' },
    advice: {
      zh: 'git/URL/file:/link: 依赖不经过 npm 注册表审计，内容可随时变化。固定版本并尽量走可信 registry。',
      en: 'git/URL/file:/link: dependencies skip registry review and can change at any time. Pin versions and prefer a trusted registry.',
    },
  },
  'scope-impersonation': {
    title: { zh: '包名仿冒（可信 scope 或相似名）', en: 'package name impersonation (trusted scope or lookalike)' },
    advice: {
      zh: '包名冒用 @deepseek-ai 官方 scope、或与官方包高度相似/仅分隔符不同（dsh.plugin.security 变体），是典型供应链投毒手法。核实该包的真实来源后再决定是否保留。',
      en: 'The name squats the official @deepseek-ai scope, closely mimics an official package, or differs only in separators (dsh.plugin.security variants) — classic supply-chain typosquatting. Verify the real origin before keeping it.',
    },
  },
  'code-exec': {
    title: { zh: '代码执行能力', en: 'code execution capability' },
    advice: {
      zh: '插件宿主进程内拥有与你相同的系统权限，child_process/eval 等调用等于任意命令执行。逐条确认这些调用是否是插件功能所必需。',
      en: 'Inside the plugin host the package runs with your full user privileges; child_process/eval calls are arbitrary command execution. Confirm each call site is genuinely required.',
    },
  },
  'net-egress': {
    title: { zh: '网络外联', en: 'network egress' },
    advice: {
      zh: '插件可主动向外部主机发数据（包括会话内容、密钥）。全局 fetch/WebSocket/dns 隧道等不需要 import 的通道也在此列。核对每个端点是否是该功能声明过的服务端。',
      en: 'The package can send data (including session content and secrets) to external hosts — including import-free channels such as global fetch, WebSocket and DNS tunnels. Verify every endpoint is a service the feature is supposed to talk to.',
    },
  },
  'fs-sensitive': {
    title: { zh: '敏感 / 配置路径线索', en: 'sensitive / configuration path patterns' },
    advice: {
      zh: '匹配到了凭据、宿主配置或启动配置相关路径。路径字面量、注释和检测规则不等于实际读写；配置管理与启动集成也可能合理。核实具体读写调用、访问目的、用户授权及数据去向。',
      en: 'A credential, host-config or startup-config path was matched. Literals, comments and detection rules do not establish actual access; configuration and launch integration can be legitimate. Check the actual operation, purpose, authorization and data destination.',
    },
  },
  'secret-env': {
    title: { zh: '读取敏感环境变量 / 环境整体导出', en: 'reads sensitive environment variables / dumps the whole env' },
    advice: {
      zh: '读取具名 TOKEN/API_KEY 常用于认证；完整环境复制也常用于子进程继承。核实完整环境是否进入请求体、日志或非预期存储；仅出现 process.env 或展开语法不能证明窃取。',
      en: 'Named TOKEN/API_KEY reads commonly support authentication; copying the environment commonly supports child processes. Check whether the full environment reaches requests, logs or unexpected storage. Reading or spreading process.env alone does not prove theft.',
    },
  },
  'client-risk': {
    title: { zh: '浏览器端注入 / 跨域脚本', en: 'browser-side injection / cross-origin script' },
    advice: {
      zh: '客户端代码在你的页面上下文运行：innerHTML/外域脚本/eval 可窃取页面内一切内容（含会话）。确认这些用法没有引入不可信内容。',
      en: 'Client code runs in your page context: innerHTML/remote scripts/eval can read anything on the page (sessions included). Confirm no untrusted content flows into these sinks.',
    },
  },
  'inject-surface': {
    title: { zh: '高权限宿主服务依赖', en: 'high-privilege host service dependencies' },
    advice: {
      zh: '插件声明依赖这些宿主能力（文件、进程、凭据、提示词、工具管控…）。确认与插件功能相符，宁可多问一句。',
      en: 'The plugin pulls in these host capabilities (fs, processes, credentials, prompt, tool control…). Confirm each matches the advertised feature.',
    },
  },
  'patch-config': {
    title: { zh: '补丁/配置风险（明文密钥、外部进程、外部端点）', en: 'patch/config risks (plaintext secrets, external processes, endpoints)' },
    advice: {
      zh: '补丁与配置是插件的另一张脸：明文密钥会随配置文件被读取和同步；command:/URL 配置会在宿主内执行或外联。密钥请用 apiKeyEnv 等环境变量引用。',
      en: 'Patches and configs are a plugin\'s second face: plaintext secrets travel with the config file; command:/URL entries execute or phone home. Prefer env-var references such as apiKeyEnv.',
    },
  },
  'patch-semantics': {
    title: { zh: '补丁结构操作（禁用插件 / 插入加载行 / 策略覆盖）', en: 'patch structure operations (disable / insert / policy override)' },
    advice: {
      zh: 'patch 可以改变插件加载与策略配置，也可能是正常功能集成。核实修改对象、最终生效值与用户意图；插入加载行本身不能证明恶意。',
      en: 'Patches can change plugin loading and policy configuration, including legitimate integration. Check the modified target, effective value and user intent; inserting a load row alone does not prove malicious behavior.',
    },
  },
  'tool-surface': {
    title: { zh: 'Agent 工具面 / 提示词注入面', en: 'agent tool surface / prompt-injection surface' },
    advice: {
      zh: '注册的工具、注入的提示词与流水线监听（含 llm/request、session/*、ctx.provide/ctx.command）都会直接影响模型行为（可改写请求、隐藏工具）。确认这些扩展点没有被用来误导模型。',
      en: 'Registered tools, injected prompt text and pipeline listeners (llm/request, session/*, ctx.provide/ctx.command included) directly shape model behavior (rewrite requests, hide tools). Confirm these extension points are not steering the model.',
    },
  },
  'module-hijack': {
    title: { zh: '模块 / 全局对象改写线索', en: 'module / global-object modification patterns' },
    advice: {
      zh: '模块加载器、缓存或全局对象改写可能用于测试、兼容补丁，也可能改变运行行为。核实实际赋值目标、替换内容、影响范围与执行路径；模式匹配不等于劫持结论。',
      en: 'Module-loader, cache or global-object changes can support tests and compatibility patches, or alter runtime behavior. Review the assignment target, replacement, scope and execution path; a pattern match is not a hijacking verdict.',
    },
  },
  'obfuscation': {
    title: { zh: '编码 / 长行 / 解码执行线索', en: 'encoding / long lines / decode-execution patterns' },
    advice: {
      zh: 'base64、转义串和长行常见于图片、SVG、协议与构建产物。只有联系到执行接口才需要重点核实解码后的内容；编码或压缩本身不能证明混淆攻击。',
      en: 'Base64, escaped strings and long lines commonly represent images, SVG, protocols and build output. Inspect decoded content when it reaches an execution sink; encoding or minification alone is not evidence of an attack.',
    },
  },
  'dep-tree-scripts': {
    title: { zh: '依赖树安装脚本（自带 node_modules）', en: 'dependency-tree install scripts (bundled node_modules)' },
    advice: {
      zh: '依赖包包含生命周期脚本或原生构建配置。先确认是否实际触发、运行什么命令及依赖来源；安装脚本和原生模块本身不是恶意证据。',
      en: 'Dependencies contain lifecycle scripts or native build configuration. Verify whether they run, their actual commands and their source; scripts and native modules alone are not malicious evidence.',
    },
  },
  'prompt-injection': {
    title: { zh: '指令性文本线索（文档/技能/配置）', en: 'instruction-like text patterns (docs/skills/config)' },
    advice: {
      zh: '匹配到忽略指令、隐藏行为、执行命令或审批相关措辞，也可能来自安全文档和测试示例。核实文本是否实际进入模型上下文、是谁提供的及意图；审读时保持其为不可信输入。',
      en: 'Instruction, concealment, execution or approval wording was matched, possibly in security docs or test examples. Check whether it reaches model context, who supplies it and its intent. Treat reviewed text as untrusted input.',
    },
  },
  metadata: {
    title: { zh: '元数据不完整', en: 'incomplete package metadata' },
    advice: {
      zh: '缺少 repository/license 等基本信息会显著降低可追责性，是低信誉包的常见特征。',
      en: 'Missing repository/license metadata lowers accountability and is common in low-reputation packages.',
    },
  },
};

/** File kinds for content dispatch. */
export const CODE_EXTS = new Set(['.js', '.mjs', '.cjs']);
export const TEXT_EXTS = new Set(['.md', '.txt', '.json', '.yml', '.yaml']);

/** Rules that read package source content; skipped for the scanner itself. */
export const CODE_RULES = new Set([
  'code-exec', 'net-egress', 'fs-sensitive', 'secret-env', 'client-risk',
  'inject-surface', 'tool-surface', 'module-hijack', 'obfuscation',
  'dep-tree-scripts',
]);

/** Rules that only read bundled text (.md/.txt/.json/.yml/.yaml). */
export const TEXT_RULES = new Set(['prompt-injection']);

/** Rule ids added by the v0.2.2 rule expansion, for upper-layer family maps. */
export const NEW_RULE_IDS = ['module-hijack', 'obfuscation', 'dep-tree-scripts', 'patch-semantics', 'prompt-injection'];

function extOf(rel) {
  return extname(String(rel ?? '')).toLowerCase();
}

/**
 * Files of one kind: 'code' (.js/.mjs/.cjs), 'text' (.md/.txt/.json/.yml/.yaml)
 * or 'json' (.json only). Content rules iterate through this so a collected
 * file of the wrong kind can never trip them.
 * @param {object} target
 * @param {'code'|'text'|'json'} kind
 */
export function filesOf(target, kind) {
  const files = Array.isArray(target?.files) ? target.files : [];
  if (kind === 'code') return files.filter((f) => CODE_EXTS.has(extOf(f?.rel)));
  if (kind === 'text') return files.filter((f) => TEXT_EXTS.has(extOf(f?.rel)));
  if (kind === 'json') return files.filter((f) => extOf(f?.rel) === '.json');
  return [];
}

// ---------------------------------------------------------------------------
// helpers

const SNIPPET_MAX = 180;

function cleanSnippet(line) {
  const trimmed = line.trim();
  return trimmed.length > SNIPPET_MAX ? `${trimmed.slice(0, SNIPPET_MAX)}…` : trimmed;
}

/**
 * Run a per-line regex over text; returns evidence entries.
 * @param {string|null} text
 * @param {RegExp} regex non-global recommended; reset per line anyway
 */
function lineEvidence(text, regex, rel, max = 8) {
  const out = [];
  if (typeof text !== 'string') return out;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    regex.lastIndex = 0;
    if (regex.test(lines[i])) {
      out.push({ ref: `${rel}:${i + 1}`, snippet: cleanSnippet(lines[i]) });
      if (out.length >= max) break;
    }
  }
  return out;
}

function finding(ruleId, severity, evidence, extra) {
  return extra === undefined
    ? { ruleId, severity, evidence }
    : { ruleId, severity, evidence, extra };
}

function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0 || n === 0) return m + n;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i += 1) {
    const curr = [i];
    for (let j = 1; j <= n; j += 1) {
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = curr;
  }
  return prev[n];
}

const LOCAL_HOST = /^(localhost|127\.|0\.0\.0\.0|\[?::1\]?$)/i;
const ALLOWED_HOST = /(\.|^)(deepseek\.com|npmjs\.org|github\.com|githubusercontent\.com|schemastore\.org|w3\.org)$/i;
const EXFIL_HOST = /discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com|pastebin\.com|ngrok(?:-free)?\.(?:io|app|dev)|requestbin|pipedream\.net|interact\.sh|oast\.(?:fun|fyi|site)|webhook\.site/i;

/** Egress channels that need no import at all: global fetch, WS, DNS, ... */
const GLOBAL_EGRESS = /\bfetch\s*\(|WebSocket\s*\(|new\s+Worker\s*\(|sendBeacon\s*\(|\bdns(?:\.promises)?\.(?:lookup|resolve)|\bdgram\b|http2\.(?:connect|request)|wss?:\/\//;

/** Whole-env dump shapes: reading every environment variable at once. */
const ENV_DUMP = /JSON\.stringify\(\s*process\.env|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)|\.\.\.process\.env\b/;

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function stripUrlNoise(raw) {
  return raw.replace(/[.,;:)\]}'"]+$/, '');
}

function readJsonSafe(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// rules

/** npm lifecycle scripts that execute arbitrary commands. */
export function checkInstallScripts(target) {
  const scripts = target.manifest?.scripts;
  if (scripts === null || typeof scripts !== 'object') return [];
  const bySeverity = { high: [], medium: [], low: [] };
  for (const [key, value] of Object.entries(scripts)) {
    if (typeof value !== 'string' || value.length === 0) continue;
    if (/^(pre)?install$|^postinstall$/.test(key)) {
      bySeverity.high.push({ ref: 'package.json', snippet: `scripts.${key}: ${value}` });
    } else if (key === 'prepare') {
      bySeverity.medium.push({ ref: 'package.json', snippet: `scripts.prepare: ${value}` });
    } else if (/^prepublish(Only)?$|^prepack$/.test(key)) {
      // maintainer-side only: runs at publish time, not on consumer install
      bySeverity.low.push({ ref: 'package.json', snippet: `scripts.${key}: ${value}` });
    }
  }
  const out = [];
  for (const severity of ['high', 'medium', 'low']) {
    if (bySeverity[severity].length > 0) out.push(finding('install-scripts', severity, bySeverity[severity]));
  }
  return out;
}

/** Dependencies that bypass the npm registry, by kind. */
export function checkDepSource(target) {
  const deps = target.manifest?.dependencies;
  if (deps === null || typeof deps !== 'object') return [];
  const kinds = { remote: [], alias: [], local: [], loose: [] };
  for (const [name, spec] of Object.entries(deps)) {
    if (typeof spec !== 'string') continue;
    if (/^(git\+|https?:\/\/)/.test(spec)) kinds.remote.push({ ref: 'package.json', snippet: `${name}: ${spec}` });
    else if (spec.startsWith('npm:')) kinds.alias.push({ ref: 'package.json', snippet: `${name}: ${spec}` });
    else if (/^(file:|link:)/.test(spec)) kinds.local.push({ ref: 'package.json', snippet: `${name}: ${spec}` });
    else if (spec === '*' || spec === 'latest') kinds.loose.push({ ref: 'package.json', snippet: `${name}: ${spec}` });
  }
  const out = [];
  if (kinds.remote.length > 0) out.push(finding('dep-source', 'high', kinds.remote));
  if (kinds.alias.length > 0) out.push(finding('dep-source', 'medium', kinds.alias));
  if (kinds.loose.length > 0) out.push(finding('dep-source', 'low', kinds.loose));
  if (kinds.local.length > 0) out.push(finding('dep-source', 'info', kinds.local));
  return out;
}

const nfkcFold = (name) => name.normalize('NFKC').toLowerCase();
/** NFKC + separator-insensitive key: `dsh.plugin.security` folds onto `dsh-plugin-security`. */
const nameKey = (name) => nfkcFold(name).replace(/[-._]/g, '');
const bareOf = (key) => (key.startsWith('@') ? key.split('/').pop() : key);

/**
 * Trusted-scope squatting and lookalike names — for dependencies AND for the
 * package's own name (self is legitimate by definition and skipped). Names are
 * NFKC-normalized and compared separator-insensitively, so homoglyph and
 * `dsh.plugin.security` variants fold onto their official counterparts.
 */
export function checkScopeImpersonation(target, ctx) {
  const official = Array.isArray(ctx?.officialNames) ? ctx.officialNames : [];
  if (official.length === 0) return [];
  const officialKeys = official.map((name) => {
    const folded = nfkcFold(name);
    return { name, folded, bare: bareOf(nameKey(name)) };
  });
  const scoped = [];
  const lookalike = [];
  const consider = (name, note) => {
    if (typeof name !== 'string' || name.length < 4) return;
    const folded = nfkcFold(name);
    const bare = bareOf(nameKey(name));
    // A genuine known package must not be compared against its own siblings.
    if (officialKeys.some((off) => off.folded === folded)) return;
    if (folded.startsWith('@deepseek-ai/') && !officialKeys.some((off) => nameKey(off.name) === nameKey(name))) {
      scoped.push({ ref: 'package.json', snippet: `${name}${note}` });
      return;
    }
    for (const off of officialKeys) {
      // identical once separators/homoglyphs fold, different as written
      if (bare === off.bare && folded !== off.folded && bare.length >= 6) {
        lookalike.push({ ref: 'package.json', snippet: `${name}${note} ≈ ${off.name}（分隔符/同形变体）` });
        return;
      }
      if (Math.abs(bare.length - off.bare.length) > 2 || off.bare.length < 6) continue;
      const distance = levenshtein(bare, off.bare);
      // distance 2 is only meaningful on long names; short names collide by
      // coincidence (dsh-bots ≈ dsh-jobs)
      const maxDistance = bare.length >= 12 ? 2 : 1;
      if (distance > 0 && distance <= maxDistance && bare.length >= 6) {
        lookalike.push({ ref: 'package.json', snippet: `${name}${note} ≈ ${off.name}（编辑距离 ${distance}）` });
        return;
      }
    }
  };
  if (target.self !== true) consider(target?.name, '');
  const deps = target.manifest?.dependencies;
  if (deps !== null && typeof deps === 'object') {
    for (const name of Object.keys(deps)) {
      if (name === target?.name) continue;
      if (typeof name !== 'string' || name.length < 4) continue;
      consider(name, `: ${deps[name]}`);
    }
  }
  const out = [];
  if (scoped.length > 0) out.push(finding('scope-impersonation', 'critical', scoped));
  if (lookalike.length > 0) out.push(finding('scope-impersonation', 'high', lookalike));
  return out;
}

/** Exec / eval / dynamic module loading inside package sources. */
export function checkCodeExec(target) {
  const findings = [];
  const buckets = { process: [], eval: [], dynamic: [] };
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    buckets.process.push(...lineEvidence(file.text, /(?:^|[^.\w'"])(?:require|import)\s*\(?\s*['"](?:node:)?child_process['"]/, file.rel, 4));
    buckets.process.push(...lineEvidence(file.text, /\b(execSync|spawnSync|execFileSync)\s*\(/, file.rel, 4));
    buckets.process.push(...lineEvidence(file.text, /[^.\w'](exec|spawn|execFile)\s*\(/, file.rel, 4));
    buckets.process.push(...lineEvidence(file.text, /\bprocess\.binding\s*\(/, file.rel, 3));
    buckets.eval.push(...lineEvidence(file.text, /(?:^|[^.\w'\-])eval\s*\(/, file.rel, 4));
    buckets.eval.push(...lineEvidence(file.text, /new\s+Function\s*\(/, file.rel, 4));
    buckets.eval.push(...lineEvidence(file.text, /\bvm\.(runInThisContext|runInNewContext|runInContext|compileFunction)\b/, file.rel, 3));
    buckets.dynamic.push(...lineEvidence(file.text, /\bimport\(\s*[A-Za-z_$][^'"]/, file.rel, 4));
    buckets.dynamic.push(...lineEvidence(file.text, /(?:^|[^.\w'\-])require\(\s*[A-Za-z_$][^'"]/, file.rel, 4));
  }
  if (buckets.process.length > 0) findings.push(finding('code-exec', 'high', dedupeEvidence(buckets.process)));
  if (buckets.eval.length > 0) findings.push(finding('code-exec', 'high', dedupeEvidence(buckets.eval)));
  if (buckets.dynamic.length > 0) findings.push(finding('code-exec', 'medium', dedupeEvidence(buckets.dynamic)));
  return findings;
}

/** External endpoints, network client libraries, and import-free egress calls. */
export function checkNetEgress(target) {
  const findings = [];
  const exfil = [];
  const unknown = new Map();
  const clients = [];
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    for (const match of file.text.matchAll(/https?:\/\/[^\s'"`<>(){}[\]\\]+/g)) {
      const url = stripUrlNoise(match[0]);
      const host = hostOf(url);
      if (host === null) continue;
      // template-literal fragments (`http://${host}`) and dotless hosts are
      // not endpoints
      if (!host.includes('.') && !LOCAL_HOST.test(host)) continue;
      if (EXFIL_HOST.test(host) || EXFIL_HOST.test(url)) {
        exfil.push({ ref: `${file.rel}:?`, snippet: url.slice(0, SNIPPET_MAX) });
        continue;
      }
      if (LOCAL_HOST.test(host) || ALLOWED_HOST.test(host)) continue;
      const existing = unknown.get(host) ?? { host, refs: [] };
      if (existing.refs.length < 4) existing.refs.push({ ref: `${file.rel}:?`, snippet: url.slice(0, SNIPPET_MAX) });
      unknown.set(host, existing);
    }
    clients.push(...lineEvidence(
      file.text,
      /(?:from\s*|require\(\s*)['"](node:)?(?:https?|net|tls|undici|axios|got|node-fetch)['"]/,
      file.rel, 4,
    ));
    // global fetch / WebSocket / Worker / sendBeacon / DNS tunnels / dgram /
    // http2 / ws endpoints / data: modules need no import at all — direct
    // evidence of outbound capability
    clients.push(...lineEvidence(file.text, GLOBAL_EGRESS, file.rel, 6));
    clients.push(...lineEvidence(file.text, /data:text\/javascript/, file.rel, 2));
  }
  if (exfil.length > 0) findings.push(finding('net-egress', 'critical', dedupeEvidence(exfil)));
  for (const { host, refs } of [...unknown.values()].sort((a, b) => (a.host < b.host ? -1 : 1))) {
    findings.push(finding('net-egress', 'medium', refs, { host }));
  }
  if (clients.length > 0) findings.push(finding('net-egress', 'medium', dedupeEvidence(clients)));
  return findings;
}

/** Sensitive paths, persistence mechanisms, and dsh host-config tampering. */
export function checkFsSensitive(target) {
  const findings = [];
  const critical = [];
  // Writes into the dsh host home: persistence, self-revival, killing other
  // plugins. Named separately so reviewers see the channel, not just a path.
  const dshWrite = [];
  const destructive = [];
  const home = [];
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    critical.push(...lineEvidence(file.text, /['"][^'"]*\/\.ssh(?:\/[^'"]*)?['"]|authorized_keys/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /['"][^'"]*\.aws(?:\/[^'"]*)?['"]|\.gnupg|Keychain/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /['"][^'"]*(?:Login Data|Web Data|Cookies)['"]/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /['"][^'"]*\.?(?:zshrc|bashrc|bash_profile|zprofile)['"]/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /crontab|LaunchAgents|LaunchDaemons|\/etc\/(?:passwd|shadow|sudoers)/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /wallet\.dat|metamask/i, file.rel, 3));
    // credential stores the original set missed (P1-11)
    critical.push(...lineEvidence(file.text, /['"][^'"]*\.npmrc['"]/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /['"][^'"]*\.env(?:[.\w-]*)['"]|(?:require\(\s*|from\s*)['"]dotenv(?:\/[\w.]+)?['"]/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /['"][^'"]*\.git-credentials['"]|\.netrc\b|_netrc\b/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /\.docker[\/\\]config\.json|\.kube[\/\\]config\b/, file.rel, 4));
    critical.push(...lineEvidence(file.text, /['"][^'"]*Local State['"]|\bLevelDB\b/, file.rel, 4));
    // ~/.dsh host-config tampering (read or write — the host home is the
    // most valuable target in this harness)
    dshWrite.push(...lineEvidence(file.text, /['"]~\/\.dsh|\.dsh(?:\/|['"])/, file.rel, 4));
    dshWrite.push(...lineEvidence(file.text, /cordis\.patch\.yml/, file.rel, 4));
    dshWrite.push(...lineEvidence(file.text, /profiles[\/\\][^'"\n]*package\.json/, file.rel, 4));
    dshWrite.push(...lineEvidence(file.text, /settings\.ya?ml/, file.rel, 4));
    dshWrite.push(...lineEvidence(file.text, /\bdsh\.profile\b|\bbundles\b/, file.rel, 4));
    dshWrite.push(...lineEvidence(file.text, /writeFileSync\s*\([^\n]*package\.json/, file.rel, 4));
    destructive.push(...lineEvidence(file.text, /\brm(?:Sync)?\s*\([^)]*recursive\s*:\s*true/, file.rel, 4));
    home.push(...lineEvidence(file.text, /\bos\.homedir\(\)|process\.env\.HOME\b/, file.rel, 2));
  }
  if (critical.length > 0) findings.push(finding('fs-sensitive', 'critical', dedupeEvidence(critical)));
  if (dshWrite.length > 0) findings.push(finding('fs-sensitive', 'critical', dedupeEvidence(dshWrite)));
  if (destructive.length > 0) findings.push(finding('fs-sensitive', 'high', dedupeEvidence(destructive)));
  if (home.length > 0) findings.push(finding('fs-sensitive', 'low', dedupeEvidence(home)));
  return findings;
}

/** Sensitive environment variables and whole-env dumps in package sources. */
export function checkSecretEnv(target) {
  const seen = new Map();
  const dumps = [];
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    // whole-env dump: the classic credential-theft shape the named-read loop
    // below can never see (P0-3)
    dumps.push(...lineEvidence(file.text, ENV_DUMP, file.rel, 6));
    const lines = file.text.split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      for (const match of lines[i].matchAll(/process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g)) {
        const name = match[1] ?? match[2];
        if (!/TOKEN|SECRET|API_?KEY|PASSWORD|PASSPHRASE|PRIVATE_KEY|CREDENTIAL/i.test(name)) continue;
        const entry = seen.get(name) ?? { name, refs: [] };
        if (entry.refs.length < 4) entry.refs.push({ ref: `${file.rel}:${i + 1}`, snippet: cleanSnippet(lines[i]) });
        seen.set(name, entry);
      }
    }
  }
  const out = [];
  if (dumps.length > 0) out.push(finding('secret-env', 'high', dedupeEvidence(dumps)));
  if (seen.size > 0) {
    const evidence = [];
    for (const { name, refs } of [...seen.values()].sort((a, b) => (a.name < b.name ? -1 : 1))) {
      evidence.push({ ref: refs[0].ref, snippet: `process.env.${name}` });
    }
    out.push(finding('secret-env', 'medium', evidence.slice(0, 12)));
  }
  return out;
}

/** Module-system, global-object and prototype hijacking in package sources. */
export function checkModuleHijack(target) {
  const evidence = [];
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    evidence.push(...lineEvidence(file.text, /(?<![.\w$])Module\._load\s*=(?!=)/, file.rel, 3));
    evidence.push(...lineEvidence(file.text, /(?<![.\w$])require\.cache\[[^\]\n]+\]\s*=(?!=)|\bdelete\s+require\.cache\[/, file.rel, 3));
    evidence.push(...lineEvidence(file.text, /Object\.defineProperty\(\s*(?:global|globalThis)\b/, file.rel, 3));
    evidence.push(...lineEvidence(file.text, /(?<![.\w$])(?:global|globalThis)\.\w+\s*=(?!=)/, file.rel, 4));
    evidence.push(...lineEvidence(file.text, /__proto__\s*=(?!=)|prototype\[[^\]\n]*\]\s*=(?!=)/, file.rel, 3));
    evidence.push(...lineEvidence(file.text, /(?<![.\w$])globalThis\[[^\]\n]+\]\s*=(?!=)/, file.rel, 3));
  }
  if (evidence.length === 0) return [];
  return [finding('module-hijack', 'high', dedupeEvidence(evidence))];
}

/** Obfuscation shapes: decode-then-execute, escape runs, minified blobs. */
export function checkObfuscation(target) {
  const evidence = [];
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    evidence.push(...lineEvidence(file.text, /Buffer\.from\([^)]*['"]base64['"]\s*\)|\batob\s*\(|\bString\.fromCharCode\b/, file.rel, 4));
    const lines = file.text.split('\n');
    for (let i = 0; i < lines.length && evidence.length < 12; i += 1) {
      const line = lines[i];
      const hex = line.match(/\\x[0-9a-fA-F]{2}/g);
      if (hex !== null && hex.length >= 4) {
        evidence.push({ ref: `${file.rel}:${i + 1}`, snippet: cleanSnippet(line) });
      } else if (line.length > 2000) {
        evidence.push({ ref: `${file.rel}:${i + 1}`, snippet: `单行 ${line.length} 字符（minified）: ${cleanSnippet(line)}` });
      }
    }
  }
  if (evidence.length === 0) return [];
  return [finding('obfuscation', 'medium', dedupeEvidence(evidence))];
}

const DEP_TREE_MAX_DEPTH = 3;
const DEP_TREE_MAX_PACKAGES = 200;
const DEP_TREE_LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare'];

/**
 * Install-time surface of the target's own bundled node_modules: lifecycle
 * scripts and native builds (binding.gyp) that the top-level install-scripts
 * rule never sees (P0-4/P1-7). Reads package.json files from disk — bounded
 * in depth and count — and only parses them; nothing is executed.
 */
export function checkDepTreeScripts(target) {
  const dir = target?.dir;
  if (typeof dir !== 'string' || dir.length === 0) return [];
  const root = join(dir, 'node_modules');
  if (!existsSync(root)) return [];
  const evidence = [];
  let packages = 0;
  const walk = (dirPath, depth, rel) => {
    if (depth > DEP_TREE_MAX_DEPTH || packages >= DEP_TREE_MAX_PACKAGES || evidence.length >= 12) return;
    let entries;
    try {
      entries = readdirSync(dirPath, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      if (packages >= DEP_TREE_MAX_PACKAGES || evidence.length >= 12) return;
      if (entry.name.startsWith('.') || entry.name === '.bin') continue;
      const childRel = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(join(dirPath, entry.name), depth + 1, childRel);
        continue;
      }
      if (!entry.isFile()) continue;
      if (entry.name === 'package.json') {
        packages += 1;
        const manifest = readJsonSafe(join(dirPath, entry.name));
        if (manifest === null || typeof manifest !== 'object') continue;
        const scripts = manifest.scripts;
        if (scripts === null || typeof scripts !== 'object') continue;
        for (const key of DEP_TREE_LIFECYCLE) {
          const value = scripts[key];
          if (typeof value === 'string' && value.length > 0) {
            evidence.push({ ref: childRel, snippet: `${manifest.name ?? childRel}: scripts.${key}: ${value}` });
          }
        }
      } else if (entry.name === 'binding.gyp') {
        evidence.push({ ref: childRel, snippet: 'binding.gyp（原生编译脚本，安装期可执行任意代码）' });
      }
    }
  };
  walk(root, 0, 'node_modules');
  if (evidence.length === 0) return [];
  return [finding('dep-tree-scripts', 'high', dedupeEvidence(evidence))];
}

/** Browser-side injection and cross-origin loading in client code. */
export function checkClientRisk(target) {
  const clientFiles = target.files.filter(
    (f) => CODE_EXTS.has(extOf(f?.rel)) && (/client/i.test(f.rel) || f.rel === target.clientEntry?.rel),
  );
  if (target.clientEntry !== null && !clientFiles.some((f) => f.rel === target.clientEntry.rel)
    && CODE_EXTS.has(extOf(target.clientEntry?.rel)) && typeof target.clientEntry.text === 'string') {
    clientFiles.push({ rel: target.clientEntry.rel, abs: target.clientEntry.abs, text: target.clientEntry.text });
  }
  if (clientFiles.length === 0) return [];
  const buckets = { injection: [], crossOrigin: [], page: [], boot: [] };
  for (const file of clientFiles) {
    if (typeof file.text !== 'string') continue;
    buckets.injection.push(...lineEvidence(file.text, /\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(/, file.rel, 4));
    buckets.injection.push(...lineEvidence(file.text, /(?:^|[^.\w'\-])eval\s*\(|new\s+Function\s*\(/, file.rel, 4));
    buckets.crossOrigin.push(...lineEvidence(file.text, /(?:src|href)\s*=\s*['"]https?:\/\/|createElement\(\s*['"](?:script|iframe)['"]\s*\)/, file.rel, 4));
    buckets.page.push(...lineEvidence(file.text, /postMessage\s*\([^,]+,\s*['"]\*['"]\)|document\.cookie|window\.open\s*\(/, file.rel, 4));
    buckets.boot.push(...lineEvidence(file.text, /__DSH_BOOT__|localStorage|sessionStorage/, file.rel, 3));
  }
  const out = [];
  if (buckets.injection.length > 0) out.push(finding('client-risk', 'high', dedupeEvidence(buckets.injection)));
  if (buckets.crossOrigin.length > 0) out.push(finding('client-risk', 'high', dedupeEvidence(buckets.crossOrigin)));
  if (buckets.page.length > 0) out.push(finding('client-risk', 'medium', dedupeEvidence(buckets.page)));
  if (buckets.boot.length > 0) out.push(finding('client-risk', 'low', dedupeEvidence(buckets.boot)));
  return out;
}

/** Host service dependencies declared via `inject` lists. */
export function checkInjectSurface(target) {
  const RISKY = {
    fs: { zh: '文件系统', en: 'filesystem' },
    subprocess: { zh: '进程执行', en: 'process execution' },
    terminals: { zh: '终端/进程', en: 'terminals/processes' },
    shell: { zh: 'Shell', en: 'shell' },
    credentials: { zh: '凭据读取', en: 'credential reads' },
    approval: { zh: '审批策略（可放行工具调用）', en: 'approval policy (can wave tool calls through)' },
    tools: { zh: '工具注册与管控（可隐藏/拒绝其他工具）', en: 'tool registry & control (can hide/deny other tools)' },
    systemPrompt: { zh: '系统提示词（可注入模型指令）', en: 'system prompt (can inject model instructions)' },
    llm: { zh: '模型调用（可消耗额度/伪造请求）', en: 'LLM calls (can spend quota / forge requests)' },
    connection: { zh: '连接/RPC 通道', en: 'connection/RPC channel' },
    webServer: { zh: 'HTTP 路由（可暴露端点）', en: 'HTTP routes (can expose endpoints)' },
    sandbox: { zh: '沙箱', en: 'sandbox' },
    sandboxPolicy: { zh: '沙箱策略', en: 'sandbox policy' },
    authorization: { zh: '授权流程', en: 'authorization flows' },
    sessionPersistence: { zh: '会话持久化（可读取会话内容）', en: 'session persistence (can read session content)' },
    sessions: { zh: '会话列表', en: 'session list' },
    agents: { zh: '代理管理', en: 'agent management' },
    storage: { zh: '存储', en: 'storage' },
  };
  const declared = [];
  const evidence = [];
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    for (const match of file.text.matchAll(/export\s+const\s+inject\s*=\s*\[([^\]]*)\]/g)) {
      for (const name of [...match[1].matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1])) {
        declared.push(name);
        if (evidence.length < 12) evidence.push({ ref: `${file.rel}:?`, snippet: `inject: '${name}'` });
      }
    }
  }
  const clientInject = target.manifest?.dsh?.client?.inject;
  if (Array.isArray(clientInject)) {
    for (const name of clientInject) {
      if (typeof name === 'string') declared.push(name);
    }
  }
  if (declared.length === 0) return [];
  const risky = [...new Set(declared.filter((name) => RISKY[name] !== undefined))];
  const other = [...new Set(declared.filter((name) => RISKY[name] === undefined))];
  const out = [];
  if (risky.length > 0) {
    out.push(finding('inject-surface', 'medium', evidence.filter((e) => risky.some((r) => e.snippet.includes(r)))));
  }
  if (other.length > 0) {
    out.push(finding('inject-surface', 'info', [{ ref: 'manifest/exports', snippet: other.join(', ') }]));
  }
  return out;
}

/** Secret literals, external commands and endpoints inside patch/config text. */
export function checkPatchConfig(target) {
  if (typeof target.patchText !== 'string' || target.patchText.length === 0) return [];
  const label = target.source === 'profile-patch' ? 'profile cordis.patch.yml' : 'cordis.patch.yml';
  const secrets = [];
  const commands = [];
  const hosts = new Map();
  const lines = target.patchText.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const secretMatch = line.match(/^\s*(apiKey|api_key|apikey|token|secret|password|passphrase|clientSecret|client_secret|accessKey|access_key|privateKey|private_key)\s*:\s*(.+?)\s*(?:#.*)?$/i);
    if (secretMatch !== null) {
      const raw = secretMatch[2].trim().replace(/^['"]|['"]$/g, '').trim();
      const isEnvRef = /^[A-Z][A-Z0-9_]*$/.test(raw) || raw.startsWith('${') || /^(env|ENV)$/.test(raw);
      const isPlaceholder = /^(?:x{3,}|test|tests|changeme|your[-_].*|<.*>|\$\{.*\}|\*\*\*)$/i.test(raw);
      if (!isEnvRef && !isPlaceholder && raw.length >= 8) {
        secrets.push({ ref: `${label}:${i + 1}`, snippet: `${secretMatch[1]}: ${raw.slice(0, 3)}***（已脱敏，长度 ${raw.length}）` });
      } else if (!isEnvRef && !isPlaceholder && raw.length >= 4) {
        secrets.push({ ref: `${label}:${i + 1}`, snippet: `${secretMatch[1]}: ${raw.slice(0, 2)}***（疑似弱口令，长度 ${raw.length}）` });
      }
    }
    const cmdMatch = line.match(/^\s*(?:command|cmd)\s*:\s*['"]?(npx|uvx|node|python3?|bash|sh|zsh|curl|wget|osascript|powershell|pwsh)\b/i);
    if (cmdMatch !== null) commands.push({ ref: `${label}:${i + 1}`, snippet: cleanSnippet(line) });
    for (const match of line.matchAll(/https?:\/\/[^\s'"#]+/g)) {
      const url = stripUrlNoise(match[0]);
      const host = hostOf(url);
      if (host === null) continue;
      if (!host.includes('.') && !LOCAL_HOST.test(host)) continue;
      if (LOCAL_HOST.test(host) || ALLOWED_HOST.test(host)) continue;
      if (EXFIL_HOST.test(host)) {
        secrets.push({ ref: `${label}:${i + 1}`, snippet: `${url.slice(0, SNIPPET_MAX)}` });
        continue;
      }
      if (!hosts.has(host)) hosts.set(host, { ref: `${label}:${i + 1}`, snippet: url.slice(0, SNIPPET_MAX) });
    }
  }
  const out = [];
  if (secrets.length > 0) out.push(finding('patch-config', 'high', secrets.slice(0, 12)));
  if (commands.length > 0) out.push(finding('patch-config', 'medium', commands.slice(0, 8)));
  if (hosts.size > 0) {
    out.push(finding('patch-config', 'medium', [...hosts.values()].slice(0, 10), { host: [...hosts.keys()].join(', ') }));
  }
  return out;
}

/**
 * Structural patch operations in a plugin's own bundle patch: disabling other
 * plugins, inserting loader rows for itself, overriding approval/sandbox/
 * systemPrompt policy (P1-12). The profile's own patch is the user's
 * composition — inserts and disabled rows there are how profiles mount plugins
 * — so the profile-patch pseudo-target is skipped (its content risks stay with
 * patch-config; a plugin writing that file is caught by fs-sensitive).
 */
export function checkPatchSemantics(target) {
  if (target.source === 'profile-patch') return [];
  if (typeof target.patchText !== 'string' || target.patchText.length === 0) return [];
  const label = 'cordis.patch.yml';
  const disabled = [];
  const inserts = [];
  const overrides = [];
  const lines = target.patchText.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/disabled\s*:\s*true\b/.test(line)) {
      disabled.push({ ref: `${label}:${i + 1}`, snippet: cleanSnippet(line) });
    }
    const inlineInsert = line.match(/^\s*-\s+insert\s*:\s*(\S.*)$/);
    if (inlineInsert !== null) {
      // the inline value (or a `name:` key in the entry below) is the row mounted
      inserts.push({ ref: `${label}:${i + 1}`, snippet: cleanSnippet(line) });
    } else if (/^\s*-\s+insert\s*:\s*$/.test(line)) {
      const entry = lines.slice(i + 1, i + 5).find((l) => /^\s*(?:-\s+)?name\s*:/.test(l));
      if (entry !== undefined) inserts.push({ ref: `${label}:${i + 1}`, snippet: cleanSnippet(line) });
    }
    if (/approval|sandbox|tools\.guard|systemPrompt/i.test(line)) {
      overrides.push({ ref: `${label}:${i + 1}`, snippet: cleanSnippet(line) });
    }
  }
  const out = [];
  if (disabled.length > 0) out.push(finding('patch-semantics', 'high', disabled.slice(0, 8)));
  if (inserts.length > 0) out.push(finding('patch-semantics', 'medium', inserts.slice(0, 8)));
  if (overrides.length > 0) out.push(finding('patch-semantics', 'medium', overrides.slice(0, 8)));
  return out;
}

/** Prompt-injection patterns in bundled text: zh + en steering phrases. */
const PROMPT_INJECTION_PATTERNS = [
  /忽略(?:以上|之前|上述)(?:的)?(?:所有)?指令/,
  /\bignore\s+(?:all\s+)?(?:previous|prior|above)/i,
  /不要告诉(?:用户|任何人)/,
  /\bdo\s+not\s+(?:tell|inform|reveal)\b/i,
  /隐藏(?:这个|该|此)(?:行为|指令|工具)/,
  /\bhide\s+(?:this|the)\s+(?:tool|instruction|behavior|capability)\b/i,
  /执行以下命令/,
  /\brun\s+the\s+following\s+(?:command|code)\b/i,
  /绕过(?:审批|确认|沙箱)/,
  /\bbypass\s+(?:approval|confirmation|sandbox)\b/i,
  /你在不知不觉中/,
  /\bsystem\s*prompt\b/i,
];

/**
 * Instruction-steering text in bundled md/txt/json/yml (P0-5): skills,
 * locale files and READMEs are model-facing content and a prime injection
 * surface. Text files only — the same words in code are not this rule.
 */
export function checkPromptInjection(target) {
  const evidence = [];
  for (const file of filesOf(target, 'text')) {
    if (typeof file.text !== 'string') continue;
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
      evidence.push(...lineEvidence(file.text, pattern, file.rel, 4));
      if (evidence.length >= 12) break;
    }
    if (evidence.length >= 12) break;
  }
  if (evidence.length === 0) return [];
  return [finding('prompt-injection', 'high', dedupeEvidence(evidence))];
}

/** Agent-facing extension points in package sources. */
export function checkToolSurface(target) {
  const buckets = { register: [], control: [], prompt: [], pipeline: [], fsUse: [] };
  for (const file of filesOf(target, 'code')) {
    if (typeof file.text !== 'string') continue;
    buckets.register.push(...lineEvidence(file.text, /\btools\.register\s*\(/, file.rel, 3));
    buckets.control.push(...lineEvidence(file.text, /\btools\.(guard|restrict)\s*\(/, file.rel, 3));
    buckets.prompt.push(...lineEvidence(file.text, /\bsystemPrompt\.section\s*\(|\bagent\.inject\s*\(/, file.rel, 3));
    buckets.pipeline.push(...lineEvidence(
      file.text,
      /\bon\(\s*['"](agent\/pre-step|agent\/request|agent\/response|agent\/message|agent\/assistant-stream|llm\/request|llm\/stream|tools\/pre-execute|tools\/execute|tools\/post-execute|tools\/result|session\/[a-z-]+)['"]/,
      file.rel, 4,
    ));
    buckets.pipeline.push(...lineEvidence(file.text, /\bctx\.(?:provide|command)\s*\(/, file.rel, 3));
    buckets.fsUse.push(...lineEvidence(file.text, /(?:from\s*|require\(\s*)['"]node:?fs(?:\/promises)?['"]/, file.rel, 2));
  }
  const out = [];
  if (buckets.control.length > 0) out.push(finding('tool-surface', 'medium', dedupeEvidence(buckets.control)));
  if (buckets.prompt.length > 0) out.push(finding('tool-surface', 'medium', dedupeEvidence(buckets.prompt)));
  if (buckets.pipeline.length > 0) out.push(finding('tool-surface', 'medium', dedupeEvidence(buckets.pipeline)));
  if (buckets.register.length > 0) out.push(finding('tool-surface', 'info', dedupeEvidence(buckets.register)));
  if (buckets.fsUse.length > 0) out.push(finding('tool-surface', 'low', dedupeEvidence(buckets.fsUse)));
  return out;
}

/** Package metadata completeness. */
export function checkMetadata(target) {
  const manifest = target.manifest;
  if (manifest === null || typeof manifest !== 'object' || target.source === 'profile-patch') return [];
  const evidence = [];
  if (manifest.repository === undefined) evidence.push({ ref: 'package.json', snippet: '缺少 repository 字段' });
  if (manifest.license === undefined) evidence.push({ ref: 'package.json', snippet: '缺少 license 字段' });
  if (manifest.author === undefined && manifest.maintainers === undefined) evidence.push({ ref: 'package.json', snippet: '缺少 author 字段' });
  if (manifest.version === '0.0.0') evidence.push({ ref: 'package.json', snippet: `version: ${manifest.version}` });
  if (evidence.length === 0) return [];
  return [finding('metadata', evidence.some((e) => e.snippet.includes('0.0.0')) ? 'low' : 'info', evidence)];
}

function dedupeEvidence(entries) {
  const seen = new Set();
  const out = [];
  for (const entry of entries) {
    if (seen.has(entry.ref)) continue;
    seen.add(entry.ref);
    out.push(entry);
    if (out.length >= 12) break;
  }
  return out;
}

/** The ordered rule pipeline; `ctx` carries cross-target facts. */
export function runRules(target, ctx) {
  const rules = target.self === true
    ? [checkInstallScripts, checkDepSource, checkScopeImpersonation, checkPatchConfig, checkMetadata]
    : [
      checkInstallScripts,
      checkDepSource,
      checkScopeImpersonation,
      checkCodeExec,
      checkNetEgress,
      checkFsSensitive,
      checkSecretEnv,
      checkModuleHijack,
      checkObfuscation,
      checkDepTreeScripts,
      checkClientRisk,
      checkInjectSurface,
      checkPatchConfig,
      checkPatchSemantics,
      checkPromptInjection,
      checkToolSurface,
      checkMetadata,
    ];
  const findings = [];
  for (const rule of rules) {
    try {
      findings.push(...rule(target, ctx));
    } catch {
      // a broken rule must never fail the whole scan
    }
  }
  return findings;
}
