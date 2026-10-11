/**
 * Call-time gate. Every tool call is attributed to the plugin package that
 * registered the tool, then decided in the host `tools/pre-execute`
 * waterfall before the tool body runs:
 *
 *   - plugin disabled by the user          → deny
 *   - plugin never scanned at this version → scan it now, then decide
 *   - high risk, no stored decision        → ask: 允许一次 / 允许 / 禁用
 *   - anything else                        → next policy (host approval etc.)
 *
 * The question is a `ctx.userQuestions` card, the same seam dsh's own
 * permission flows use for structured answers. When it cannot reach the user
 * (no web client, a delegated child agent), the call falls back to the host's
 * native approval prompt (allow once / reject). `允许` is remembered for the
 * installed version; `禁用` blocks the package name until it is enabled again
 * in the settings page.
 *
 * Attribution: the host tool registry does not record owners, so this module
 * wraps `register()` on the registry prototype and reads the caller's loader
 * entry (`ctx.fiber.entry`). Tools registered before this plugin started fall
 * back to the tool names each scan record extracted from the package source.
 *
 * Internal failures fail open (the call proceeds and a warning is logged);
 * a stored `block` decision always denies.
 *
 * @module dsh-plugin-security/gate
 */

import { isProtected } from './disposition.js';
import { riskOf } from './risk.js';
import { resolvePackageDir } from './collect.js';
import { openState } from './state.js';

/** Package name for a loader module specifier (`pkg/lib/x` → `pkg`). */
export function packageOfModule(spec) {
  if (typeof spec !== 'string' || spec.length === 0) return null;
  if (/^(?:\.|\/|[a-z]:[\\/]|file:|node:)/i.test(spec)) return null;
  const parts = spec.split('/');
  if (spec.startsWith('@')) return parts.length >= 2 && parts[1] ? `${parts[0]}/${parts[1]}` : null;
  return parts[0];
}

/** The package whose loader entry owns `ctx`, walking up child fibers. */
export function ownerOfContext(ctx) {
  let fiber = ctx?.fiber;
  for (let depth = 0; fiber && depth < 64; depth += 1) {
    const name = packageOfModule(fiber.entry?.options?.name);
    if (name) return name;
    const next = fiber.parent?.fiber;
    if (!next || next === fiber) break;
    fiber = next;
  }
  return null;
}

/** Tool → owner map fed by the register() wrapper. */
export function createToolOwners() {
  const byDefinition = new WeakMap();
  const byName = new Map();
  return {
    record(definition, owner) {
      if (definition === null || typeof definition !== 'object' || !owner) return;
      byDefinition.set(definition, owner);
      if (typeof definition.name === 'string') byName.set(definition.name, owner);
    },
    ownerOf(name, definition) {
      return (definition !== null && typeof definition === 'object' ? byDefinition.get(definition) : undefined) ?? byName.get(name) ?? null;
    },
  };
}

const ATTRIBUTION = Symbol.for('dsh-plugin-security.tool-attribution');

/**
 * Wrap `register()` on the tool registry prototype so each registration
 * reports its caller context. Cordis resolves service methods through the
 * prototype on every access and binds `this.ctx` to the caller, so the wrapper
 * sees the registering plugin. Reentrant installs share one wrapper.
 *
 * @returns disposer restoring the original method, or null when unsupported
 */
export function installToolAttribution(tools, owners) {
  const proto = tools !== null && typeof tools === 'object' ? Object.getPrototypeOf(tools) : null;
  if (proto === null || typeof proto.register !== 'function') return null;
  let slot = proto[ATTRIBUTION];
  if (slot === undefined) {
    const original = proto.register;
    slot = { original, sinks: new Set(), wrapped: null };
    const current = slot;
    slot.wrapped = function register(definition) {
      for (const sink of current.sinks) {
        try { sink(definition, this?.ctx); } catch { /* attribution never breaks registration */ }
      }
      return current.original.call(this, definition);
    };
    Object.defineProperty(proto, ATTRIBUTION, { value: slot, configurable: true });
    proto.register = slot.wrapped;
  }
  const sink = (definition, callerCtx) => owners.record(definition, ownerOfContext(callerCtx));
  slot.sinks.add(sink);
  return () => {
    slot.sinks.delete(sink);
    if (slot.sinks.size === 0 && proto[ATTRIBUTION] === slot) {
      if (proto.register === slot.wrapped) proto.register = slot.original;
      delete proto[ATTRIBUTION];
    }
  };
}

/**
 * The decision table. Pure.
 *
 * @param {{owner: string|null, config: object, policy: object|null, entry: object|null, version: string|null|undefined}} input
 * @returns {{kind: 'pass'|'deny'|'scan'|'ask', reason: string, risk?: object}}
 */
export function decideGate({ owner, config, policy, entry, version }) {
  if (config?.mode === 'off' || !owner) return { kind: 'pass', reason: 'not-gated' };
  if (isProtected(owner, config)) return { kind: 'pass', reason: 'protected' };
  if (policy?.decision === 'block') return { kind: 'deny', reason: 'blocked' };
  if (entry === null || entry === undefined) return { kind: 'scan', reason: 'unscanned' };
  const risk = entry.risk ?? riskOf(entry);
  if (risk.level !== 'high') return { kind: 'pass', reason: `risk-${risk.level}`, risk };
  if (policy?.decision === 'allow' && (policy.version ?? null) === (version ?? entry.version ?? null)) {
    return { kind: 'pass', reason: 'allowed', risk };
  }
  return { kind: 'ask', reason: risk.reason, risk };
}

/** Option labels per language; answers in either language are accepted. */
export const CHOICE_LABELS = Object.freeze({
  zh: Object.freeze({ once: '允许一次', allow: '允许', block: '禁用' }),
  en: Object.freeze({ once: 'Allow once', allow: 'Allow', block: 'Disable' }),
});

/** Map a user-questions answer to `once` / `allow` / `block`, or null. */
export function choiceOf(answer) {
  const item = answer?.answers?.find((a) => a?.id === QUESTION_ID) ?? answer?.answers?.[0];
  const label = item?.selected?.[0];
  for (const labels of Object.values(CHOICE_LABELS)) {
    for (const [choice, text] of Object.entries(labels)) if (label === text) return choice;
  }
  return null;
}

export const QUESTION_ID = 'plugin-security-gate';

/** Host locale guess for host-rendered text: `zh` or `en`. */
export function localeOf(env = process.env) {
  const tag = env.DSH_LOCALE ?? env.LC_ALL ?? env.LC_MESSAGES ?? env.LANG ?? (() => {
    try { return Intl.DateTimeFormat().resolvedOptions().locale; } catch { return ''; }
  })();
  return /^zh/i.test(String(tag)) ? 'zh' : 'en';
}

const RISK_TEXT = {
  zh: { riskConfirmed: '审读确认存在恶意行为', riskAdvisory: '存在高危依赖漏洞' },
  en: { riskConfirmed: 'a review confirmed malicious behavior', riskAdvisory: 'it has high or critical dependency advisories' },
};

/** Build the three-option question for one high-risk plugin. */
export function buildQuestion({ owner, tool, version, entry, risk }, lang = 'zh') {
  const zh = lang === 'zh';
  const labels = CHOICE_LABELS[zh ? 'zh' : 'en'];
  const at = version ? `${owner}@${version}` : owner;
  const why = RISK_TEXT[zh ? 'zh' : 'en'][risk?.reason] ?? (zh ? '被标记为高危' : 'it is marked high risk');
  const detail = [zh ? `风险依据：${why}。` : `Why: ${why}.`];
  const advisories = (Array.isArray(entry?.deps?.advisories) ? entry.deps.advisories : [])
    .filter((a) => ['critical', 'high'].includes(a?.severity)).slice(0, 3);
  for (const a of advisories) {
    detail.push(`- [${a.severity}] ${a.dep}: ${a.title}${a.fixedIn ? (zh ? `（修复于 ${a.fixedIn}）` : ` (fixed in ${a.fixedIn})`) : ''}`);
  }
  if (entry?.review?.reason) detail.push((zh ? '审读理由：' : 'Review: ') + entry.review.reason);
  detail.push(zh ? '之后可在「设置 → 插件安全门」中修改。' : 'You can change this later in Settings → Security.');
  return {
    id: QUESTION_ID,
    header: zh ? '插件安全' : 'Plugin security',
    question: zh
      ? `高危插件 ${at} 请求调用工具 ${tool}，是否允许？`
      : `High-risk plugin ${at} wants to run the tool ${tool}. Allow it?`,
    detail: detail.join('\n'),
    options: [
      { label: labels.once, description: zh ? '只放行这一次调用，下次继续询问' : 'Run this call only; ask again next time' },
      { label: labels.allow, description: zh ? `始终允许 ${at}；插件更新到新版本后重新询问` : `Always allow ${at}; a new version asks again` },
      { label: labels.block, description: zh ? `禁止 ${owner} 的所有工具调用，可在设置中重新启用` : `Deny every tool call from ${owner}; re-enable it in Settings` },
    ],
    multiSelect: false,
  };
}

function denial(owner, tool, code, lang) {
  const zh = lang === 'zh';
  const reason = code === 'PLUGIN_BLOCKED'
    ? (zh
      ? `插件安全门已禁用插件 ${owner}，工具 ${tool} 未执行。不要重试该插件的工具；如需使用，请用户在「设置 → 插件安全门」中重新启用。`
      : `The plugin security gate has disabled ${owner}; ${tool} did not run. Do not retry this plugin's tools; the user can re-enable it in Settings → Security.`)
    : (zh
      ? `用户未允许高危插件 ${owner} 的工具 ${tool} 运行，工具未执行。`
      : `The user did not allow the high-risk plugin ${owner} to run ${tool}; the tool did not run.`);
  return { kind: 'deny', reason, info: { name: 'PluginSecurityGate', code, reason } };
}

/**
 * Build the gate around injected dependencies (all IO is injected so the
 * decision flow is testable without a host).
 *
 * @param {object} deps
 * @param {object} deps.state           openState() handle
 * @param {object} deps.owners          createToolOwners() map
 * @param {(name: string, agent?: object) => object|undefined} [deps.lookup]  registry lookup for definition identity
 * @param {(name: string) => string|null|undefined} deps.installedVersion
 * @param {(name: string) => Promise<unknown>} deps.scan  on-demand scan of one package
 * @param {() => object|undefined} deps.userQuestions
 * @param {'zh'|'en'} [deps.lang]
 * @param {(message: string) => void} [deps.warn]
 */
export function createCallGate(deps) {
  const lang = deps.lang ?? 'zh';
  const warn = deps.warn ?? (() => {});
  const asking = new Map();
  const scanning = new Map();

  /** Owner by runtime registration, then by scan-record tool names. */
  const ownerOf = (exec) => {
    let definition;
    try { definition = deps.lookup?.(exec.name, exec.agent); } catch { definition = undefined; }
    const runtime = deps.owners.ownerOf(exec.name, definition);
    if (runtime) return runtime;
    const claimed = new Set();
    for (const entry of Object.values(deps.state.readScanIndex())) {
      if (Array.isArray(entry?.tools) && entry.tools.includes(exec.name)) claimed.add(entry.name);
    }
    return claimed.size === 1 ? [...claimed][0] : null;
  };

  const scanOnce = (owner) => {
    let pending = scanning.get(owner);
    if (pending === undefined) {
      pending = Promise.resolve()
        .then(() => deps.scan(owner))
        .catch((error) => warn(`on-demand scan of ${owner} failed: ${error?.message ?? error}`))
        .finally(() => scanning.delete(owner));
      scanning.set(owner, pending);
    }
    return pending;
  };

  /** One question per plugin at a time; concurrent calls share the answer. */
  const askOnce = (owner, exec, entry, version, risk) => {
    let pending = asking.get(owner);
    if (pending === undefined) {
      pending = (async () => {
        const service = deps.userQuestions();
        if (service === undefined || service === null || typeof service.ask !== 'function' || exec.agent === undefined) {
          return { fallback: true };
        }
        let answer;
        try {
          answer = await service.ask({
            agent: exec.agent,
            signal: exec.signal,
            questions: [buildQuestion({ owner, tool: exec.name, version, entry, risk }, lang)],
          });
        } catch (error) {
          if (exec.signal?.aborted || error?.code === 'ASK_ABORTED') return { cancelled: true };
          // delegated child agents and absent clients cannot answer a card
          return { fallback: true };
        }
        const choice = choiceOf(answer);
        deps.state.audit({ kind: 'gate-ask', name: owner, version: version ?? null, tool: exec.name, choice: choice ?? 'none' });
        if (choice === 'allow') deps.state.setPolicy(owner, { decision: 'allow', version: version ?? entry?.version ?? null, by: 'user-prompt' });
        if (choice === 'block') deps.state.setPolicy(owner, { decision: 'block', by: 'user-prompt' });
        return { choice };
      })().finally(() => asking.delete(owner));
      asking.set(owner, pending);
    }
    return pending;
  };

  /** The pre-execute decision for one call, or null to pass to `next()`. */
  const decide = async (exec) => {
    const owner = ownerOf(exec);
    if (!owner) return null;
    const config = deps.state.readConfig();
    if (config.mode === 'off' || isProtected(owner, config)) return null;
    const version = deps.installedVersion(owner);
    const find = () => deps.state.findScan(owner, version === undefined ? undefined : version);
    let entry = find();
    let decision = decideGate({ owner, config, policy: deps.state.getPolicy(owner), entry, version });
    if (decision.kind === 'scan') {
      await scanOnce(owner);
      entry = find();
      decision = decideGate({ owner, config, policy: deps.state.getPolicy(owner), entry, version });
      // a scan that produced no record cannot establish high risk
      if (decision.kind === 'scan') return null;
    }
    if (decision.kind === 'deny') return denial(owner, exec.name, 'PLUGIN_BLOCKED', lang);
    if (decision.kind !== 'ask') return null;
    const outcome = await askOnce(owner, exec, entry, version, decision.risk);
    if (outcome.cancelled) return { kind: 'cancel' };
    if (outcome.fallback) {
      const en = buildQuestion({ owner, tool: exec.name, version, entry, risk: decision.risk }, 'en');
      const zh = buildQuestion({ owner, tool: exec.name, version, entry, risk: decision.risk }, 'zh');
      return {
        kind: 'ask',
        reason: `${en.question}\n${en.detail}`,
        displayReason: { en: `${en.question}\n${en.detail}`, zh: `${zh.question}\n${zh.detail}` },
      };
    }
    if (outcome.choice === 'once' || outcome.choice === 'allow') return null;
    return denial(owner, exec.name, outcome.choice === 'block' ? 'PLUGIN_BLOCKED' : 'PLUGIN_NOT_ALLOWED', lang);
  };

  return {
    ownerOf,
    decide,
    /** `tools/pre-execute` listener body. */
    async handle(exec, next) {
      let decision;
      try {
        decision = await decide(exec);
      } catch (error) {
        warn(`call gate failed open for ${exec?.name}: ${error?.message ?? error}`);
        decision = null;
        try {
          const owner = ownerOf(exec);
          if (owner && deps.state.getPolicy(owner)?.decision === 'block') decision = denial(owner, exec.name, 'PLUGIN_BLOCKED', lang);
        } catch { /* stay open */ }
      }
      return decision ?? next();
    },
  };
}

const VERSION_TTL_MS = 10_000;

/**
 * Wire the gate into a host context: attribution on `ctx.tools`, the
 * `tools/pre-execute` listener, and user questions read at call time (an
 * optional service — without it the gate falls back to host approval).
 *
 * @param {object} ctx Cordis context with `tools`
 * @param {{env: object, scan: (name: string) => Promise<unknown>}} options
 * @returns disposer, or null when the host has no tool registry
 */
export function installCallGate(ctx, { env, scan }) {
  const tools = typeof ctx?.get === 'function' ? ctx.get('tools') : undefined;
  if (tools === undefined || tools === null || typeof ctx.on !== 'function') return null;
  const owners = createToolOwners();
  const detach = installToolAttribution(tools, owners);
  const versions = new Map();
  const roots = [env.profileRoot, env.globalRoot].filter((root) => typeof root === 'string');
  const gate = createCallGate({
    state: openState(env.dshHome),
    owners,
    lookup: (name, agent) => (typeof tools.get === 'function' ? tools.get(name, agent) : undefined),
    installedVersion(name) {
      const hit = versions.get(name);
      if (hit !== undefined && Date.now() - hit.at < VERSION_TTL_MS) return hit.version;
      const resolved = resolvePackageDir(name, roots);
      const version = resolved === null ? undefined
        : typeof resolved.manifest?.version === 'string' ? resolved.manifest.version : null;
      versions.set(name, { at: Date.now(), version });
      return version;
    },
    scan,
    userQuestions: () => ctx.get('userQuestions'),
    lang: localeOf(),
    warn: (message) => ctx.logger?.warn?.(`plugin-security: ${message}`),
  });
  const off = ctx.on('tools/pre-execute', (exec, next) => gate.handle(exec, next));
  return () => {
    try { off?.(); } catch { /* best-effort */ }
    try { detach?.(); } catch { /* best-effort */ }
  };
}
