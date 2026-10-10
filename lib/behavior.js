/** Bounded, intraprocedural evidence links. This is screening, not a malware verdict. */
import { parse } from 'acorn';
import { posix } from 'node:path';

const SUPPORT_PATH = /(?:^|\/)(?:test|tests|__tests__|fixtures|docs|examples|refs)(?:\/|$)|(?:^|\/)smoke[-.]|\.(?:test|spec)\.[cm]?js$/i;
const SENSITIVE_PATH = /(?:\.ssh|\.aws|\.gnupg|\.npmrc|\.git-credentials|\.netrc|Login Data|Cookies|wallet\.dat)/i;
const children = (node) => Object.values(node).flatMap((value) => Array.isArray(value) ? value : [value]).filter((value) => value && typeof value.type === 'string');
const member = (node) => node?.type === 'MemberExpression'
  ? `${member(node.object)}.${node.computed ? node.property.value : node.property.name}`
  : node?.type === 'Identifier' ? node.name : '';
const isEnv = (node) => member(node) === 'process.env';
const codeFile = (file) => /\.[cm]?js$/.test(file.rel) && typeof file.text === 'string';

function syntax(file) {
  try { return parse(file.text, { ecmaVersion: 'latest', sourceType: 'module', locations: true, allowReturnOutsideFunction: true, allowHashBang: true }); }
  catch { return null; } // Unsupported syntax never becomes proof of a behavior chain.
}

/** Keep support/vendor evidence visible; explicit local imports make support files runtime-relevant. */
export function evidenceScopes(target) {
  const files = target.files ?? [];
  const byPath = new Map(files.map((file) => [file.rel, file]));
  const reachable = new Set();
  const roots = [target.hostEntry, target.clientEntry?.rel, target.manifest?.main, 'lib/index.js', 'index.js',
    ...Object.values(typeof target.manifest?.bin === 'object' ? target.manifest.bin : { bin: target.manifest?.bin })];
  const visit = (rel) => {
    if (typeof rel !== 'string') return;
    rel = posix.normalize(rel);
    if (reachable.has(rel) || !byPath.has(rel)) return;
    reachable.add(rel);
    const file = byPath.get(rel);
    if (!codeFile(file)) return;
    const ast = syntax(file);
    if (!ast) return;
    const walk = (node) => {
      let spec;
      if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(node.type)) spec = node.source?.value;
      if (node.type === 'ImportExpression') spec = node.source?.value;
      if (node.type === 'CallExpression' && member(node.callee) === 'require') spec = node.arguments[0]?.value;
      if (typeof spec === 'string' && spec.startsWith('.')) {
        const path = posix.join(posix.dirname(rel), spec);
        for (const candidate of [path, `${path}.js`, `${path}.mjs`, `${path}.cjs`, `${path}/index.js`]) visit(candidate);
      }
      for (const child of children(node)) walk(child);
    };
    walk(ast);
  };
  for (const root of roots) visit(root);
  // Undeclared runtime sources remain scanned; path classification is not a whitelist.
  return (rel) => reachable.has(rel) ? 'runtime'
    : /(?:^|\/)node_modules\//.test(rel) ? 'dependency'
    : SUPPORT_PATH.test(rel) || (/\.(?:md|txt)$/i.test(rel) && !/(?:^|\/)skills?\//.test(rel)) ? 'support' : 'runtime';
}

/** Trace environment/credential data into a request body, or decoded bytes into execution. */
export function behaviorChains(target, scopeOf) {
  const out = [];
  for (const file of (target.files ?? []).filter(codeFile)) {
    const ast = syntax(file);
    if (!ast) continue;
    const evidence = (node) => ({ ref: `${file.rel}:${node.loc.start.line}`, snippet: file.text.slice(node.start, node.end).replace(/\s+/g, ' ').slice(0, 180) });
    const pathText = (node, bindings) => !node ? '' : node.type === 'Identifier'
      ? bindings.get(`path:${node.name}`) ?? node.name
      : node.type === 'Literal' ? String(node.value) : children(node).map((child) => pathText(child, bindings)).join('/');
    const infer = (node, bindings, seen = new Set()) => {
      if (!node || seen.has(node)) return [];
      seen.add(node);
      if (node.type === 'Identifier') return bindings.get(node.name) ?? [];
      if (/^(?:FunctionExpression|ArrowFunctionExpression)$/.test(node.type)) return [];
      if (isEnv(node)) return [{ kind: 'sensitive', evidence: evidence(node) }];
      if (node.type === 'CallExpression') {
        const callee = member(node.callee);
        if (/^(?:Buffer\.from|atob)$/.test(callee)
          && (callee === 'atob' || node.arguments[1]?.value === 'base64')) {
          return [{ kind: 'decoded', evidence: evidence(node) }];
        }
        if (/(?:^|\.)(?:readFile|readFileSync)$/.test(callee)) {
          const path = node.arguments[0];
          const resolved = pathText(path, bindings);
          if (typeof resolved === 'string' && SENSITIVE_PATH.test(resolved)) return [{ kind: 'sensitive', evidence: evidence(node) }];
        }
      }
      // A named env key is usually legitimate authentication; do not taint the whole request.
      if (node.type === 'MemberExpression' && isEnv(node.object)) return [];
      if (node.type === 'Property') return infer(node.value, bindings, seen);
      if (node.type === 'CallExpression' || node.type === 'NewExpression') return [
        ...(node.callee?.type === 'MemberExpression' ? infer(node.callee.object, bindings, seen) : []),
        ...node.arguments.flatMap((arg) => infer(arg, bindings, seen)),
      ];
      return children(node).flatMap((child) => infer(child, bindings, seen));
    };
    const report = (ruleId, node, sources, correlation) => {
      if (!sources.length) return;
      const scope = scopeOf(file.rel);
      out.push({ ruleId, severity: scope === 'runtime' ? 'high' : 'medium', kind: 'suspicious', scope,
        evidence: [...sources.map((source) => source.evidence), evidence(node)],
        extra: { correlation, confidence: 'medium', requiresReview: true } });
    };
    const walk = (node, bindings) => {
      if (/^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(node.type)) {
        const inner = new Map(bindings);
        const clear = (pattern) => {
          if (pattern.type === 'Identifier') { inner.delete(pattern.name); inner.delete(`path:${pattern.name}`); }
          else if (pattern.type === 'Property') clear(pattern.value);
          else if (pattern.type === 'AssignmentPattern') clear(pattern.left);
          else for (const child of children(pattern)) clear(child);
        };
        for (const param of node.params) clear(param);
        walk(node.body, inner);
        return;
      }
      if (node.type === 'BlockStatement') {
        const inner = new Map(bindings);
        for (const child of node.body) walk(child, inner);
        return;
      }
      if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {
        bindings.set(node.id.name, infer(node.init, bindings));
        bindings.set(`path:${node.id.name}`, pathText(node.init, bindings));
      }
      if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier') {
        bindings.set(node.left.name, infer(node.right, bindings));
        bindings.set(`path:${node.left.name}`, pathText(node.right, bindings));
      }
      if (node.type === 'CallExpression' || node.type === 'NewExpression') {
        const callee = member(node.callee);
        if (callee === 'fetch' || /\.fetch$/.test(callee)) {
          const options = node.arguments[1];
          const body = options?.type === 'ObjectExpression' ? options.properties.find((p) => (p.key?.name ?? p.key?.value) === 'body')?.value : null;
          report('net-egress', node, infer(body, bindings).filter((source) => source.kind === 'sensitive'), 'sensitive-data-to-request-body');
        }
        if (['eval', 'Function', 'vm.runInThisContext', 'vm.runInNewContext'].includes(callee)) {
          report('obfuscation', node, node.arguments.flatMap((arg) => infer(arg, bindings)).filter((source) => source.kind === 'decoded'), 'decoded-data-to-execution');
        }
      }
      for (const child of children(node)) walk(child, bindings);
    };
    walk(ast, new Map());
  }
  return out;
}

/** Severity describes review priority. API presence and support code are not malware proof. */
export function classifyFindings(target, findings, scopeOf) {
  const limits = { 'code-exec': 'medium', 'fs-sensitive': 'medium', 'net-egress': 'medium',
    'module-hijack': 'medium', 'obfuscation': 'info', 'secret-env': 'medium',
    'install-scripts': 'medium', 'dep-tree-scripts': 'medium', 'client-risk': 'medium', 'patch-semantics': 'medium' };
  return findings.flatMap((finding) => {
    const grouped = new Map();
    for (const entry of finding.evidence ?? []) {
      const path = entry.ref.replace(/:(?:\d+|\?)$/, '');
      const scope = scopeOf(path);
      (grouped.get(scope) ?? grouped.set(scope, []).get(scope)).push(entry);
    }
    return [...grouped].map(([scope, evidence]) => ({ ...finding, evidence, scope,
      severity: scope !== 'runtime' ? 'info' : limits[finding.ruleId] ?? finding.severity,
      kind: limits[finding.ruleId] || scope !== 'runtime' ? 'capability' : 'suspicious',
      extra: { ...finding.extra, requiresReview: true },
    }));
  });
}
