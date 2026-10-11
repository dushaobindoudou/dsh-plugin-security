/**
 * dsh-plugin-security - client half (web).
 *
 * Registers the "插件安全门 / Security Gate" settings page (settings.section).
 * Talks to the host `security` Remote namespace through the connection RPC
 * carrier — the same contract the dsh-recovery doctor page established.
 *
 * Page responsibilities:
 *  - the disposition report: per-plugin action badge (disable / upgrade /
 *    review / allow), screening summary, dependency advisories, evidence
 *  - the gate configuration: mode (off / report-only / enforce), the
 *    review-gated enforcement, the upgrade suggestion switch
 *  - undo for an executed auto-disable (re-adds the name to profile bundles)
 *
 *  - per-plugin call-gate switch: enable / disable / default, the same
 *    decision the high-risk prompt (允许 / 禁用) stores
 *
 * The page mutates through `security/configure`, `security/reenable`,
 * `security/policy`, `security/uninstall` and `security/upgrade`. Styling uses only `--dsw-alias-*` theme
 * tokens; the `ps-` class prefix stands for "plugin security".
 * `state-warn-primary` (not `state-warning-primary`) is the warning token.
 */
window.__ModuleLoader__.load({
  id: 'dsh-plugin-security',
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    const React = require('react');
    const h = React.createElement;

    /** Dictionary namespace owned by this plugin. */
    const NS = 'settings.security';

    /** Simplified Chinese dictionary and key source of truth. */
    const zh = {
      localeCode: 'zh',
      tab: '安全',
      subtitle: 'Security Gate',
      loading: '正在运行安全门…',
      rescan: '强制重扫',
      rescanning: '扫描中…',
      scanFailed: '运行失败',
      pluginsLabel: '插件',
      freshLabel: '本次新扫',
      cachedLabel: '复用记录',
      all: '全部',
      riskHigh: '高危',
      riskSome: '有风险',
      riskNone: '无风险',
      riskMeaning: '高危：已确认恶意或记录到高危依赖漏洞；有风险：存在需核实的行为、其他漏洞或检查不完整；无风险：本次检查未发现风险，不代表保证安全。普通 API 能力记录不单独判为风险。',
      riskConfirmed: '已确认恶意行为',
      riskAdvisory: '存在依赖漏洞',
      riskBehavior: '存在需核实的行为线索',
      riskIncomplete: '检查或审读尚不完整',
      riskClear: '本次检查未发现风险',
      searchPlaceholder: '搜索插件名称',
      searchLabel: '搜索插件',
      listTitle: '插件列表',
      whitelistTab: '白名单',
      whitelistChoose: '选择插件加入白名单',
      whitelistAddPlugin: '加入白名单',
      whitelistRemovePlugin: '移出白名单',
      whitelistDefault: '默认保护',
      whitelistDefaultHint: '默认保护名单不可在此移除',
      whitelistNotInstalled: '未安装的白名单记录',
      whitelistRowHint: '白名单内插件跳过检查与处置',
      autoDisableLabel: '自动停用阈值',
      autoDisableNever: '从不',
      autoDisableCritical: '仅 critical',
      autoDisableHigh: 'high 及以上',
      autoDisableHint: '仅对高置信度恶意审读结论自动停用；静态线索不会自动停用。“从不”关闭自动停用。',
      autoUpgradeLabel: '自动升级建议',
      sevCritical: '优先核实',
      sevHigh: '重点核实',
      sevMedium: '一般线索',
      sevLow: '低优先级',
      sevInfo: '提示',
      unreviewed: '未审读',
      reviewedBenign: '已审读 · 用途合理',
      reviewedMalicious: '已审读 · 恶意',
      reviewedSuspicious: '已审读 · 有风险',
      skipped: '未检查',
      capability: '能力记录',
      reviewPriority: '复核优先级',
      noPriority: '未见重点线索',
      scopeRuntime: '插件代码',
      scopeSupport: '测试 / 文档',
      scopeDependency: '依赖代码',
      staticHint: '静态命中不是恶意判定。调用进程、联网、读取配置或 base64 解码都有正常用途；需结合数据流、执行路径与插件功能核实。未审读插件不会因静态规则自动禁用。',
      noAdvisories: '未记录漏洞',
      findingsLabel: '发现',
      adviceLabel: '建议',
      evidenceLabel: '证据',
      clean: '未命中静态规则',
      cleanHint: '扫描范围内没有线索，不代表已审读或保证安全',
      selfNote: '自检包',
      sourceProfile: 'profile 插件',
      sourceBuiltin: '官方内置',
      sourceExternal: '外部链接',
      sourceMissing: '未解析到包目录',
      sourceProfilePatch: 'profile 补丁',
      endpointHosts: '外部主机',
      expand: '展开 {count} 项发现',
      collapse: '收起',
      exportJson: '导出 JSON',
      exportMd: '导出 Markdown',
      lastScan: '生成于 {at} · 耗时 {ms}ms',
      notesTitle: '说明',
      emptyFilter: '当前过滤条件下没有插件。',
      statusLabel: '行状态',
      // gate config
      configTitle: '处置配置',
      modeLabel: '模式',
      modeOff: '关闭',
      modeOffHint: '不扫描、不处置',
      modeReport: '只提示',
      modeReportHint: '扫描并记录，不修改被扫插件',
      modeEnforce: '处置',
      modeEnforceHint: '仅高置信度恶意审读结论可自动禁用；静态线索只复核',
      autoUpgradeOn: '开启',
      autoUpgradeOff: '关闭',
      autoUpgradeHint: '开启后对依赖漏洞给出升级命令（升级引入新代码，不会静默执行）',
      configSaved: '配置已保存',
      configureFailed: '配置保存失败',
      // disposition
      actionDisable: '停用',
      actionUpgrade: '升级',
      actionReview: '待复核',
      actionAllow: '无需处置',
      dispositionsLabel: '处置',
      restartHint: '已从 profile 移除并隔离包目录，重启宿主后生效',
      undoDisable: '撤销禁用',
      reenableOk: '已恢复 {name}（重启宿主后生效）',
      reenableFailed: '恢复失败',
      depsLabel: '依赖',
      depsWorst: '依赖最坏等级',
      advisoriesLabel: '依赖漏洞',
      noFix: '无修复版本',
      fixedIn: '修复于',
      reviewLabel: '审读结论',
      cachedNote: '沿用 {at} 的扫描记录',
      scannedAtLabel: '扫描于 {at}',
      protectedNote: '保护名单（永不自动禁用）：本插件、官方 @deepseek-ai/* 与 dsh-plugin-sentinel',
      actionLabel: '处置',
      reasonLabel: '依据',
      upgradeCmdLabel: '升级命令',
      // threats panel (request #4/#5)
      threatsTitle: '待复核与依赖漏洞',
      threatsEmpty: '暂无需复核的线索',
      uninstall: '卸载',
      uninstallConfirm: '确认卸载 {name}？将从 profile 移除并删除包文件（pnpm remove）。',
      uninstallOk: '已卸载 {name}',
      uninstallFailed: '卸载失败',
      upgradeBtn: '升级',
      upgradeConfirm: '确认升级 {name}？将执行记录的 pnpm add 命令，升级会安装新代码。',
      upgradeOk: '已升级 {name}，下次扫描重新审计',
      upgradeFailed: '升级失败',
      whitelistTitle: '白名单（不检查）',
      whitelistHint: '名单内的插件完全跳过扫描与处置；默认保护名单（本插件、官方 @deepseek-ai/*、dsh-plugin-sentinel）始终生效',
      whitelistPlaceholder: '插件包名',
      whitelistAdd: '添加',
      whitelistRemove: '移除',
      whitelistEmpty: '暂无自定义白名单',
      whitelistInvalid: '包名不合法',
      trustedBadge: '白名单',
      trustedCount: '白名单跳过',
      // call gate (per-plugin enable / disable)
      policyBlockedTab: '已禁用',
      policyBlocked: '调用已禁用',
      policyAllowed: '已允许 {version}',
      policyEnable: '启用',
      policyDisable: '禁用',
      policyReset: '恢复默认',
      policyBlockedHint: '该插件的所有工具调用都会被拦截；点「启用」恢复',
      policyAllowedHint: '已允许该版本调用，不再询问；插件更新后重新判断',
      policyOk: '已更新 {name} 的调用设置',
      policyFailed: '调用设置失败',
      gateHint: '调用拦截：高危插件的工具被调用时会询问「允许一次 / 允许 / 禁用」。「启用」等同允许，「禁用」拦截该插件的全部工具调用，立即生效，无需重启。',
    };

    /** English dictionary; keys mirror {@link zh} exactly. */
    const en = {
      localeCode: 'en',
      tab: 'Security',
      subtitle: 'Security Gate',
      loading: 'Running the security gate…',
      rescan: 'Force rescan',
      rescanning: 'Scanning…',
      scanFailed: 'Run failed',
      pluginsLabel: 'plugins',
      freshLabel: 'fresh',
      cachedLabel: 'from records',
      all: 'All',
      riskHigh: 'High risk',
      riskSome: 'Risk detected',
      riskNone: 'No risk detected',
      riskMeaning: 'High risk: confirmed malicious behavior or high/critical dependency advisories. Risk detected: unresolved behavior, other advisories or incomplete checks. No risk detected: none found in this scan, not a safety guarantee. API capability observations alone do not establish risk.',
      riskConfirmed: 'Confirmed malicious behavior',
      riskAdvisory: 'Dependency advisories recorded',
      riskBehavior: 'Behavior needs verification',
      riskIncomplete: 'Checks or review are incomplete',
      riskClear: 'No risk detected in this scan',
      searchPlaceholder: 'Search plugin names',
      searchLabel: 'Search plugins',
      listTitle: 'Plugins',
      whitelistTab: 'Whitelist',
      whitelistChoose: 'Select a plugin to whitelist',
      whitelistAddPlugin: 'Add to whitelist',
      whitelistRemovePlugin: 'Remove from whitelist',
      whitelistDefault: 'Default protection',
      whitelistDefaultHint: 'Default protection cannot be removed here',
      whitelistNotInstalled: 'Uninstalled whitelist entry',
      whitelistRowHint: 'Whitelisted plugins skip scanning and disposal',
      autoDisableLabel: 'Auto-disable threshold',
      autoDisableNever: 'Never',
      autoDisableCritical: 'Critical only',
      autoDisableHigh: 'High and above',
      autoDisableHint: 'Only high-confidence malicious reviews can auto-disable. Static evidence never auto-disables. Never turns automatic disabling off.',
      autoUpgradeLabel: 'Upgrade suggestions',
      sevCritical: 'Urgent review',
      sevHigh: 'Focused review',
      sevMedium: 'Observation',
      sevLow: 'Low priority',
      sevInfo: 'Info',
      unreviewed: 'Not reviewed',
      reviewedBenign: 'Reviewed · legitimate use',
      reviewedMalicious: 'Reviewed · malicious',
      reviewedSuspicious: 'Reviewed · risk unresolved',
      skipped: 'Not scanned',
      capability: 'Capability',
      reviewPriority: 'Review priority',
      noPriority: 'No priority observations',
      scopeRuntime: 'Plugin code',
      scopeSupport: 'Tests / docs',
      scopeDependency: 'Dependency code',
      staticHint: 'Static matches are not malware verdicts. Process execution, networking, configuration access and base64 decoding have legitimate uses. Review data flow, execution paths and feature purpose. Static findings never auto-disable an unreviewed plugin.',
      noAdvisories: 'No recorded advisories',
      findingsLabel: 'findings',
      adviceLabel: 'Advice',
      evidenceLabel: 'Evidence',
      clean: 'No static matches',
      cleanHint: 'no observations in the scanned scope; not a review or safety guarantee',
      selfNote: 'self-check',
      sourceProfile: 'profile plugin',
      sourceBuiltin: 'official built-in',
      sourceExternal: 'external link',
      sourceMissing: 'package dir not resolved',
      sourceProfilePatch: 'profile patch',
      endpointHosts: 'hosts',
      expand: 'Expand {count} findings',
      collapse: 'Collapse',
      exportJson: 'Export JSON',
      exportMd: 'Export Markdown',
      lastScan: 'Generated {at} · {ms}ms',
      notesTitle: 'Notes',
      emptyFilter: 'No plugins under the current filter.',
      statusLabel: 'row status',
      configTitle: 'Disposition config',
      modeLabel: 'Mode',
      modeOff: 'Off',
      modeOffHint: 'no scanning, no enforcement',
      modeReport: 'Report-only',
      modeReportHint: 'scan and report, change nothing',
      modeEnforce: 'Enforce',
      modeEnforceHint: 'Only high-confidence malicious reviews can auto-disable; static evidence needs review',
      autoUpgradeOn: 'on',
      autoUpgradeOff: 'off',
      autoUpgradeHint: 'shows upgrade commands for vulnerable deps (an upgrade pulls new code and is never run silently)',
      configSaved: 'Config saved',
      configureFailed: 'Failed to save config',
      actionDisable: 'Disable',
      actionUpgrade: 'Upgrade',
      actionReview: 'Needs review',
      actionAllow: 'No action needed',
      dispositionsLabel: 'Dispositions',
      restartHint: 'removed from profile and quarantined, effective after restart',
      undoDisable: 'Undo disable',
      reenableOk: 'Restored {name} (effective after restart)',
      reenableFailed: 'Failed to restore',
      depsLabel: 'deps',
      depsWorst: 'deps worst',
      advisoriesLabel: 'Dependency advisories',
      noFix: 'no fix yet',
      fixedIn: 'fixed in',
      reviewLabel: 'Review',
      cachedNote: 'record from {at}',
      scannedAtLabel: 'scanned {at}',
      protectedNote: 'Protected list (never auto-disabled): this plugin, official @deepseek-ai/*, dsh-plugin-sentinel',
      actionLabel: 'Action',
      reasonLabel: 'Because',
      upgradeCmdLabel: 'Upgrade command',
      // threats panel (request #4/#5)
      threatsTitle: 'Review queue and dependency advisories',
      threatsEmpty: 'No observations needing review',
      uninstall: 'Uninstall',
      uninstallConfirm: 'Uninstall {name}? Removes it from the profile and deletes the package files (pnpm remove).',
      uninstallOk: 'Uninstalled {name}',
      uninstallFailed: 'Uninstall failed',
      upgradeBtn: 'Upgrade',
      upgradeConfirm: 'Upgrade {name}? Runs the recorded pnpm add command — this installs new code.',
      upgradeOk: 'Upgraded {name}; the next scan re-audits it',
      upgradeFailed: 'Upgrade failed',
      whitelistTitle: 'Whitelist (not scanned)',
      whitelistHint: 'Plugins on this list skip scanning and disposal entirely; the default protection seats (this plugin, official @deepseek-ai/*, dsh-plugin-sentinel) always apply',
      whitelistPlaceholder: 'package name',
      whitelistAdd: 'Add',
      whitelistRemove: 'Remove',
      whitelistEmpty: 'No custom whitelist entries',
      whitelistInvalid: 'invalid package name',
      trustedBadge: 'whitelisted',
      trustedCount: 'skipped (whitelist)',
      policyBlockedTab: 'Disabled',
      policyBlocked: 'Calls disabled',
      policyAllowed: 'Allowed {version}',
      policyEnable: 'Enable',
      policyDisable: 'Disable',
      policyReset: 'Reset',
      policyBlockedHint: 'Every tool call from this plugin is blocked; choose Enable to restore it',
      policyAllowedHint: 'This version may run without asking; a new version is judged again',
      policyOk: 'Updated call settings for {name}',
      policyFailed: 'Failed to update call settings',
      gateHint: 'Call gate: a tool call into a high-risk plugin asks Allow once / Allow / Disable. Enable equals Allow; Disable blocks every tool call from the plugin. Changes apply immediately, without a restart.',
    };

    const SEV_KEY = {
      critical: 'sevCritical', high: 'sevHigh', medium: 'sevMedium', low: 'sevLow', info: 'sevInfo',
    };
    const SOURCE_KEY = {
      profile: 'sourceProfile', builtin: 'sourceBuiltin', external: 'sourceExternal',
      missing: 'sourceMissing', 'profile-patch': 'sourceProfilePatch',
    };
    const ACTION_KEY = {
      disable: 'actionDisable', upgrade: 'actionUpgrade', review: 'actionReview', allow: 'actionAllow',
    };
    const Icon = ({ name, size = 16 }) => {
      const paths = {
        disable: 'M9 9l6 6m0-6-6 6M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18',
        upgrade: 'M12 19V5m-5 5 5-5 5 5M5 19h14',
        review: 'M10 3h4l7 12v4H3v-4L10 3Zm2 4v6m0 3v.5',
        allow: 'm5 12 4 4L19 6',
        shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z',
        scan: 'M20 7V3l-3 3a8 8 0 1 0 3 6M20 3h-4',
        export: 'M12 3v12m-4-4 4 4 4-4M4 15v6h16v-6',
        trash: 'M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7',
        block: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M5.6 5.6l12.8 12.8',
        play: 'M7 4v16l13-8L7 4Z',
      };
      return h('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
        strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true, focusable: false,
        className: 'ps-icon' }, h('path', { d: paths[name] ?? paths.shield }));
    };
    const actionContent = (t, action) => [h(Icon, { name: action, key: 'icon' }), t(ACTION_KEY[action] ?? 'actionReview')];
    const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
    const MODES = [
      { value: 'off', label: 'modeOff', hint: 'modeOffHint' },
      { value: 'report-only', label: 'modeReport', hint: 'modeReportHint' },
      { value: 'enforce', label: 'modeEnforce', hint: 'modeEnforceHint' },
    ];

    /** Fill `{name}` placeholders the way the host's own `t` does. */
    const interpolate = (text, params) => (params === undefined
      ? text
      : String(text).replace(/\{(\w+)\}/g, (whole, key) => (params[key] === undefined ? whole : String(params[key]))));

    /** A `t` for hosts that do not inject one (document language wins). */
    const fallbackT = () => {
      let lang = '';
      try {
        lang = (document.documentElement.lang || navigator.language || '').toLowerCase();
      } catch {
        lang = '';
      }
      const dict = lang.startsWith('en') ? en : zh;
      return (key, params) => interpolate(dict[key] === undefined ? key : dict[key], params);
    };

    const CSS = [
      '.ps-page{font-size:13.5px;color:var(--dsw-alias-label-primary);display:flex;flex-direction:column;gap:14px;max-width:760px}',
      '.ps-summary{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;gap:16px;min-width:0;border-bottom:1px solid var(--dsw-alias-border-l1);padding:0 0 9px}',
      '.ps-summary-stats{display:flex;align-items:baseline;gap:16px;min-width:0;white-space:nowrap;overflow-x:auto;padding-top:5px}',
      '.ps-summary-controls{display:flex;flex-direction:column;align-items:flex-end;gap:5px;min-width:0}',
      '.ps-stat{display:inline-flex;align-items:baseline;gap:5px;white-space:nowrap;flex:none;font-size:12px}',
      '.ps-stat strong{font-size:16px;font-weight:600;font-variant-numeric:tabular-nums}',
      '.ps-stat-total{color:var(--dsw-alias-label-primary)}',
      '.ps-stat-fresh{color:var(--dsw-alias-state-success-primary)}',
      '.ps-stat-cached{color:var(--dsw-alias-state-business-primary)}',
      '.ps-stat-trusted{color:var(--dsw-alias-state-warn-label)}',
      '.ps-scan-stamp{max-width:270px;font-size:10.5px;color:var(--dsw-alias-label-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:right}',
      '@media(max-width:520px){.ps-summary{gap:10px}.ps-summary-stats{gap:10px}.ps-stat{font-size:11px;gap:3px}.ps-stat strong{font-size:14px}.ps-scan-stamp{max-width:140px}}',
      '.ps-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}',
      '.ps-title{font-size:16px;font-weight:600;margin-right:auto;display:flex;align-items:center;gap:8px}',
      '.ps-icon{display:inline-block;flex:none;vertical-align:middle}',
      '.ps-assessment{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:500;color:var(--dsw-alias-label-secondary)}',
      '.ps-hint{font-size:12px;color:var(--dsw-alias-label-secondary)}',
      '.ps-btn{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 12px;border-radius:8px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);cursor:pointer;font:inherit;font-size:13px;white-space:nowrap}',
      '.ps-btn:hover:not(:disabled){border-color:var(--dsw-alias-brand-primary);background:var(--dsw-alias-interactive-bg-hover)}',
      // primary keeps its brand fill on hover: darkening it to the neutral
      // hover token crushed foreground contrast (user report #3)
      '.ps-btn-primary:hover:not(:disabled){background:var(--dsw-alias-brand-primary);filter:brightness(.9);border-color:transparent}',
      '.ps-btn-danger{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary);background:transparent}',
      '.ps-btn-danger:hover:not(:disabled){background:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary);color:var(--dsw-alias-label-primary-foreground)}',
      '.ps-btn:disabled{opacity:.5;cursor:default}',
      '.ps-btn-primary{background:var(--dsw-alias-brand-primary);border-color:transparent;color:var(--dsw-alias-label-primary-foreground)}',
      '.ps-btn:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:2px}',
      '.ps-card{border:1px solid var(--dsw-alias-border-l1);border-radius:12px;padding:12px 14px;background:var(--dsw-alias-bg-layer-1);display:flex;flex-direction:column;gap:8px}',
      '.ps-card-disable{border-color:var(--dsw-alias-state-error-primary)}',
      '.ps-card-head{display:flex;align-items:center;gap:8px;min-width:0}',
      '.ps-plugin-name{font-weight:600;font-size:14px;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.ps-row-actions{display:flex;align-items:center;gap:6px;flex:none;margin-left:auto}',
      '.ps-btn-small{height:24px;padding:0 7px;font-size:11.5px;border-radius:6px}',
      '.ps-btn-uninstall{color:var(--dsw-alias-label-secondary);background:transparent;border-color:var(--dsw-alias-border-l2)}',
      '.ps-btn-uninstall:hover:not(:disabled){color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}',
      '.ps-card-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap}',
      '.ps-card-meta .ps-assessment{margin-left:auto}',
      '.ps-risk{font-size:11.5px;white-space:nowrap;border-radius:5px;padding:2px 7px;flex:none;background:var(--dsw-alias-bg-layer-2)}',
      '.ps-risk-high{color:var(--dsw-alias-state-error-primary)}',
      '.ps-chip-blocked{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}',
      '.ps-risk-risk{color:var(--dsw-alias-state-warn-label)}',
      '.ps-risk-none,.ps-risk-whitelist{color:var(--dsw-alias-label-secondary)}',
      '.ps-list{display:flex;flex-direction:column;gap:10px}',
      '.ps-findings{display:flex;flex-direction:column;gap:8px}',
      '.ps-list-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}',
      '.ps-list-toolbar strong{font-size:14px;white-space:nowrap}',
      '.ps-search{height:30px;min-width:130px;padding:0 10px;border-radius:7px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font:inherit;font-size:12px;flex:1}',
      '.ps-search:focus{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:1px}',
      '.ps-tabs{display:flex;gap:18px;overflow-x:auto;border-bottom:1px solid var(--dsw-alias-border-l2)}',
      '.ps-tab{display:inline-flex;align-items:center;gap:5px;white-space:nowrap;background:transparent;border:0;border-bottom:2px solid transparent;padding:9px 0;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12.5px;cursor:pointer}',
      '.ps-tab-active{color:var(--dsw-alias-brand-primary);border-bottom-color:var(--dsw-alias-brand-primary);font-weight:600}',
      '.ps-tab:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:-2px}',
      '.ps-tab-count{font-size:11px;font-variant-numeric:tabular-nums;color:var(--dsw-alias-label-secondary)}',
      '.ps-whitelist-picker{display:flex;align-items:center;gap:8px}',
      '@media(max-width:520px){.ps-card{padding:10px}.ps-card-head{gap:5px}.ps-row-actions{gap:4px}.ps-btn-small{padding:0 5px;font-size:11px}.ps-btn-small .ps-icon{display:none}.ps-list-toolbar .ps-search{flex-basis:100%;order:2}.ps-tabs{gap:14px}}',
      '.ps-chip{font-size:11px;padding:1px 8px;border-radius:99px;border:1px solid var(--dsw-alias-border-l2);color:var(--dsw-alias-label-secondary);flex:none}',
      '.ps-chip-sev{font-size:11px;padding:1px 8px;border-radius:99px;border:1px solid var(--dsw-alias-border-l2);flex:none}',
      '.ps-chip-critical{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}',
      '.ps-chip-high{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}',
      '.ps-chip-medium{color:var(--dsw-alias-state-warn-label);border-color:var(--dsw-alias-state-warn-primary)}',
      '.ps-chip-low{color:var(--dsw-alias-state-business-primary);border-color:var(--dsw-alias-state-business-primary)}',
      '.ps-chip-info{color:var(--dsw-alias-label-secondary)}',
      '.ps-chip-action{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;padding:2px 10px;border-radius:99px;border:1px solid var(--dsw-alias-border-l2);flex:none;font-weight:600}',
      '.ps-chip-action-disable{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}',
      '.ps-chip-action-upgrade{color:var(--dsw-alias-state-warn-label);border-color:var(--dsw-alias-state-warn-primary)}',
      '.ps-chip-action-review{color:var(--dsw-alias-state-warn-label);border-color:var(--dsw-alias-state-warn-primary)}',
      '.ps-chip-action-allow{color:var(--dsw-alias-label-secondary);border-color:var(--dsw-alias-border-l2)}',
      '.ps-open{border:none;background:transparent;color:var(--dsw-alias-state-business-primary);cursor:pointer;font:inherit;font-size:12.5px;padding:2px 4px;border-radius:6px;align-self:flex-start}',
      '.ps-open:hover{background:var(--dsw-alias-interactive-bg-hover)}',
      '.ps-open:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:2px}',
      '.ps-finding{border-left:3px solid var(--dsw-alias-border-l2);padding:6px 0 6px 10px;display:flex;flex-direction:column;gap:5px}',
      '.ps-finding-critical{border-left-color:var(--dsw-alias-state-error-primary)}',
      '.ps-finding-high{border-left-color:var(--dsw-alias-state-error-primary)}',
      '.ps-finding-medium{border-left-color:var(--dsw-alias-state-warn-primary)}',
      '.ps-finding-low{border-left-color:var(--dsw-alias-state-business-primary)}',
      '.ps-finding-capability{border-left-color:var(--dsw-alias-border-l2)}',
      '.ps-finding-head{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}',
      '.ps-finding-title{font-weight:600;font-size:13px}',
      '.ps-advice{font-size:12.5px;color:var(--dsw-alias-label-secondary);line-height:1.55}',
      '.ps-evidence{display:flex;flex-direction:column;gap:3px;font-size:12px}',
      '.ps-ev{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}',
      '.ps-ev-ref{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--dsw-alias-state-business-primary);flex:none}',
      '.ps-ev-snippet{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--dsw-alias-label-secondary);overflow-wrap:anywhere}',
      '.ps-deps{display:flex;flex-direction:column;gap:4px;font-size:12px}',
      '.ps-dep{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}',
      '.ps-dep-name{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--dsw-alias-label-primary);flex:none}',
      '.ps-dep-fix{color:var(--dsw-alias-state-business-primary);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}',
      '.ps-note{font-size:12px;color:var(--dsw-alias-label-secondary);line-height:1.6;border:1px dashed var(--dsw-alias-border-l2);border-radius:10px;padding:10px 12px}',
      '.ps-footer{font-size:12px;color:var(--dsw-alias-label-secondary);display:flex;flex-direction:column;gap:2px;overflow-wrap:anywhere}',
      '.ps-error{color:var(--dsw-alias-state-error-primary);font-size:12.5px;background:var(--dsw-alias-bg-layer-1);border:1px solid var(--dsw-alias-border-l1);border-radius:10px;padding:10px 12px}',
      '.ps-loading{color:var(--dsw-alias-label-secondary)}',
      // config block
      '.ps-config{border:1px solid var(--dsw-alias-border-l1);border-radius:12px;padding:12px 14px;background:var(--dsw-alias-bg-layer-1);display:flex;flex-direction:column;gap:10px}',
      '.ps-config-title{font-weight:600;font-size:13.5px}',
      '.ps-config-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}',
      '.ps-config-label{font-size:12.5px;color:var(--dsw-alias-label-secondary);min-width:110px;flex:none}',
      '.ps-seg{display:inline-flex;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;overflow:hidden}',
      '.ps-seg-btn{border:none;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12.5px;padding:5px 12px;cursor:pointer;border-right:1px solid var(--dsw-alias-border-l2)}',
      '.ps-seg-btn:last-child{border-right:none}',
      '.ps-seg-btn:hover{background:var(--dsw-alias-interactive-bg-hover)}',
      '.ps-seg-btn:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:-2px}',
      '.ps-seg-btn-active{background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-label-primary-foreground)}',
      '.ps-config-hint{font-size:11.5px;color:var(--dsw-alias-label-secondary);line-height:1.5}',
      '.ps-toast{position:fixed;right:18px;bottom:18px;background:var(--dsw-alias-bg-layer-1);border:1px solid var(--dsw-alias-border-l2);border-radius:10px;padding:8px 14px;font-size:12.5px;box-shadow:0 4px 16px rgba(0,0,0,.18);z-index:60}',
    ].join('\n');
    const cssTag = 'dsh-plugin-security/styles';
    if (typeof document !== 'undefined' && document.querySelector('style[data-plugin-css=' + JSON.stringify(cssTag) + ']') === null) {
      const tag = document.createElement('style');
      tag.dataset.plugin = 'dsh-plugin-security';
      tag.dataset.pluginCss = cssTag;
      tag.textContent = CSS;
      document.head.appendChild(tag);
    }

    let connectionSvc = null;

    /**
     * Invoke one host `security/<method>` Remote endpoint over the connection
     * RPC carrier. Returns the business value; throws on transport failure
     * (business `{ error }` shapes stay return values).
     */
    const securityCall = async (method, request) => {
      if (connectionSvc === null) throw new Error('no connection');
      const envelope = await connectionSvc.rpc.call('/api', 'security/' + method, {
        args: { request: request === undefined ? null : request },
      });
      if (envelope !== null && typeof envelope === 'object' && envelope.ok === false) {
        const message = envelope.error && envelope.error.message ? envelope.error.message : 'RPC failed';
        throw new Error(message);
      }
      if (envelope !== null && typeof envelope === 'object' && envelope.ok === true) return envelope.value;
      throw new Error('unexpected RPC response');
    };

    const errText = (e) => ((e && e.message) ? String(e.message) : String(e));

    const sevChip = (severity, label) => h('span', { className: 'ps-chip-sev ps-chip-' + severity }, label);

    /** One finding: severity chip, rule title, advice, evidence list. */
    const Finding = (t, report, isEn, f) => {
      const def = report?.rules?.[f.ruleId];
      const title = def?.title ? (isEn ? (def.title.en ?? def.title.zh) : def.title.zh) : f.ruleId;
      const advice = def?.advice ? (isEn ? (def.advice.en ?? def.advice.zh) : def.advice.zh) : null;
      const extraHosts = f.extra && typeof f.extra.host === 'string' ? f.extra.host : null;
      return h('div', { className: 'ps-finding ps-finding-' + f.severity + (f.kind === 'capability' ? ' ps-finding-capability' : ''), key: f.ruleId + ':' + (f.evidence?.[0]?.ref ?? '') },
        h('div', { className: 'ps-finding-head' },
          f.kind === 'capability' ? h('span', { className: 'ps-chip' }, t('capability'))
            : sevChip(f.severity, t('reviewPriority') + ': ' + t(SEV_KEY[f.severity] ?? 'sevInfo')),
          h('span', { className: 'ps-finding-title' }, title),
          f.scope ? h('span', { className: 'ps-chip' }, t({ runtime: 'scopeRuntime', support: 'scopeSupport', dependency: 'scopeDependency' }[f.scope] ?? 'scopeRuntime')) : null,
          extraHosts !== null ? h('span', { className: 'ps-chip' }, t('endpointHosts') + ': ' + extraHosts) : null),
        f.extra?.correlation ? h('div', { className: 'ps-advice' },
          isEn ? 'A local data or execution link was found; review its purpose and execution path.' : '发现局部数据或执行联系；仍需核实用途与实际执行路径。') : null,
        advice !== null ? h('div', { className: 'ps-advice' }, t('adviceLabel') + '：' + advice) : null,
        h('div', { className: 'ps-evidence' },
          (f.evidence ?? []).map((e, i) => h('div', { className: 'ps-ev', key: e.ref + ':' + i },
            h('span', { className: 'ps-ev-ref' }, e.ref),
            h('span', { className: 'ps-ev-snippet' }, e.snippet)))));
    };

    /** Dependency advisories block for one plugin card. */
    const DepsBlock = (t, isEn, plugin) => {
      const advisories = Array.isArray(plugin.depsAdvisories) ? plugin.depsAdvisories : [];
      if (advisories.length === 0) return null;
      return h('div', { className: 'ps-deps' },
        h('div', { className: 'ps-hint' }, t('advisoriesLabel') + ' (' + advisories.length + ')'),
        advisories.slice(0, 8).map((a, i) => h('div', { className: 'ps-dep', key: a.dep + ':' + a.id + ':' + i },
          sevChip(a.severity, isEn ? a.severity : ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[a.severity] ?? a.severity)),
          h('span', { className: 'ps-dep-name' }, a.dep),
          h('span', {}, a.title),
          a.fixedIn
            ? h('span', { className: 'ps-dep-fix' }, t('fixedIn') + ' ' + a.fixedIn)
            : h('span', { className: 'ps-chip' }, t('noFix')))));
    };

    const defaultProtected = (name) => typeof name === 'string' &&
      (name.startsWith('@deepseek-ai/') || ['dsh-plugin-security', 'dsh-plugin-sentinel'].includes(name));
    const whitelisted = (plugin, config) => plugin.trusted === true || defaultProtected(plugin.name) ||
      (config?.protectedNames ?? []).includes(plugin.name);
    const packageName = (name) => typeof name === 'string' && /^(@[a-z0-9][a-z0-9-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(name);

    /**
     * Risk is evidence-based and independent of the suggested action. The
     * host records it (lib/risk.js); this copy covers older records and must
     * stay identical to the host rule.
     */
    const pluginRisk = (plugin) => {
      if (plugin.risk && ['high', 'risk', 'none'].includes(plugin.risk.level) && typeof plugin.risk.reason === 'string' &&
        plugin.risk.reason !== 'whitelisted') return plugin.risk;
      const review = plugin.review;
      const deps = plugin.deps?.worst ?? 'none';
      const advisories = plugin.depsAdvisories ?? [];
      if (review?.verdict === 'malicious' && review.confidence === 'high') return { level: 'high', reason: 'riskConfirmed' };
      if (['critical', 'high'].includes(deps) || advisories.some((a) => ['critical', 'high'].includes(a.severity)))
        return { level: 'high', reason: 'riskAdvisory' };
      if (deps !== 'none' || advisories.length) return { level: 'risk', reason: 'riskAdvisory' };
      if (plugin.filesTruncated || plugin.source === 'missing' || plugin.deps?.errors?.length || plugin.deps?.unknown === true ||
        Object.values(plugin.deps?.results ?? {}).some((d) => d.unknown)) return { level: 'risk', reason: 'riskIncomplete' };
      if (review && !(review.verdict === 'benign' && review.confidence === 'high')) return { level: 'risk', reason: 'riskIncomplete' };
      if (!(review?.verdict === 'benign' && review.confidence === 'high') &&
        ((plugin.screening?.signal?.level ?? 'none') !== 'none' ||
        (plugin.findings ?? plugin.screening?.findings ?? []).some((f) => f.kind !== 'capability' && f.scope !== 'support' && ['high', 'critical'].includes(f.severity))))
        return { level: 'risk', reason: 'riskBehavior' };
      return { level: 'none', reason: 'riskClear' };
    };
    const RISK_KEY = { high: 'riskHigh', risk: 'riskSome', none: 'riskNone' };
    const FILTERS = [
      { value: 'all', label: 'all' }, { value: 'high', label: 'riskHigh' },
      { value: 'risk', label: 'riskSome' }, { value: 'none', label: 'riskNone' },
      { value: 'blocked', label: 'policyBlockedTab' },
      { value: 'disable', label: 'actionDisable' }, { value: 'upgrade', label: 'actionUpgrade' },
      { value: 'whitelist', label: 'whitelistTab' },
    ];
    const matchesFilter = (plugin, filter, config) => filter === 'all' ||
      (filter === 'whitelist' ? whitelisted(plugin, config)
        : filter === 'blocked' ? plugin.policy?.decision === 'block'
        : ['disable', 'upgrade'].includes(filter) ? plugin.disposition?.action === filter
        : !whitelisted(plugin, config) && pluginRisk(plugin).level === filter);
    const listPlugins = (report) => {
      const plugins = [...(report?.plugins ?? [])];
      for (const name of report?.config?.protectedNames ?? []) if (!plugins.some((p) => p.name === name))
        plugins.push({ name, source: 'missing', trusted: true, notInstalled: true, findings: [] });
      return plugins;
    };

    /** Compact actions stay on the same header row as the plugin name. */
    /** Enable / disable / reset buttons for the per-plugin call gate. */
    const PolicyButtons = (t, plugin, risk, onPolicy, busy) => {
      const decision = plugin.policy?.decision ?? null;
      const button = (key, icon, label, next) => h('button', { type: 'button', key, className: 'ps-btn ps-btn-small', disabled: busy,
        onClick: () => onPolicy?.(plugin.name, next) }, h(Icon, { name: icon, size: 13 }), t(label));
      const out = [];
      if (decision === 'block' || (decision === null && risk.level === 'high')) out.push(button('enable', 'play', 'policyEnable', 'allow'));
      if (decision !== 'block') out.push(button('disable', 'block', 'policyDisable', 'block'));
      if (decision !== null) out.push(button('reset', 'scan', 'policyReset', null));
      return out;
    };

    const PluginCard = (t, report, isEn, plugin, expanded, onToggle, onUndo, onUninstall, onUpgrade, onWhitelistAdd, onWhitelistRemove, busy = false, onPolicy = null) => {
      const findings = plugin.findings ?? [];
      const action = plugin.disposition?.action ?? 'allow';
      const config = report?.config;
      const trusted = whitelisted(plugin, config);
      const fixed = defaultProtected(plugin.name) || plugin.self === true;
      const manageable = packageName(plugin.name) && plugin.source !== 'profile-patch';
      const risk = pluginRisk(plugin);
      const chips = [];
      if (SOURCE_KEY[plugin.source]) chips.push(h('span', { className: 'ps-chip', key: 'src' }, t(SOURCE_KEY[plugin.source])));
      if (plugin.version) chips.push(h('span', { className: 'ps-chip', key: 'ver' }, 'v' + plugin.version));
      if (plugin.rowStatus?.status) chips.push(h('span', { className: 'ps-chip', key: 'status' }, t('statusLabel') + ': ' + plugin.rowStatus.status));
      if (['disable', 'upgrade'].includes(action)) chips.push(h('span', { className: 'ps-chip-action ps-chip-action-' + action, key: 'action' }, actionContent(t, action)));
      if (plugin.cached && plugin.scannedAt) chips.push(h('span', { className: 'ps-chip', key: 'cached' }, t('cachedNote', { at: String(plugin.scannedAt).slice(0, 10) })));
      const policy = trusted ? null : plugin.policy?.decision ?? null;
      if (policy === 'block') chips.push(h('span', { className: 'ps-chip ps-chip-blocked', key: 'policy' }, h(Icon, { name: 'block', size: 12 }), t('policyBlocked')));
      if (policy === 'allow') chips.push(h('span', { className: 'ps-chip', key: 'policy' }, t('policyAllowed', { version: plugin.policy.version ? 'v' + plugin.policy.version : '' })));
      const gated = manageable && !trusted && !plugin.notInstalled;
      const assessment = trusted ? 'skipped' : !plugin.review ? 'unreviewed'
        : plugin.review.verdict === 'benign' && plugin.review.confidence === 'high' ? 'reviewedBenign'
        : plugin.review.verdict === 'malicious' && plugin.review.confidence === 'high' ? 'reviewedMalicious' : 'reviewedSuspicious';
      return h('div', { className: 'ps-card', key: plugin.name },
        h('div', { className: 'ps-card-head' },
          h('span', { className: 'ps-plugin-name', title: plugin.name }, plugin.name),
          h('span', { className: 'ps-risk ps-risk-' + (trusted ? 'whitelist' : risk.level) }, t(trusted ? 'trustedBadge' : RISK_KEY[risk.level])),
          h('div', { className: 'ps-row-actions' },
            gated ? PolicyButtons(t, plugin, risk, onPolicy, busy) : null,
            plugin.disposition?.executed ? h('button', { type: 'button', className: 'ps-btn ps-btn-small', disabled: busy, onClick: () => onUndo?.(plugin.name) }, t('undoDisable')) : null,
            plugin.upgrade?.command && !trusted ? h('button', { type: 'button', className: 'ps-btn ps-btn-small', disabled: busy, onClick: () => onUpgrade?.(plugin.name) }, h(Icon, { name: 'upgrade' }), t('upgradeBtn')) : null,
            manageable ? h('button', { type: 'button', className: 'ps-btn ps-btn-small', disabled: busy || fixed,
              title: fixed ? t('whitelistDefaultHint') : undefined,
              onClick: () => trusted ? onWhitelistRemove?.(plugin.name) : onWhitelistAdd?.(plugin.name) },
              h(Icon, { name: 'shield', size: 13 }), t(fixed ? 'whitelistDefault' : trusted ? 'whitelistRemovePlugin' : 'whitelistAddPlugin')) : null,
            manageable && !plugin.notInstalled ? h('button', { type: 'button', className: 'ps-btn ps-btn-small ps-btn-uninstall', disabled: busy || trusted || fixed,
              onClick: () => onUninstall?.(plugin.name) }, h(Icon, { name: 'trash', size: 13 }), t('uninstall')) : null)),
        h('div', { className: 'ps-card-meta' }, chips, h('span', { className: 'ps-assessment' }, t(assessment))),
        h('div', { className: 'ps-hint' }, t(plugin.notInstalled ? 'whitelistNotInstalled' : trusted ? 'whitelistRowHint' : risk.reason)),
        policy === 'block' ? h('div', { className: 'ps-hint' }, t('policyBlockedHint')) : null,
        policy === 'allow' ? h('div', { className: 'ps-hint' }, t('policyAllowedHint')) : null,
        plugin.review?.reason ? h('div', { className: 'ps-hint' }, t('reasonLabel') + ': ' + plugin.review.reason) : null,
        plugin.disposition?.executed ? h('div', { className: 'ps-hint' }, t('restartHint')) : null,
        !trusted ? DepsBlock(t, isEn, plugin) : null,
        !trusted && findings.length ? h('button', { type: 'button', className: 'ps-open', 'aria-expanded': expanded ? 'true' : 'false',
          onClick: onToggle }, expanded ? t('collapse') : t('expand', { count: findings.length })) : null,
        !trusted && expanded && findings.length ? h('div', { className: 'ps-findings' }, findings.map((f) => Finding(t, report, isEn, f))) : null);
    };

    const WhitelistPicker = (t, candidates, selected, onSelect, onAdd, busy) => h('div', { className: 'ps-whitelist-picker' },
      h('select', { className: 'ps-search', value: selected, 'aria-label': t('whitelistChoose'), disabled: busy,
        onChange: (e) => onSelect(e.target.value) },
        h('option', { value: '' }, t('whitelistChoose')),
        candidates.map((p) => h('option', { value: p.name, key: p.name }, p.name))),
      h('button', { type: 'button', className: 'ps-btn', disabled: busy || !candidates.some((p) => p.name === selected), onClick: () => onAdd(selected) },
        h(Icon, { name: 'shield' }), t('whitelistAddPlugin')));

    /** Build a Markdown report client-side from the gate payload. */
    const buildMarkdown = (report, isEn) => {
      const pick = (obj) => (obj && typeof obj === 'object' ? (isEn ? (obj.en ?? obj.zh) : (obj.zh ?? obj.en)) : '');
      const lines = [];
      lines.push('# ' + (isEn ? 'dsh Plugin Security Gate Report' : 'dsh 插件安全门报告'));
      lines.push('');
      lines.push('- ' + (isEn ? 'Generated' : '生成时间') + `: ${report.generatedAt}`);
      lines.push('- ' + (isEn ? 'Mode' : '模式') + `: ${report.mode ?? report.config?.mode ?? '?'}`);
      lines.push('- profile: `' + (report.env?.profileRoot ?? '?') + '`');
      const s = report.summary ?? {};
      lines.push('- ' + (isEn ? 'Dispositions' : '处置') + `: disable ${s.dispositions?.disable ?? 0} / upgrade ${s.dispositions?.upgrade ?? 0} / review ${s.dispositions?.review ?? 0} / allow ${s.dispositions?.allow ?? 0}`);
      lines.push('');
      lines.push('> ' + pick(report.notes));
      lines.push('');
      for (const p of report.plugins ?? []) {
        lines.push(`## ${p.name}${p.version ? `@${p.version}` : ''} — ${p.review ? p.review.verdict : (isEn ? 'not reviewed' : '未审读')} · ${p.disposition?.action ?? 'review'}`);
        lines.push('');
        if (p.disposition?.reason) lines.push((isEn ? 'Because' : '依据') + `: ${p.disposition.reason}${p.disposition.detail ? ` — ${p.disposition.detail}` : ''}`);
        if (p.upgrade?.upgrade && p.upgrade.command) lines.push((isEn ? 'Upgrade' : '升级') + `: \`${p.upgrade.command}\``);
        const advisories = Array.isArray(p.depsAdvisories) ? p.depsAdvisories : [];
        for (const a of advisories) {
          lines.push(`- [${a.severity}] ${a.dep}: ${a.title}${a.fixedIn ? ` (${isEn ? 'fixed in' : '修复于'} ${a.fixedIn})` : ''}`);
        }
        for (const f of p.findings ?? []) {
          const def = report.rules?.[f.ruleId];
          lines.push(`- [${f.severity}] ${def?.title ? pick(def.title) : f.ruleId}`);
          for (const e of f.evidence ?? []) lines.push(`  - \`${e.ref}\` ${e.snippet}`);
        }
        lines.push('');
      }
      return lines.join('\n');
    };

    const download = (name, text, mime) => {
      const blob = new Blob([text], { type: mime });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = name;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };

    const SecurityPage = (props) => {
      const t = React.useMemo(() => (typeof props.t === 'function' ? props.t : fallbackT()), [props.t]);
      const [info, setInfo] = React.useState(null);
      const [data, setData] = React.useState(null);
      const [loading, setLoading] = React.useState(true);
      const [busy, setBusy] = React.useState(false);
      const [error, setError] = React.useState('');
      const [toast, setToast] = React.useState('');
      const [filter, setFilter] = React.useState('all');
      const [openSet, setOpenSet] = React.useState(() => new Set());
      const [wlDraft, setWlDraft] = React.useState('');
      const [search, setSearch] = React.useState('');
      const [configBusy, setConfigBusy] = React.useState(false);

      const flash = (message) => {
        setToast(message);
        setTimeout(() => setToast(''), 2600);
      };

      const load = React.useCallback((force) => {
        setError('');
        if (force) setBusy(true); else setLoading(true);
        securityCall('status', { force: force === true }).then((value) => {
          setData(value);
          setLoading(false);
          setBusy(false);
        }, (e) => {
          setError(errText(e));
          setLoading(false);
          setBusy(false);
        });
      }, []);

      React.useEffect(() => {
        securityCall('info', {}).then(setInfo, () => setInfo(null));
        load(false);
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);

      const saveConfig = (patch) => {
        if (configBusy) return;
        setConfigBusy(true);
        securityCall('configure', patch).then((value) => {
          setConfigBusy(false);
          if (value && value.error) {
            flash(t('configureFailed') + ': ' + value.error);
            return;
          }
          if (info !== null) setInfo({ ...info, config: value.config });
          setData((prev) => prev ? { ...prev, config: value.config, mode: value.config.mode } : prev);
          flash(t('configSaved'));
          load(false);
        }, (e) => { setConfigBusy(false); flash(t('configureFailed') + ': ' + errText(e)); });
      };

      const undoDisable = (name) => {
        securityCall('reenable', { name, enable: true }).then((value) => {
          if (value && value.ok === true) flash(t('reenableOk', { name }));
          else flash(t('reenableFailed') + ': ' + (value?.reason ?? ''));
          load(true);
        }, (e) => flash(t('reenableFailed') + ': ' + errText(e)));
      };

      // ---- call gate: per-plugin enable / disable / default ---------------
      const setPolicy = (name, decision) => {
        setBusy(true);
        securityCall('policy', { name, decision }).then((value) => {
          setBusy(false);
          if (value && value.ok === true) {
            flash(t('policyOk', { name }));
            setData((prev) => prev ? { ...prev, plugins: (prev.plugins ?? []).map((p) => p.name === name ? { ...p, policy: value.policy ?? null } : p) } : prev);
          } else flash(t('policyFailed') + ': ' + (value?.error ?? value?.reason ?? ''));
        }, (e) => { setBusy(false); flash(t('policyFailed') + ': ' + errText(e)); });
      };

      // ---- threats panel actions (request #5) ----------------------------
      const uninstallPlugin = (name) => {
        if (!window.confirm(t('uninstallConfirm', { name }))) return;
        setBusy(true);
        securityCall('uninstall', { name }).then((value) => {
          setBusy(false);
          if (value && value.ok === true) flash(t('uninstallOk', { name }));
          else flash(t('uninstallFailed') + ': ' + (value?.error ?? value?.reason ?? ''));
          load(true);
        }, (e) => { setBusy(false); flash(t('uninstallFailed') + ': ' + errText(e)); });
      };
      const upgradePlugin = (name) => {
        if (!window.confirm(t('upgradeConfirm', { name }))) return;
        setBusy(true);
        securityCall('upgrade', { name }).then((value) => {
          setBusy(false);
          if (value && value.ok === true) flash(t('upgradeOk', { name }));
          else flash(t('upgradeFailed') + ': ' + (value?.error ?? value?.reason ?? ''));
          load(true);
        }, (e) => { setBusy(false); flash(t('upgradeFailed') + ': ' + errText(e)); });
      };

      // ---- whitelist management (request #6) -----------------------------
      const whitelistAdd = (selected) => {
        const name = (typeof selected === 'string' ? selected : wlDraft).trim();
        if (!/^(@[a-z0-9][a-z0-9-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(name)) {
          flash(t('whitelistInvalid') + ': ' + name);
          return;
        }
        const current = Array.isArray(config?.protectedNames) ? config.protectedNames : [];
        if (!current.includes(name)) saveConfig({ protectedNames: [...current, name] });
        setWlDraft('');
      };
      const whitelistRemove = (name) => {
        const current = Array.isArray(config?.protectedNames) ? config.protectedNames : [];
        saveConfig({ protectedNames: current.filter((n) => n !== name) });
      };

      if (data === null && loading) {
        return h('div', { className: 'ps-page' }, h('div', { className: 'ps-loading' }, t('loading')));
      }

      const isEn = (() => {
        try {
          const code = t('localeCode');
          return code === 'en' || (code !== 'zh' && document.documentElement.lang.toLowerCase().startsWith('en'));
        } catch {
          return false;
        }
      })();

      const config = data?.config ?? info?.config ?? null;
      const mode = data?.mode ?? config?.mode ?? 'report-only';
      const plugins = listPlugins(data);
      const query = search.trim().toLowerCase();
      const visiblePlugins = plugins.filter((p) => matchesFilter(p, filter, config) && p.name.toLowerCase().includes(query));
      const candidates = plugins.filter((p) => !whitelisted(p, config) && packageName(p.name) && p.source !== 'profile-patch' && p.name.toLowerCase().includes(query));
      const counts = Object.fromEntries(FILTERS.map((f) => [f.value, plugins.filter((p) => matchesFilter(p, f.value, config)).length]));

      const toggle = (name) => {
        setOpenSet((prev) => {
          const next = new Set(prev);
          if (next.has(name)) next.delete(name); else next.add(name);
          return next;
        });
      };

      const stamp = (data?.generatedAt ?? '').slice(0, 19).replace('T', ' ');
      const s = data?.summary;
      const hasData = data !== null && data.error === undefined;
      const modeOff = mode === 'off';

      return h('div', { className: 'ps-page' },
        h('div', { className: 'ps-head' },
          h('div', { className: 'ps-title' }, t('tab'), h('span', { className: 'ps-hint' }, t('subtitle')))),
        h('div', { className: 'ps-summary' },
          h('div', { className: 'ps-summary-stats' }, !modeOff && hasData ? [
            { key: 'total', count: s?.targets ?? 0, label: 'pluginsLabel' },
            { key: 'fresh', count: s?.fresh ?? 0, label: 'freshLabel' },
            { key: 'cached', count: s?.cached ?? 0, label: 'cachedLabel' },
            { key: 'trusted', count: s?.trusted ?? 0, label: 'trustedCount' },
          ].map((stat) => h('span', { className: 'ps-stat ps-stat-' + stat.key, key: stat.key },
            h('strong', {}, String(stat.count)), t(stat.label))) : null),
          h('div', { className: 'ps-summary-controls' },
            h('button', {
              type: 'button', className: 'ps-btn', disabled: busy || loading || modeOff, 'aria-busy': busy ? 'true' : undefined,
              onClick: () => load(true),
            }, h(Icon, { name: 'scan' }), busy ? t('rescanning') : t('rescan')),
            !modeOff && hasData ? h('span', { className: 'ps-scan-stamp', title: t('lastScan', { at: stamp, ms: String(data.durationMs ?? 0) }) },
              t('lastScan', { at: stamp, ms: String(data.durationMs ?? 0) })) : null)),
        error ? h('div', { className: 'ps-error', role: 'alert' }, t('scanFailed') + '：' + error) : null,
        // ---- gate config -------------------------------------------------
        h('div', { className: 'ps-config' },
          h('div', { className: 'ps-config-title' }, t('configTitle')),
          h('div', { className: 'ps-config-row' },
            h('span', { className: 'ps-config-label' }, t('modeLabel')),
            h('div', { className: 'ps-seg', role: 'group' },
              MODES.map((m) => h('button', {
                type: 'button', key: m.value, disabled: configBusy,
                className: 'ps-seg-btn' + (mode === m.value ? ' ps-seg-btn-active' : ''),
                'aria-pressed': mode === m.value ? 'true' : 'false',
                onClick: () => saveConfig({ mode: m.value }),
              }, t(m.label)))),
            h('span', { className: 'ps-config-hint' }, t(MODES.find((m) => m.value === mode)?.hint ?? 'modeReportHint'))),
          h('div', { className: 'ps-config-row' },
            h('span', { className: 'ps-config-label' }, t('autoDisableLabel')),
            h('div', { className: 'ps-seg', role: 'group', 'aria-label': t('autoDisableLabel') },
              [{ value: 'never', label: 'autoDisableNever' }, { value: 'critical', label: 'autoDisableCritical' }, { value: 'high', label: 'autoDisableHigh' }].map((lv) => h('button', {
                type: 'button', key: lv.value, disabled: configBusy,
                className: 'ps-seg-btn' + ((config?.autoDisableAt ?? 'critical') === lv.value ? ' ps-seg-btn-active' : ''),
                'aria-pressed': (config?.autoDisableAt ?? 'critical') === lv.value ? 'true' : 'false',
                onClick: () => saveConfig({ autoDisableAt: lv.value }),
              }, t(lv.label)))),
            h('span', { className: 'ps-config-hint' }, t('autoDisableHint'))),
          h('div', { className: 'ps-config-row' },
            h('span', { className: 'ps-config-label' }, t('autoUpgradeLabel')),
            h('div', { className: 'ps-seg', role: 'group' },
              [false, true].map((v) => h('button', {
                type: 'button', key: String(v), disabled: configBusy,
                className: 'ps-seg-btn' + ((config?.autoUpgrade === true) === v ? ' ps-seg-btn-active' : ''),
                'aria-pressed': (config?.autoUpgrade === true) === v ? 'true' : 'false',
                onClick: () => saveConfig({ autoUpgrade: v }),
              }, t(v ? 'autoUpgradeOn' : 'autoUpgradeOff')))),
            h('span', { className: 'ps-config-hint' }, t('autoUpgradeHint'))),
          h('div', { className: 'ps-config-hint' }, t('protectedNote'))),
        // ---- report ------------------------------------------------------
        modeOff
          ? h('div', { className: 'ps-note' }, isEn ? data?.notes?.en : data?.notes?.zh)
          : null,
        hasData ? h('div', { className: 'ps-list-toolbar' },
          h('strong', {}, t('listTitle')),
          h('input', { type: 'search', className: 'ps-search', value: search, placeholder: t('searchPlaceholder'), 'aria-label': t('searchLabel'), onChange: (e) => setSearch(e.target.value) }),
          h('button', {
            type: 'button', className: 'ps-btn', disabled: !hasData,
            onClick: () => download(`dsh-plugin-security-report-${(data.generatedAt ?? '').slice(0, 10)}.json`, JSON.stringify(data, null, 2), 'application/json'),
          }, h(Icon, { name: 'export' }), t('exportJson')),
          h('button', {
            type: 'button', className: 'ps-btn', disabled: !hasData,
            onClick: () => download(`dsh-plugin-security-report-${(data.generatedAt ?? '').slice(0, 10)}.md`, buildMarkdown(data, isEn), 'text/markdown'),
          }, h(Icon, { name: 'export' }), t('exportMd'))) : null,
        hasData ? h('div', { className: 'ps-tabs', role: 'tablist', 'aria-label': t('listTitle') },
          FILTERS.map((f) => h('button', { type: 'button', key: f.value, id: 'ps-tab-' + f.value,
            className: 'ps-tab' + (filter === f.value ? ' ps-tab-active' : ''), role: 'tab',
            tabIndex: filter === f.value ? 0 : -1,
            'aria-selected': filter === f.value, 'aria-controls': 'ps-plugin-list',
            onKeyDown: (e) => {
              const index = FILTERS.findIndex((tab) => tab.value === filter);
              const next = e.key === 'ArrowRight' ? (index + 1) % FILTERS.length : e.key === 'ArrowLeft' ? (index + FILTERS.length - 1) % FILTERS.length
                : e.key === 'Home' ? 0 : e.key === 'End' ? FILTERS.length - 1 : -1;
              if (next < 0) return;
              e.preventDefault();
              setFilter(FILTERS[next].value);
              document.getElementById('ps-tab-' + FILTERS[next].value)?.focus();
            },
            onClick: () => setFilter(f.value) }, t(f.label), h('span', { className: 'ps-tab-count' }, String(counts[f.value]))))) : null,
        hasData ? h('div', { className: 'ps-hint' }, t(filter === 'whitelist' ? 'whitelistHint' : 'riskMeaning')) : null,
        hasData && !modeOff && filter !== 'whitelist' ? h('div', { className: 'ps-hint' }, t('gateHint')) : null,
        hasData && filter === 'whitelist' ? WhitelistPicker(t, candidates, wlDraft, setWlDraft, whitelistAdd, busy || configBusy) : null,
        hasData && visiblePlugins.length === 0
          ? h('div', { className: 'ps-note' }, t('emptyFilter'))
          : null,
        hasData ? h('div', { id: 'ps-plugin-list', role: 'tabpanel', 'aria-labelledby': 'ps-tab-' + filter, className: 'ps-list' }, visiblePlugins.map((plugin) => PluginCard(
          t, data, isEn, plugin,
          openSet.has(plugin.name), () => toggle(plugin.name), undoDisable, uninstallPlugin, upgradePlugin, whitelistAdd, whitelistRemove, busy || configBusy, setPolicy,
        ))) : null,
        hasData ? h('div', { className: 'ps-note' }, h('strong', {}, t('notesTitle') + '：'), ' ', isEn ? data.notes.en : data.notes.zh) : null,
        info !== null && info.env !== null
          ? h('div', { className: 'ps-footer' },
            h('div', {}, 'profile: ' + info.env.profileRoot),
            h('div', {}, 'global: ' + info.env.globalRoot))
          : null,
        toast ? h('div', { className: 'ps-toast', role: 'status' }, toast) : null);
    };

    const inject = ['connection', 'slots', 'locale'];

    function apply(c) {
      connectionSvc = c.get('connection');
      const slots = c.get('slots');
      if (slots === undefined) return;
      const locale = c.get('locale');
      // Dictionaries before the section, so the tab label resolves on first paint.
      if (locale !== undefined && typeof locale.register === 'function') {
        c.effect(() => locale.register(NS, { zh, en }), 'security: dictionaries');
      }
      const bound = (locale !== undefined && typeof locale.bind === 'function') ? locale.bind(NS) : null;
      const label = bound === null ? fallbackT() : bound;
      c.effect(() => slots.inject('settings.section', () => slots.register(
        { name: 'settings.section', id: 'plugin-security', order: 32, label: () => label('tab'), locale: NS },
        (props) => h(SecurityPage, { close: props.close, t: props.t === undefined ? bound : props.t }),
      )), 'security: settings section');
    }

    exports.apply = apply;
    exports.inject = inject;
    exports.NS = NS;
    // Exported for tests: dictionary parity catches a key translated in one
    // language and forgotten in the other.
    exports.locales = { zh, en };
    exports.PluginCard = PluginCard;
    exports.Finding = Finding;
    exports.pluginRisk = pluginRisk;
    exports.matchesFilter = matchesFilter;
    exports.listPlugins = listPlugins;
    exports.SecurityPage = SecurityPage;
    return module.exports;
  },
});
