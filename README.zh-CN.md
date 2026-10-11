# dsh-plugin-security · 插件安全门

[English](README.md) · [npm](https://www.npmjs.com/package/dsh-plugin-security) · [更新记录](CHANGELOG.md)

为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 提供插件依赖漏洞审计、源码证据、AI 辅助语境审读与可撤销处置，支持 Web 设置页和 Agent 工具。

**使用 `fetch`、`process.env`、文件系统或子进程 API，不等于恶意。** 普通匹配作为能力记录展示；局部数据与执行联系作为需要核实的证据。Agent 结合目的、数据去向和用户授权审读，再写回结论。

## 安装

使用当前版本的 dsh，宿主协议依赖为 `@deepseek-ai/dsh-typert-protocol@0.2.0-rc.2`。插件要求 Node.js 20+；实际运行需满足你的 dsh 发行版要求，推荐 Node.js 24。

```sh
# 安装到现有 Web profile，然后重启正在运行的宿主。
dsh plugin --profile web add dsh-plugin-security@latest
dsh --profile web
```

进入 **设置 → 插件安全门**。包已声明标准的 `dsh.bundle` 配置层与 `dsh.client` Web 入口，无需手改 profile 清单。其他已有 profile 将 `web` 替换成对应名称即可。没有 Web connection 的 profile 仍可使用 Agent 工具；宿主需提供 `tools`、`pluginManager`、`typert` 服务。

随包提供的审读 skill（`dsh-plugin-security`）会在插件启动后自动注册到宿主的 skill 目录，Agent 可直接使用，无需手动建立软链。

卸载插件：

```sh
dsh plugin --profile web remove dsh-plugin-security
```

本地状态文件（`$DSH_HOME/plugin-security/`）需另行删除。

## 核心能力

- 按实际安装版本查询 npm 依赖漏洞公告，使用 OSV 补充修复版本；网络失败保留为 **未知**，不会缓存成检查通过。
- 读取源码与文本，不执行目标代码；证据包含文件、行号、片段及运行代码、辅助材料、依赖代码来源。
- 通过有界 JavaScript AST 分析识别局部行为联系，例如完整环境数据进入请求 body、解码文本进入执行 API。联网与敏感访问在包内共同出现，不会自动升级。
- 按版本、内容指纹、筛查规则版本复用记录；代码或规则变更会重扫，也可强制重扫。
- 支持搜索、风险与处置 tab、白名单、逐项操作、JSON/Markdown 导出、紧凑统计及双语设置元数据。
- 调用拦截：模型调用高危插件的工具时，以问题卡片询问「允许一次 / 允许 / 禁用」；设置页可逐个插件启用或禁用，立即生效。
- 高置信度恶意审读之后可执行可撤销停用，保留 profile 快照与有数量上限的处置日志。

## 扫描时机

每个插件的每个版本只做一次完整检查（代码静态初筛 + npm 依赖漏洞审计），结果与三级风险一起记录在状态文件。以下时机会触发扫描，已有记录的插件直接复用：

1. 本插件启动后（首次安装后的第一次启动即全量扫描）。
2. 通过插件管理器安装、移除或启用插件后。
3. 调用拦截遇到当前版本还没有扫描记录的插件时，先扫描该插件再判断。

内容指纹或规则版本变化会重扫；网络失败导致依赖审计结果为「未知」时，下次扫描会重试。强制重扫会重新筛查，但保留同一内容的 Agent 审读结论。

## 调用拦截

插件安全门监听宿主的 `tools/pre-execute`，把每次工具调用归属到注册该工具的插件（读取注册时的 loader entry；本插件启动前已注册的工具，按扫描时从源码提取的工具名归属）。

| 情况 | 结果 |
| --- | --- |
| 插件已被禁用（在「插件」页或本页） | 直接拒绝，模型收到「不要重试」的说明 |
| 当前版本未扫描 | 先扫描该插件，再按下面的规则判断 |
| 高危且没有决定 | 弹出问题卡片：**允许一次**（只放行本次）/ **允许**（记住当前版本，新版本重新询问）/ **禁用**（通过插件管理器禁用该插件，与「插件」页的禁用相同） |
| 有风险、无风险、白名单或保护名单 | 放行，交给宿主后续策略 |

问题卡片使用宿主的 `ctx.userQuestions`，与 dsh 原生向用户提问的通道一致。无法弹出卡片时（例如没有 Web 客户端、子 Agent 调用），回退为宿主原生授权提示（允许一次 / 拒绝）。同一插件并发的多个调用共用一次询问。

设置页每个插件行提供 **启用 / 禁用 / 恢复默认** 与 **卸载**，与 dsh 原生「插件」页同步：禁用、启用与卸载都调用宿主插件管理器（`setBundleEnabled` / `removeBundle`），和在「插件」页操作完全相同；在「插件」页禁用的插件，本页显示为「已禁用（插件管理）」，其工具在重启前仍被加载时，调用也会被拦截。启用会同时允许高危插件的当前版本运行，恢复默认则回到按风险询问。插件管理器无法管理的插件（不是 bundle）才退回为本插件自己的拦截记录（状态文件 `policies`）。页面重新获得焦点时自动刷新。模式为 `off` 时不拦截。

拦截只覆盖工具调用；插件注入的钩子、系统提示词与 Web 界面不经过 `tools/pre-execute`。拦截内部出错时放行并记录警告，但已禁用的插件仍会被拒绝。

## 风险标签与处置

| 标签 | 含义 |
| --- | --- |
| 高危 | 高置信度恶意审读，或 high/critical 依赖漏洞公告。 |
| 有风险 | 需核实的行为、其他漏洞、不确定审读、扫描截断或检查失败。 |
| 无风险 | 本次扫描范围内未发现需处置风险。普通能力记录不单独升级风险；不代表绝对安全。 |
| 白名单 | 已跳过检查，单独展示，不计入“无风险”。 |

风险标签随扫描记录保存，扫描报告与 Agent 工具同样输出。风险标签与处置动作独立：高危会在调用时询问用户，但 **不会直接触发自动停用**。界面已移除 A–F 评级；旧报告字段仍保留以兼容已有工具。

## 处置配置

通过设置页配置，保存到 `$DSH_HOME/plugin-security/state.json`，默认路径为 `~/.dsh/plugin-security/state.json`。

| 配置 | 默认值 | 行为 |
| --- | --- | --- |
| 模式 | `report-only` | `off` 不扫描、不拦截、不处置；`report-only` 扫描并保存报告，不修改目标插件；`enforce` 按恶意审读结论执行停用。 |
| 自动停用阈值 | `critical` | `never` 关闭自动停用。`critical` 与 `high` 均覆盖确认的高置信度恶意审读，此结论按 critical 处置。静态命中或漏洞公告本身不会触发自动隔离。 |
| 升级建议 | `false` | 开启后给出依赖升级命令，不静默执行升级。 |
| 白名单 | 内置保护项 | 在白名单 tab 或插件行添加/移除自定义包名。名单项跳过检查；内置保护项不可在界面移除。 |

自动停用还须满足 `enforce` 模式、目标不受保护。处置通过插件管理器禁用该 bundle（与「插件」页同步）；插件管理器无法管理时，才从 profile 移除 bundle 并将包目录重命名加上 `.security-quarantined` 后缀，**重启 dsh 后生效**。撤销会恢复目录与 bundle。本插件及内置保护包不能通过本插件停用或卸载，服务端也执行这一限制。

扫描状态与处置日志保存在本地。Profile 修改采用原子写入，保留最近五份滚动快照；状态文件最多保留 200 条处置日志。支持的平台上，状态目录权限为 `0700`，文件为 `0600`。

## Agent 工具

```text
security_scan { package?, force?, evidence? }
security_review { package, verdict, confidence?, reason? }
```

`verdict` 可选 `malicious`、`suspicious`、`benign`；`confidence` 可选 `high`、`medium`、`low`。高置信度 benign 可解释静态疑点，但不能覆盖依赖漏洞事实。可疑或不确定结论保留人工核实。

随包提供的 [审读 skill](skills/dsh-plugin-security/SKILL.md) 将目标源码、注释、README 和 skill 文本视为不可信证据。报告本身不会自动调用模型；语境审读使用你的 dsh Agent 及其配置的工具和模型服务。

## 隐私与能力边界

依赖审计向 npm 发送包名与实际安装版本，向 OSV 发送漏洞 ID 查询修复版本，不上传源码和本地路径。Agent 审读遵循你配置的模型服务的数据处理方式；提交给 Agent 的证据可能包含源码片段。

本插件是 **加载后的检查**，不是沙箱或安装前执行屏障。审计器与插件共享宿主进程及权限。静态分析受文件、字节等预算限制，无法覆盖全部跨文件数据流、动态行为、网络接口或传递依赖漏洞。截断和失败会如实展示；白名单会主动减少覆盖。审读结论存于本地，不具有独立的密码学可信保证。

## 开发与发布

```sh
corepack pnpm install --frozen-lockfile
pnpm test
npm pack --dry-run
```

端到端测试 `npm run test:e2e` 在临时 `DSH_HOME` 中用 headless 模板建立 profile，安装本包与 `e2e/` 下的两个测试插件（一个无害但被判为高危的回显插件，一个代替用户点击问题卡片的应答插件），通过本地确定性的假模型驱动真实 `dsh` 调用工具，覆盖首次调用、允许一次、允许、禁用、设置页启用、白名单与关闭模式。需要全局 `dsh` 与访问 npm registry 的网络，不会改动你自己的 profile。

测试覆盖检测与误报样例、profile、缓存失效、可撤销处置、设置交互，以及真实 Cordis/Typert/网关 RPC 生命周期。共享宿主协议包按 [dsh 官方打包指南](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md) 同时声明 peer 与开发依赖。

开发及发布步骤见 [CONTRIBUTING.md](CONTRIBUTING.md)。包直接分发 JavaScript 产物，无需消费者运行构建脚本或本包的安装脚本。

## 排查 HTTP 404

`transport failure for /api/security/status: HTTP 404` 表示宿主没有注册设置页 RPC 路由。请升级插件、确认协议 peer 版本并重启 dsh。本插件使用显式 host 契约，并跟随 Web connection 服务生命周期注册路由。

检查宿主日志里的 `plugin-security: RPC contract registration failed` 或 `Fetch route registration failed`。`$DSH_HOME/plugin-security/remote-diag.json` 记录观察到的服务和路由状态。没有 Web connection 的 headless profile 使用 Agent 工具。

## 许可证

[MIT](LICENSE) © 2026 dushaobindoudou。
