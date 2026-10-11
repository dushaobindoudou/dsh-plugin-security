# dsh-plugin-security · 插件安全门

[![CI](https://github.com/dushaobindoudou/dsh-plugin-security/actions/workflows/ci.yml/badge.svg)](https://github.com/dushaobindoudou/dsh-plugin-security/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/dsh-plugin-security.svg)](https://www.npmjs.com/package/dsh-plugin-security)
[![license](https://img.shields.io/npm/l/dsh-plugin-security.svg)](LICENSE)

[English](README.md) · [npm](https://www.npmjs.com/package/dsh-plugin-security) · [更新记录](CHANGELOG.md) · [安全策略](SECURITY.md)

[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）的插件安全门：扫描已安装插件的源码与 npm 依赖漏洞，把每个插件记为 **高危 / 有风险 / 无风险**，在模型调用高危插件的工具时先问你 **允许一次 / 允许 / 禁用**，并让 dsh Agent 按随包 skill 审读可疑插件。禁用、启用与卸载都通过 dsh 原生插件管理器执行，与「插件」页保持同步。

> 使用 `fetch`、`process.env`、文件系统或子进程 API 本身不等于恶意。静态命中只是需要核实的证据；结论来自依赖漏洞事实与 Agent 的语境审读。

## 工作方式

```text
安装 / 启动 / 插件变更 ──► 扫描（源码静态筛查 + npm 依赖审计）──► 记录：高危 / 有风险 / 无风险
                                                                         │
模型调用某插件的工具 ──► 归属到插件 ──► 已禁用？拒绝 │ 未检查？先扫描 │ 高危？询问 │ 其余放行
                                                                         │
用户或 Agent ──► dsh-plugin-security skill 审读 ──► security_review 写回结论
```

## 安装

需要 dsh `0.2.x`（宿主协议 `@deepseek-ai/dsh-typert-protocol >=0.1.0-rc.6 <0.3.0`）与 Node.js 20+，推荐 Node.js 24。

```sh
dsh plugin --profile web add dsh-plugin-security@latest
```

Web profile 开启了热重载，首次安装会直接加载，并立即对所有插件做一轮扫描；**升级到新版本需要重启 dsh**（Node 会缓存已加载的模块）。其他 profile 将 `web` 换成对应名称。没有 Web 客户端的 profile 仍可使用 Agent 工具与调用拦截。

卸载：`dsh plugin --profile web remove dsh-plugin-security`。本地状态 `$DSH_HOME/plugin-security/` 需另行删除。

## 使用

- **设置 → 插件安全门**：按风险、已禁用、处置建议或白名单筛选插件，查看依赖漏洞与证据，逐个插件 **启用 / 禁用 / 恢复默认 / 卸载**，导出 JSON 或 Markdown 报告。
- **调用时询问**：模型调用高危插件的工具时，输入框旁出现问题卡片。
- **让 dsh 审读**：在对话中输入「使用 dsh-plugin-security skill 审读当前插件的安全问题」。Agent 调用 `security_scan` 获取证据，按 skill 的五问审读，再用 `security_review` 写回结论。skill 随插件自动注册，无需手动链接。

## 扫描：不漏检

每个插件的每个版本只做一次完整检查，结果按 *版本 + 内容指纹 + 规则版本* 记录；代码或规则变化会重扫。扫描在以下时机触发：

1. 本插件启动时（首次安装后的第一次启动即全量扫描）。
2. 通过插件管理器安装、移除、启用或禁用插件之后。
3. profile 重新组合之后（CLI 安装或手改配置后由热重载加载）。
4. 调用拦截遇到当前版本没有记录的插件时，先扫描该插件再判断。

无法扫描的插件（找不到包、扫描失败）**不会被静默放行**，而是像高危插件一样询问。依赖审计因网络失败记为「未知」时不会当作通过：下次扫描会重试，调用时也会补扫（每个插件 5 分钟最多一次）。

| 风险 | 含义 |
| --- | --- |
| 高危 | 高置信度恶意审读结论，或 high / critical 依赖漏洞。 |
| 有风险 | 需核实的行为线索、其他漏洞、不确定的审读、扫描截断或检查不完整。 |
| 无风险 | 本次检查范围内未发现风险；不代表绝对安全。 |
| 白名单 | 按配置跳过检查与拦截，单独展示。 |

## 调用拦截：准确放行

本插件监听宿主的 `tools/pre-execute`，把每次工具调用归属到注册该工具的插件：优先使用注册时的 loader entry；本插件启动前已注册的工具，按其 `execute` 源码在已安装包中唯一匹配归属；最后参考扫描记录里的工具名。

| 情况 | 结果 |
| --- | --- |
| 插件已禁用（在「插件」页或本页） | 拒绝，模型收到「不要重试」的说明 |
| 当前版本未扫描 | 先扫描，再按下列规则判断 |
| 高危或无法完成检查，且没有决定 | 询问：允许一次 / 允许 / 禁用 |
| 有风险、无风险、白名单、保护名单，或模式为 `off` | 放行，交给宿主其余策略（例如原生授权） |

- **允许一次**：只放行发起询问的这一次调用。同时等待的其它调用会重新判断，各自询问。
- **允许**：记住该插件的**当前安装版本**，之后不再询问；插件更新到新版本后会重新询问。
- **禁用**：通过插件管理器禁用该插件，与「插件」页的禁用完全相同（依赖保留）；本次及之后的调用都会被拒绝。

问题卡片使用宿主的 `ctx.userQuestions`，与 dsh 原生向用户提问的通道一致；无法弹出卡片时（没有 Web 客户端、子 Agent 调用）回退为原生授权提示（允许一次 / 拒绝）。拦截内部出错时放行并记录警告，但已禁用的插件始终被拒绝。

## 与「插件」页同步

禁用、启用、卸载以及 `enforce` 模式下的自动停用，都调用宿主插件管理器的 `setBundleEnabled` / `removeBundle`，与原生「插件」页的操作相同：

- 在任一页面禁用的插件，另一页面都显示为已禁用；重启前它仍被加载时，工具调用也会被拦截。
- 设置页的「启用」会重新启用 bundle，并允许高危插件的当前版本运行；「恢复默认」重新启用并回到按风险询问。
- 设置页在重新获得焦点时自动刷新。启用或禁用已加载的插件，需重启 dsh 才完全生效。
- 插件管理器无法管理的插件（不是 bundle）才使用本插件自己的拦截记录。早期版本留下的拦截记录会在启动时迁移到插件管理器。

## 配置

在设置页修改，保存在 `$DSH_HOME/plugin-security/state.json`。

| 配置 | 默认值 | 行为 |
| --- | --- | --- |
| 模式 | `report-only` | `off`：不扫描、不拦截、不处置。`report-only`：扫描、记录并拦截调用，不自动停用。`enforce`：另对高置信度恶意审读结论自动停用。 |
| 自动停用阈值 | `critical` | `never` 关闭自动停用。静态命中或依赖漏洞本身从不触发自动停用。 |
| 升级建议 | 关闭 | 开启后为依赖漏洞给出升级命令，不会静默执行。 |
| 白名单 | 内置保护项 | 名单内的插件跳过检查与拦截。本插件、官方 `@deepseek-ai/*` 与 `dsh-plugin-sentinel` 始终受保护，不能通过本插件禁用或卸载。 |

状态目录权限为 `0700`、文件为 `0600`（支持的平台上）；处置日志最多保留 200 条。

## Agent 工具与 skill

```text
security_scan   { package?, force?, evidence? }
security_review { package, verdict: malicious|suspicious|benign, confidence?: high|medium|low, reason? }
```

高置信度 benign 可以解释静态疑点，但不能覆盖依赖漏洞事实；只有高置信度 malicious 会在 `enforce` 模式下自动停用。随包的 [审读 skill](skills/dsh-plugin-security/SKILL.md) 把被审插件的源码、注释、README 和 skill 文本一律视为不可信证据。报告本身不会自动调用模型。

## 隐私与边界

- 依赖审计只向 npm 发送包名与安装版本，向 OSV 发送漏洞 ID；不上传源码或本地路径。Agent 审读遵循你配置的模型服务，提交的证据可能包含源码片段。
- 这是**加载后**的检查，不是沙箱或安装前屏障；审计器与插件共享宿主进程。拦截只覆盖工具调用，插件注入的钩子、系统提示词与 Web 界面不经过 `tools/pre-execute`。
- 静态分析有文件与字节预算，无法覆盖全部跨文件数据流、动态行为或传递依赖；截断与失败会如实标为「有风险」。白名单会主动减少覆盖。

## 排查

- **`/api/security/status` 返回 HTTP 404**：宿主没有注册设置页路由。确认协议版本并重启 dsh；`$DSH_HOME/plugin-security/remote-diag.json` 记录了服务与路由状态。
- **更新插件后行为没变**：替换已安装版本需要重启 dsh。
- **某个工具没有被拦截**：在 debug 日志中查找 `is not attributed to an installed plugin`，说明该工具无法归属到已安装的插件包。

## 开发

```sh
corepack pnpm install --frozen-lockfile
pnpm test            # 单元与集成测试
npm run test:e2e     # 真实 dsh 端到端测试（需要全局 dsh 与 npm 网络）
```

`npm run test:e2e` 在临时 `DSH_HOME` 中用 headless 模板建立 profile，安装本包与 `e2e/` 下的两个测试插件（一个无害但被判为高危的回显插件，一个代替用户点击问题卡片的应答插件），用本地确定性的假模型驱动真实 `dsh`，覆盖首次调用、允许一次（含同一步多个调用）、允许、禁用与原生同步、白名单和关闭模式，不会改动你自己的 profile。

贡献与发布流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 许可证

[MIT](LICENSE) © 2026 dushaobindoudou
