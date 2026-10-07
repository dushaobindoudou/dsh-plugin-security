# dsh-plugin-security

[English](./README.md) · [npm](https://www.npmjs.com/package/dsh-plugin-security) · [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)

**在插件进门之前看清它能做什么——包括每一次升级。**
`dsh-plugin-security` 是 DeepSeek Harness 的供应链安全门禁：安装前审计任意 npm
插件，升级时 diff 能力变化。它读取的不是一个包「声称」要做什么，而是它**实际
发出来的代码**，并以 文件:行号 证据输出权限画像。

dsh 插件商店明确不提供沙箱隔离：插件一旦加载，就能拿到完整的 `ctx`——你的文件
系统、Shell、以及发给模型的请求。这个插件就是那扇门前面缺失的安检口。

## 它做什么

**1. `plugin_security` —— 安装前审计。** 给它一个 npm 包名（或本地插件目录），
它直接从 registry 下载 tarball、扫描实际分发的文件，返回权限卡片：

```markdown
## Plugin security: some-plugin@1.2.3

**Risk: REVIEW** — 安装此版本前建议人工复核。

| 面 | 观测 |
|---|---|
| 安装脚本 | no |
| 文件系统读取 | **yes** |
| 子进程 | **yes** |
| 网络 | **yes** |
| 凭据访问 | **yes** |
| 出站主机 | `api.github.com`, `registry.npmjs.org` |
| 疑似凭据环境变量 | `GITHUB_TOKEN` |
```

每条发现都带 `文件:行号` 证据，可以直接跳到触发它的那行代码。扫描过程构造上
只读：不写盘，tarball 在内存中解析。

**2. `plugin_security_diff` —— 升级门禁。** 经典的供应链攻击从来不是你审计过的
那个版本——是下一个。把两个版本交给 diff，它报告这次升级**新增**了什么：

```markdown
## Plugin security diff: some-plugin 1.2.3 → 1.3.0

**Risk: BLOCK** — 此升级新增了安装脚本和凭据访问。

- 新增能力: install-script, credential-access, network
- 新增出站主机: `collector.evil.example.com`
```

风险按**增量**判定，而不是按旧版本已有的能力判定——修个 bug 的升级保持
clean，哪怕这个插件一直都有文件系统权限。

## 检测模型

| 能力 | 示例 | 严重度 |
|---|---|---|
| `install-script` | package.json 里的 `postinstall` | critical —— npm 攻击的经典载体 |
| `credential-access` | `.npmrc`、`_authToken`、`~/.ssh`、`.aws/credentials`、助记词 | review |
| `fs-write` | `writeFile`、`rm`、`rename`、`mkdir` | review |
| `subprocess` | `spawn`、`exec`、`execSync` | review |
| `dynamic-exec` | `eval`、`new Function`、`vm.*` | review |
| `obfuscation` | 超长 base64 字面量、编码载荷 | review |
| `network` | `fetch`、`https.request`、axios | notice |
| `env-access` | `process.env.*` | notice |
| `fs-read` | `readFile`、`readdir`、`stat` | notice |

**风险等级刻意保守**：

- **block** —— 安装脚本 + 网络/子进程/凭据/写盘/混淆（已知攻击形态），
  或混淆代码同时触碰凭据并动态执行。
- **review** —— 存在危险能力，但形态可能是正当的（文件管理器就需要文件系统
  权限；扫描器为了检测 `.npmrc` 必然要提到它）。
- **notice** —— 只有只读面。
- **clean** —— 未观测到任何能力。

这个插件呈现证据，判决权在你。它不是结论。

## 安装

```sh
dsh plugin --profile web add dsh-plugin-security
```

然后在 harness 里对模型说：

> 安装前先审计一下这个插件：用 plugin_security 检查 "some-package"。

> 升级 dsh-plugin-shop 从 0.8.0 到 0.8.5 之前，先跑 plugin_security_diff 告诉我变了什么。

## 设计说明

- **零运行时依赖。** tarball 下载用 `fetch`；tar 解析是一个小型内存读取器——
  不用 `child_process`，不落临时文件。
- **扫的是分发的代码，不是仓库里的代码。** `dist/` 和 `lib/` 都在扫描范围内；
  只跳过 `node_modules` 和 `.git`。
- **registry 可配置。** 通过 `registry` 选项支持 npmmirror 或企业内部源。
- **构造上只读。** 唯一的副作用是对你配置的 registry 发起 GET 请求。

## 许可

MIT
