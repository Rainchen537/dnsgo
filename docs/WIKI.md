# Wiki 维护

本文维护文档站的目录、预览、发布和续写约定。SDK 行为由 [SDK 接入指南](SDK.md)维护，验证事实由[适配器验证记录](ADAPTER-COVERAGE.md)维护。

## 本地运行

使用 Node.js 22 或更新版本，在仓库根目录执行：

```sh
npm ci
npm run docs:check
npm run docs:dev
```

开发服务器地址会显示在终端，站点路径为 `/dnsgo/`。结束预览后按 `Ctrl+C` 关闭服务。

```sh
npm run docs:build
npm run docs:preview
```

`docs:check` 检查代码和对应文章是否一起更新；`docs:build` 构建站点并校验 HTML 中的内部链接、资源与锚点。`docs/.vitepress/dist/`、`docs/.vitepress/cache/` 和 `node_modules/` 由 `.gitignore` 排除；只提交源码和 `package-lock.json`。Node.js 只用于维护 Wiki，Go SDK 的构建与运行继续使用 Go 工具链；文档同步检查使用 Python 3。

当前固定使用稳定版 VitePress 1.6.4；其 Vite 5 依赖存在已公开的开发服务器漏洞，`package.json` 通过 `overrides` 固定使用 Vite 6.4.4。配置中的 `dnsgo-local-search-hmr` 插件为本地搜索虚拟模块补充开发热更新的路径解析。升级依赖时运行 `npm audit`、生产构建及开发/预览检查，再更新锁文件。项目概览、上游源码链接与页面更新时间需要 Git 元数据，本地使用 Git checkout，CI 保留完整提交历史。

## 文档分工

| 文件 | 维护内容 | 续写要求 |
| --- | --- | --- |
| 根目录 `README.md` | 定位、边界、当前版本与文档入口 | 变更项目范围时更新，事实细节链接到专用文档 |
| `docs/index.md` | Wiki 首页入口 | 只维护分类、标题和链接 |
| `docs/overview.md` | 引用根 README | 保留 include 指令，正文写入根 README |
| `docs/QUICKSTART.md` | 版本安装、首次只读运行和接入路线 | 版本、Go 要求与最小入口变化时更新 |
| `docs/SDK.md` | Go 调用、公共模型和数据语义 | API 变更先更新调用示例，明确调用方职责 |
| `docs/DNS-OPERATIONS.md` | 域名定位、记录更新、RRset 与回读 | 公共 DNS 语义或厂商差异变化时更新 |
| `docs/CERTIFICATES.md` | 证书申请、状态保存与部署确认 | 签发、挑战、订单或部署结果变化时更新 |
| `docs/AUTOMATION.md` | 探测、故障切换、定时、到期与通知 | 调度、阈值或通知语义变化时更新 |
| `docs/AGENT.md` | 常驻程序配置、命令与恢复 | 变更 YAML、命令或状态机时同步示例 |
| `docs/TROUBLESHOOTING.md` | 错误分类、排查步骤与诊断材料 | 错误或恢复路径变化时更新 |
| `docs/CONFIG-KEYS.md` | Go 配置键索引 | 用 `python3 scripts/config_keys.py` 生成，禁止手工续写 |
| `docs/UPSTREAM-INVENTORY.md` | 上游入口与静态能力矩阵 | 用 `python3 scripts/upstream_inventory.py` 生成，禁止手工续写 |
| `docs/IMPLEMENTATION.md` | 总体实现进度与差异 | 保留证据边界，逐项补充进度 |
| `docs/ADAPTER-COVERAGE.md` | 厂商真实验证与源码对照 | 追加日期、范围、结果与脱敏证据，保留历史记录 |
| 根目录 `THIRD_PARTY_NOTICES.md` | 来源、署名与许可 | 新增第三方内容时补充通知 |
| `docs/third-party.md` | 引用第三方通知 | 保留 include 指令，正文写入根通知文件 |
| `docs/WIKI.md` | 文档站维护与发布 | 目录、脚本、依赖和工作流变更时更新本文 |
| `docs/CONTRIBUTING.md` | 代码与文章同步、检查与交付顺序 | 检查脚本和 CI 变化时同步 |
| `docs/BRAND.md` | 已确认标志、品牌素材与使用约定 | 图形、路径或使用方式变化时同步 |
| 根目录 `AGENTS.md` | 仓库内自动化维护规则 | 项目工作规范变化时修订对应章节 |
| `reference/dnsmgr/README.md` | 上游 PHP 安装说明 | 在上游独立仓库维护 |

新文章直接放在 `docs/`，文件名保持稳定，并在 `.vitepress/config.mts` 的侧边栏中登记。首页常用入口按需补充。每篇文章开头说明维护范围与续写要求；同一事实保留一个维护位置，其他页面使用相对链接引用。

根 README 和第三方通知通过 VitePress include 复用。站内 Markdown 链接保留 GitHub 阅读能力；站点构建时将仓库源码、示例等站外文件链接转换成 GitHub 地址，上游子模块链接指向根仓库锁定的上游提交。`docs/verification/` 中的脱敏 JSON 随站点构建发布；新增证据前先确认其中没有凭据或业务记录。

品牌素材由[品牌素材](BRAND.md)维护。`public/favicon.svg` 是独立图形的唯一来源，导航、首页和浏览器图标共同使用；`public/brand/dnsgo-logo.png` 保留已确认的图文组合，供 README 与白底场景引用。

## GitHub Pages

站点目标地址为 <https://rainchen537.github.io/dnsgo/>，仓库路径由 `.vitepress/config.mts` 中的 `base: '/dnsgo/'` 固定。切换仓库名或自定义域名时，同时更新 `base`、`sitemap.hostname`、图标路径和本文地址。

首次发布需要在 GitHub 仓库的 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**。

`.github/workflows/docs.yml` 负责构建与发布：

- 拉取请求先检查相关 Wiki 是否与代码同步，再执行 `npm ci`、生产构建及内部链接、资源和锚点校验。
- `main` 的每次推送执行相同检查，上传构建产物并发布至 Pages，源码更新也会触发。
- Actions 中可手动运行 **Wiki** 工作流。
- 发布权限仅在部署任务中授予，使用 GitHub 自带的短期令牌。

发布后确认 **Wiki** 工作流成功，再访问首页、SDK、配置字段、验证证据和中文搜索。Git 提交时间用于页面的更新时间；变更验证结论时仍需在文章中记录实际验证日期。

## 持续同步

根目录 `AGENTS.md` 将代码与 Wiki 的同步作为正式交付要求。[开发与发布](CONTRIBUTING.md)列出实现路径与文章映射、本地检查及 CI 的比较范围。功能、配置或恢复方式有变更时，同一提交修订对应文章；新增文章登记侧边栏并补充适用入口。CI 验证文件是否同步和站点是否完整，具体语义及验证结论由维护者审查。
