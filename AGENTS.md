# DnsGo 项目工作规则

本文约束根仓库的代码、文档和交付流程；上游子模块 `reference/dnsmgr/` 仅供参考，不在其中开发 DnsGo。规则变化时直接修订对应章节，保持与 [Wiki 维护](docs/WIKI.md) 和 [开发与发布](docs/CONTRIBUTING.md) 一致。

## 开始工作

- 全程使用中文沟通；先检查分支、远端和未提交改动，再定位问题和修改。
- 项目以 Go SDK 为核心；调用方拥有凭据、授权、持久化和 DDNS 调度。
- 不读取或提交真实凭据、证书私钥、运行数据库、生产记录或本机账户信息。
- 源码实现、静态检查、真实 API、权威 DNS 和消费者集成分别记录证据。

## 代码与 Wiki 同步

- Wiki 是正式交付物。功能、接口、配置、命令、行为、支持范围和验证结论有变化时，同一提交中更新对应文章。
- 根 SDK 与厂商适配器变更同步 `docs/SDK.md`、`docs/DNS-OPERATIONS.md` 或适配器验证文章；证书与部署同步 `docs/CERTIFICATES.md`；自动化与通知同步 `docs/AUTOMATION.md`；常驻程序同步 `docs/AGENT.md`。
- 内部重构影响实现方式但不影响调用时，在 `docs/IMPLEMENTATION.md` 记录影响范围。纯测试变更由文档同步检查自动跳过。
- 版本、安装方式和使用入口变化时同步 `README.md` 与 `docs/QUICKSTART.md`。新增文章登记 VitePress 侧边栏，常用文章补充首页入口。
- 每篇 Markdown 开头明确职责和续写约定；同一事实只维护一份，其他文章链接引用。生成索引只通过生成器更新。
- 禁止把未实测厂商、CA、部署目标或消费者集成写成已验证；真实验证追加日期、账号范围、限制及脱敏证据。

## 验证与发布

- 文档或网站变更执行 `npm ci`、`npm run docs:check`、`npm run docs:build`。构建产物、依赖缓存和安装包不得提交。
- Go 变更按 `.github/workflows/ci.yml` 执行 Go 1.24 测试、静态检查和清单检查；新增示例需确认可编译。
- `scripts/check_docs_sync.py` 按改动路径检查相关文档是否同步；`scripts/check_docs.mjs` 检查构建页面、内部资源和锚点。
- 用户要求提交、推送或发布时，将本次代码与 Wiki 一起审查和提交；推送后检查 Go CI、Wiki 工作流和公网页面，再报告结果。
- `main` 的每次推送自动检查和发布 Wiki；拉取请求只校验，不发布。站点地址为 <https://rainchen537.github.io/dnsgo/>。
- UI 验证后关闭本次启动的浏览器和临时服务，避免持续占用内存。
