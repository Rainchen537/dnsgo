# 快速开始

本文维护首次接入、版本选择和只读验证步骤。接口语义由 [SDK 接入指南](SDK.md)维护；安装命令、Go 版本或最小示例变化时同步本文。

## 安装 Go 模块

DnsGo 要求 Go 1.24 或更新版本。在已有 Go 模块的项目目录中执行：

```sh
go get github.com/rainchen537/dnsgo@v0.1.1
```

`v0.1.1` 为预发布版本。升级前查看[版本发布](https://github.com/Rainchen537/dnsgo/releases)，核对目标厂商的[验证状态](ADAPTER-COVERAGE.md)，并在自己的测试域名上完成回读。

| 接入方式 | 入口 | 调用方负责 |
| --- | --- | --- |
| 在 Go 服务中调用 | 根包与 `providers`、`cert`、`deploy`、`automation`、`notify` | 凭据、权限、状态、调度与审计 |
| 独立运行任务 | `cmd/dnsgo-agent` | YAML、环境变量、私有状态目录与进程管理 |
| 非 Go 服务 | 后续规划的 HTTP 服务 | 当前需要自行提供跨语言封装 |

## 先运行只读示例

克隆源码后运行仓库中的示例。单纯构建 Go SDK 和文档站无需下载参考子模块；维护源码盘点和生成清单时再初始化它。

```sh
git clone https://github.com/Rainchen537/dnsgo.git
cd dnsgo
go build -o ./build/dns_read ./examples/dns_read
```

示例读取进程环境中的 `CLOUDFLARE_API_TOKEN`。在自己的私有凭据环境中注入该变量后，使用实际托管域名和相对主机名运行：

```sh
go run ./examples/dns_read example.com www
```

将 `example.com` 换成账号中实际存在的测试域名；根域主机名使用 `@`。输出包含记录 ID、完整名称、类型、值与 TTL。示例只读取 Cloudflare，未设置变量时会报缺少环境变量并退出。它的源码位于 [`examples/dns_read/main.go`](../examples/dns_read/main.go)。Cloudflare 当前仍标为尚未真实服务验证；示例可编译和真实账号可调用分别验收。

此示例会将记录值输出到终端。分享结果前删除业务信息，避免将输出直接粘贴到公开 issue 或文档。

## 选择厂商

调用 `providers.New(kind, dnsgo.Config{...})` 创建适配器。厂商标识与凭据键在[配置字段索引](CONFIG-KEYS.md)中维护，例如 `aliyun` 使用 `AccessKeyId` / `AccessKeySecret`，`cloudflare` 使用 `token`。凭据键大小写及别名以构造函数为准。

推荐按以下顺序接入：

1. 从私有凭据存储构造 `dnsgo.Config`，为请求设置 `context` 超时。
2. 查询 `Capabilities()`，确认计划使用的记录类型与可选功能。
3. 用 `dnsgo.FindZone` 精确发现域名，保存返回的 `Zone`。
4. 用 `dnsgo.ListSubdomainRecords` 精确查询主机名，检查返回的分页结果。
5. 在测试域名上验证写入和回读后，再接入业务任务。

完整调用示例见 [SDK 接入](SDK.md)，记录名称、RRset 和写入恢复见 [DNS 操作](DNS-OPERATIONS.md)。

## 常驻程序

```sh
go build -o ./build/dnsgo-agent ./cmd/dnsgo-agent
./build/dnsgo-agent providers
./build/dnsgo-agent deploy-targets
```

将 [`examples/agent.example.yaml`](../examples/agent.example.yaml) 复制到仓库外，配置私有绝对路径并注入环境变量后，先执行 `check`。配置检查不会连接厂商；`once`、`run` 会执行任务，可能写入 DNS、申请或购买证书、部署证书和发送通知。配置、状态目录和恢复操作见[常驻程序指南](AGENT.md)。

## 后续阅读

- [DNS 操作](DNS-OPERATIONS.md)：定位、分页、能力、更新与结果不明。
- [证书与部署](CERTIFICATES.md)：签发状态、挑战记录、部署 ID 与异步确认。
- [自动化与通知](AUTOMATION.md)：故障切换、调度、到期提醒与调用方职责。
- [故障排查](TROUBLESHOOTING.md)：按错误分类定位，保留必要的诊断信息。
