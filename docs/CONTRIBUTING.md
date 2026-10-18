# 开发与发布

本文维护代码、Wiki 和版本交付的协作流程。根目录 [AGENTS.md](../AGENTS.md) 约束自动化维护，站点配置由 [Wiki 维护](WIKI.md)说明；检查脚本、CI 或发布方式变化时同步本文。

## 修改顺序

1. 检查分支、远端、未提交改动和适用规则，定位需要改变的行为。
2. 更新实现及必要示例，保留原有厂商和业务边界。
3. 同步相关 Wiki 文章、生成索引和验证记录。
4. 运行本地检查，审查代码与文档差异后一起提交。
5. 推送后确认 Go CI、Wiki CI 和公开站点，再报告交付状态。

## 文档同步检查

`scripts/check_docs_sync.py` 依据 Git 差异检查实现与对应文章是否出现在同一批变更中：

| 实现改动 | 需同步的文章，至少一项 |
| --- | --- |
| 根目录 Go API、`providers/` | SDK、DNS 操作、故障排查、适配器验证或实施状态 |
| `cert/`、`deploy/` | 证书与部署、SDK、适配器验证或实施状态 |
| `automation/`、`notify/` | 自动化与通知、常驻程序或实施状态 |
| `agent/`、`cmd/`、常驻 YAML 示例 | 常驻程序或实施状态 |
| `examples/` 中 Go 示例、`go.mod` / `go.sum` | 快速开始、SDK 或实施状态 |
| `internal/` | SDK、证书、自动化、常驻程序或实施状态 |
| CI、文档检查及索引生成脚本 | 开发与发布、Wiki 维护或对应生成索引 |

纯 `*_test.go` 变更跳过同步要求。内部重构没有调用变化时，在实施状态记录影响和验证范围；文档检查只能判断文件是否同步，文章内容仍需在审查中核对，不能靠无关修改充数。

本地默认比较 `HEAD` 与工作区，并包含未跟踪文件；CI 比较推送前后提交或拉取请求的基准与目标提交：

```sh
python3 scripts/check_docs_sync.py
npm ci
npm run docs:check
npm run docs:build
```

`docs:build` 在 VitePress 构建后检查生成 HTML 的站内链接、资源和锚点。任一失败都会阻止 Wiki 发布。

## Go 与参考清单

首次需要读取上游源码时执行：

```sh
git submodule update --init --recursive
```

使用与 CI 一致的 Go 1.24 工具链进行检查：

```sh
go test ./...
go vet ./...
go mod verify
python3 scripts/upstream_inventory.py --check
python3 scripts/config_keys.py --check
python3 scripts/check_go_coverage.py
```

新增适配器或配置键时，用对应生成器更新索引，再执行 `--check`；禁止直接编辑生成文件。源码能力变化与真实厂商调用分别记录，新增真实证据必须脱敏。

## 自动更新站点

`main` 的每次推送都会运行 **Wiki** 工作流，先检查文档同步，再构建、校验和发布 GitHub Pages。拉取请求执行相同的检查与构建，保留发布步骤关闭。手动运行工作流时也检查目标提交。

Go 工作流继续验证格式、依赖、测试、静态分析和上游覆盖。源码和 Wiki 文章应随同一提交推送，让公开页面与实现一同更新。该流程更新已维护的文章，不会自动猜测源码含义或生成新的验证结论。

## 发布核对

- 文档站发布与 Go 模块版本发布分开核对。仅修改 Wiki 时无需新增 Go 标签。
- 发布新的 SDK 版本时更新 README 和快速开始中的安装版本，说明接口变化和验证范围。
- Wiki 工作流成功后访问首页、新文章、配置索引和验证证据，确认页面版本及搜索可用。
- 构建产物、依赖、状态文件与证书材料保持在 `.gitignore` 范围内。
