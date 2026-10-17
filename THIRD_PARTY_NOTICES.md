# 第三方来源与署名

本文件记录 DnsGo 首版开发中参考的上游项目、许可标记和后续维护方式。DnsGo 根仓库原创 Go 代码的许可见 [LICENSE](LICENSE)；第三方源码不会因根仓库许可证而改变原有授权。

## 彩虹聚合 DNS 管理系统

- 项目：[netcccyun/dnsmgr](https://github.com/netcccyun/dnsmgr)
- 保存方式：`reference/dnsmgr/` 独立 Git 子模块，跟随其官方 `main` 分支更新。
- 上游仓库的 [`LICENSE`](https://github.com/netcccyun/dnsmgr/blob/main/LICENSE) 标为 MIT，署名为 `Copyright (c) 2024 消失的彩虹海`。子模块内保留该完整许可文本及其历史。
- 上游 [`composer.json`](https://github.com/netcccyun/dnsmgr/blob/main/composer.json) 的包元数据同时写有 `"license": "Apache-2.0"`。两处标记不同；本文件如实列出，不自行替上游解释适用范围。

DnsGo 用上游的厂商入口、请求参数和业务流程作为对照，Go 适配器在根仓库独立维护。更新子模块或引入上游新的源码片段时，应重新核对其版权声明与许可文件；如果在根仓库直接收录上游的大段实现、文档或素材，应在相应文件附近保留来源与适用许可通知。

## 续写规则

- 新增直接复制的第三方源码、数据或素材时，在此记录来源、版本或提交、用途、许可文件位置及保留的署名。
- 上游许可文件或包元数据变化时同步更新本文件和 [README 的开源与许可说明](README.md#开源与许可)。
- 不把子模块许可证概括为 DnsGo 根仓库所有文件的许可证；也不把字段、API 行为和公开协议当作可复制的源码文本。
