# 证书与部署

本文维护证书签发、状态保存与部署确认的使用流程。配置键由[配置字段索引](CONFIG-KEYS.md)维护；证书或部署的状态、持久化字段和恢复方式变化时同步本文。

## 选择入口

| 来源 | Go 入口 | 需要保存 |
| --- | --- | --- |
| ACME | `cert.ACMEIssuer.Issue` / `Renew` | 账户密钥、账户 URL、证书私钥、证书链和 DNS 挑战归属 |
| 阿里云、腾讯云、UCloud 云证书 | `cert.CloudIssuer` 的分阶段方法 | `CloudOrder`、订单阶段、挑战记录和下载结果 |
| 已有 PEM | `cert.ImportPEM` | 校验后的证书、私钥与部署位置 |

当前覆盖五类 ACME 配置和三类云证书服务的源码入口。厂商 API 的真实申请、扣费、签发和目标部署仍需独立验证，状态见[适配器验证记录](ADAPTER-COVERAGE.md)。

## ACME 签发与续期

`ACMEConfig` 接收 CA、联系邮箱、条款选择、DNS 区域绑定、EAB 和已保存的账户材料。首次签发需要调用方明确接受 CA 条款。Let's Encrypt 和 Google 的 `Mode: "staging"` 使用测试环境；测试环境的证书不可当作正式受信任证书使用。

长期任务按以下顺序保存状态：

1. 通过 `cert.PrepareCertificateKey` 准备证书私钥，并先保存到私有存储。
2. 将私钥作为 `IssueRequest.CertificateKeyPEM` 传入签发请求。
3. 用 `ChallengeObserver.BeforeCreate` 在 DNS 写入前持久化挑战意图。
4. 用 `Created` 保存记录 ID，使用 `Removed` 保存清理结果；这些回调需要支持并发。
5. 收到 `IssueResult` 后保存证书链、私钥、账户密钥和账户 URL，再推进部署。

签发失败也可能返回已经生成的账户密钥或证书私钥。先保存返回状态并核对远端订单，避免把每次失败都当成可以重新开始。`Renew` 会使用传入的账户状态申请替换证书，续期时机和结果持久化仍由调用方决定。

### DNS 挑战归属

求解器创建 TXT 前会精确查询已有记录。相同且已启用的 TXT 值会被复用，清理时保留该原有记录。需要记录复用关系时，实现 `cert.ChallengeReuseObserver.Reused`。

进程中断后，根据写入意图和已知 ID 核对挑战对象。不要只按 `_acme-challenge` 名称删除整组 TXT；同名记录可能被其他签发流程使用。区域、别名和厂商配置需要与证书覆盖域名匹配。

## 云证书订单

`CloudIssuer` 将流程拆为 `Start`、`Challenges`、`SubmitValidation`、`Status` 和 `Download`：

1. 核对账号、套餐、费用和可用实例后创建订单，立即保存 `CloudOrder`。
2. 读取 DNS 验证要求，使用 DNS `Provider` 创建挑战并保存归属。
3. 提交验证并轮询状态；`CloudPending` 需要继续等待，`CloudRejected` 需要排查拒绝原因。
4. 仅在 `CloudIssued` 后下载并校验证书，保存结果再部署。
5. 根据挑战归属执行清理，并保留订单和清理结果。

订单创建结果不明时，先查询原订单或厂商后台。UCloud 的创建入口可能购买证书，阿里云测试证书要求已有可用实例。具体服务政策与费用以操作时的厂商账号为准；源码流程不构成免费或成功签发承诺。

## 部署与异步确认

通过 `deploy.New` 创建目标，将证书链和私钥传入 `Target.Deploy`。部署配置中的域名、产品、目标 ID 和主机校验字段见[配置索引](CONFIG-KEYS.md)。使用 `deploy.Config.Domains` 可传入本次证书域名；显式 `Values["domainList"]` 优先。

| 返回信息 | 后续处理 |
| --- | --- |
| `Result.Written` | 远端已有写入，失败时也要保存并核对结果 |
| `Result.Location` | 保存目标位置或证书 ID，续期时回填对应字段 |
| `Result.Pending` | 保存整个结果，对实现 `deploy.Poller` 的目标继续 `Poll` |
| `CodeResultUnknown` | 暂停自动重试，读取原目标或任务状态 |

AxisNow 的历史位置回填 `uuid`；Rainyun、LeCDN、CDNFly 和 Nginx Proxy Manager 回填 `id`；AWS CloudFront 的证书位置回填 `cert_id`。显式配置优先于历史结果，可选常驻程序会保存已确认的位置。

腾讯云通用云资源、AWS CloudFront 和火山引擎 DCDN 等目标包含异步确认。收到任务 ID 仅代表请求被接受；确认 `Pending=false` 后，业务系统仍应检查实际服务是否提供了目标证书。

## 状态和材料的存放

证书私钥与 ACME 账户密钥需要进入运行用户专属存储，避免写入 Git、工单、页面或普通日志。直接使用 SDK 时由调用方选择存储方案；`dnsgo-agent` 使用权限受限的 SQLite 保存任务和证书材料。

人工导入、续期恢复、异步部署与待核对状态的 CLI 操作见[常驻程序指南](AGENT.md#状态与恢复)。只记录证书摘要、订单 ID、任务阶段及脱敏错误；实际私钥材料单独保管。
