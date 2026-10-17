# DnsGo Go 库接入

本文维护 Go 包的调用方式、数据语义和接入项目应保存的状态。项目定位与首版范围见[README](../README.md)，厂商及部署目标的真实验证状态见[实施状态](IMPLEMENTATION.md)，常驻程序单独见[运行指南](AGENT.md)。公共类型或方法签名变化时先改这里的可编译示例，再更新 README 的入口；不要将未验证行为写成已实测。

22 家 DNS 厂商的凭据键和 50 类证书部署目标的配置键可在[配置字段索引](CONFIG-KEYS.md)查找；那里只列键名，必填组合以适配器构造函数和 `dnsgo-agent check` 的结果为准。

## 包与边界

| 包 | 提供 |
| --- | --- |
| `github.com/rainchen537/dnsgo` | `Provider`、`Zone`、`Record`、`Capabilities`、分页查询与错误分类。 |
| `.../providers` | 22 家 DNS 适配器工厂与阿里云、DNSPod、域名详情等可选扩展接口。 |
| `.../cert` | ACME 和云证书申请、续期所需的结果与订单阶段、手动 PEM 导入。 |
| `.../deploy` | 50 类证书部署目标，接收证书和私钥。 |
| `.../automation` | 探测、故障切换、定时变更、RDAP/WHOIS 查询和到期提醒计算。 |
| `.../notify` | 通知事件、策略和发送渠道。 |
| `.../agent` | 可选的 YAML、SQLite 与常驻任务编排；SDK 使用方不需要导入它。 |

Go 项目自行负责凭据保存、用户/租户授权、审计、任务队列、DDNS 的 IP 来源与变化判断。SDK 的 `Config` 只接收调用时的凭据，不保存凭据。使用方可只导入所需包；`agent` 的 SQLite 不会成为 SDK 的运行依赖。

## 最小 DNS 调用

以下代码展示读取 Cloudflare 域名列表的调用方式。设置环境变量后才会访问厂商；0.x 的接口仍可能随着真实厂商验证调整，接入方应先在自己的测试域名上回读。

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/rainchen537/dnsgo"
    "github.com/rainchen537/dnsgo/providers"
)

func main() {
    provider, err := providers.New("cloudflare", dnsgo.Config{
        Credentials: map[string]string{"token": os.Getenv("CLOUDFLARE_API_TOKEN")},
    })
    if err != nil { panic(err) }

    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()
    page, err := provider.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 20})
    if err != nil { panic(err) }
    for _, zone := range page.Items { fmt.Println(zone.ID, zone.Name) }
}
```

可编译的只读示例放在 [`examples/dns_read/main.go`](../examples/dns_read/main.go)：设置 `CLOUDFLARE_API_TOKEN` 后运行 `go run ./examples/dns_read 域名 主机名`，它会精确定位域名和主机记录并输出 ID、类型、值与 TTL。无凭据时只会提示缺少环境变量；运行时会连接 Cloudflare 并遍历列表页。

`dnsgo.FindZone` 精确匹配时将 Unicode 中文域名和 Punycode 写法视为同一个 DNS 名称，同时保留返回对象中的厂商原始 `Zone.Name` 和 `Zone.ID`。后续记录调用继续使用该对象；此处的名称等价处理只作用于域名发现，不承诺所有厂商的写入参数都可任意替换两种写法。阿里云的这项行为已于 2026-10-18 通过真实只读验证，见[验证记录](ADAPTER-COVERAGE.md#2026-10-18-阿里云真实验证)。

记录更新应先读取目标对象，确认 ID、域名、类型和预期旧值，再修改目标字段并回读。`Record.Values` 在 Route 53、PowerDNS、华为云和青云可表示同一 RRset 的多个成员；`Record.Value` 是选中的逻辑值。切勿丢弃 `Values` 或厂商 `Extra` 后把部分记录当成完整对象写回。调用方应检查 `Capabilities()`；适配器对显式但不支持的字段返回 `CodeUnsupported`，而不会静默忽略。

`Record.Name` 保留厂商适配器写回需要的名称表示：有些返回相对主机名，有些返回完整域名。比较或展示时用 `dnsgo.RecordFQDN(zone, record)` 得到统一的小写完整域名；更新时继续使用原 `Record.Name`。`RecordQuery.Name` 输入相对主机名，根域使用 `@`。

`Capabilities.Lines` 表示可以选择非默认解析线路。只返回默认线路的厂商仍可调用 `RecordLines`，但 `Lines=false`；写入非默认线路会得到 `CodeUnsupported`。默认线路在公共写入校验中接受空值、`default` 和 `0`。

需要代理或自定义超时时，调用方可构造自己的 `*http.Client`，传给 `dnsgo.Config.HTTPClient`、`cert.ACMEConfig.HTTPClient`、各云证书配置的 `HTTPClient` 或 `deploy.Config.HTTPClient`。可选常驻程序还提供逐账号、逐探测和逐任务的 `proxy_url` 配置，见[常驻程序指南](AGENT.md)。

```go
record, err := provider.GetRecord(ctx, zoneID, recordID)
if err != nil { return err }
if record.Value != expectedOldValue { return fmt.Errorf("record changed concurrently") }
record.Value = wantedValue
if len(record.Values) == 1 { record.Values[0] = wantedValue }
updated, err := provider.UpdateRecord(ctx, zoneID, record)
if err != nil {
    if dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
        // A write may already have happened. Use updated.ID if present and
        // read the provider state before deciding whether to retry.
    }
    return err
}
_, err = provider.GetRecord(ctx, zoneID, updated.ID)
return err
```

第二段是可嵌入函数的片段，`zoneID`、`recordID`、`expectedOldValue` 和 `wantedValue` 由接入项目提供。并发冲突控制、权限和审计仍由接入项目负责。厂商 API 成功回读与权威 DNS 生效是两个阶段；需要公网解析生效证明的业务应再查询权威 DNS。

## 可选厂商扩展

公共 `Provider` 覆盖彩虹 DNS `DnsInterface.php` 的常用操作。厂商特有能力通过类型断言访问，调用前先检查是否实现该接口：

```go
if groups, ok := provider.(providers.RecordGroups); ok {
    items, err := groups.ListRecordGroups(ctx, zoneID)
    _ = items
    _ = err
}
if details, ok := provider.(providers.ZoneDetails); ok {
    raw, err := details.GetZoneDetails(ctx, zoneID)
    _ = raw // 厂商原始 JSON，不代表稳定的跨厂商字段
    _ = err
}
```

`providers.AliyunExtras` 还包含权重配置和整组子域记录删除；`providers.DNSPodExtras` 还包含域名别名、账号信息及等级线路。只有阿里云和 DNSPod 实现记录分组；只有上游确实提供单域名详情 API 的适配器实现 `ZoneDetails`。

只需要一个规范化 `Zone` 时，可调用 `dnsgo.FindZone(ctx, provider, "example.com")`。它遍历域名列表并精确匹配名称；百度云和 Route 53 的上游“域名详情”本身也是由列表查找得到，因而使用这个公共入口。`ZoneDetails` 留给能返回厂商原始详情响应的适配器。

彩虹 DNS 的 `getSubDomainRecords` 在 Go 中对应 `dnsgo.ListSubdomainRecords`。传入从 `ListZones` 得到的 `Zone`（同时需要 ID 和域名）、相对主机名或 `@`、以及可选的类型、线路与分页条件。它逐页读取未筛选的厂商列表并精确比较记录名称；某些厂商原生的 `ListRecords` 名称筛选是模糊查询，也可能在每页本地过滤后留下空页，因此不能直接当成唯一目标定位。大账号需要遍历全部列表页，调用方应控制调用频率。
筛选参数使用 `SubdomainQuery`，仅包含上游该方法支持的类型、线路和分页；默认线路的别名只在不支持自选线路的厂商间归一化。

```go
records, err := dnsgo.ListSubdomainRecords(ctx, provider, zone, "www", dnsgo.SubdomainQuery{
    Type: "A", Page: 1, PageSize: 20,
})
```

青云的备注写在主机级别，可能影响同一主机名下的多条记录。公共 `Record.Remark` 与 `SetRecordRemark` 对青云返回 `CodeUnsupported`；确需改主机备注时，断言 `providers.QingCloudHostRemarks` 后调用 `SetHostRemark`，明确传入主机名。

青云上游还提供主机列表及整主机删除。Go 适配器通过 `providers.QingCloudHosts` 暴露 `ListHosts` 和 `DeleteHost`；后者删除该主机下全部解析值。公共 `DeleteRecord` 仍只删除指定逻辑记录，调用方应明确选择作用范围。

PowerDNS 的备注属于整个 RRset。对该厂商调用 `UpdateRecord` 或 `SetRecordRemark` 改备注时，同名同类型的其他值会共享这个备注；空备注会发送空注释列表以清除 RRset 注释。把记录移动到已经有其他值且备注不同的 RRset 时，适配器返回冲突，避免覆盖目标 RRset 的注释。

## 证书和自动化

`cert.ACMEIssuer.Issue` / `Renew` 返回证书、私钥、账户密钥及账户 URL。使用方必须在私有持久化存储中保留账户状态，续期时再传入；失败结果也可能包含新建的账户密钥与待签发证书私钥。长期运行的调用方应先调用 `cert.PrepareCertificateKey`，将返回的私钥保存在私有存储，再作为 `IssueRequest.CertificateKeyPEM` 传给 `Issue`。云证书的 `CloudIssuer` 划分 `Start`、`Challenges`、`SubmitValidation`、`Status`、`Download` 等步骤，调用方要持久化 `CloudOrder`，并用 DNS `Provider` 创建和清理挑战记录。`cert.ImportPEM` 可校验已有证书与私钥。签发结果交给 `deploy.Target.Deploy` 部署；若返回 `Result.Written` 或错误类别 `CodeResultUnknown`，先读取实际目标状态再重试。

长期运行的 ACME 调用方可在 `ACMEConfig.ChallengeObserver` 实现 `BeforeCreate`、`Created` 和 `Removed`，分别持久化写入意图、已知 DNS 记录 ID 与清理结果。`BeforeCreate` 必须在远端写入前完成；进程中断后按保存的意图核对挑战记录。回调可能并发执行，具体存储和锁由调用方负责。可选常驻程序已经实现这套记录。

ACME 求解器创建 TXT 前会精确查询同名记录；已有相同且启用的值时复用，并且清理时不会删除这条原有记录。需要持久化复用关系的调用方可额外实现 `cert.ChallengeReuseObserver.Reused`；常驻程序已实现并记录该记录不归自己所有。

部署目标若返回 `Result.Location`，调用方应保存它；AxisNow 下一次调用填入 `uuid`，Rainyun、LeCDN、CDNFly 与 Nginx Proxy Manager 填入 `id`，AWS CloudFront 填入 `cert_id`，这样续期会更新已确认的目标。`agent` 包会自动保存并回填这些 ID；直接使用 `deploy` 包的项目自行持久化。用户显式指定的 ID 优先于历史返回值。

`deploy.Result.Pending=true` 表示远端只接受了异步部署任务，尚未确认生效。调用方须保存整个 `Result`，对实现 `deploy.Poller` 的目标调用 `Poll`，直到 `Pending=false` 再记为成功。腾讯云通用云资源部署会返回 `deploy_record_id`；可选的 `(*deploy.Tencent).InspectDeploymentRecord` 能读取每页部署详情。AWS CloudFront 与火山引擎 DCDN 也通过只读状态轮询确认部署。常驻程序会自动保存并轮询，人工恢复摘要只显示任务 ID，不包含证书或私钥。

创建部署目标时，可把本次证书的 DNS 名称传入 `deploy.Config.Domains`。需要上游 `domainList` 的目标会默认收到这些域名；`Config.Values["domainList"]` 显式设置时优先，适合只部署证书覆盖范围中的部分域名。常驻程序从签发或导入结果自动传入证书域名。华为云 ELB 直接从证书 SAN（无 SAN 时取主题名）构造其 `domain` 参数。

腾讯云 `product=update` 与 `product=update_new` 也返回异步结果。`update_new` 显式启用的旧证书删除会在部署详情确认成功后作为后续步骤执行；如果该步骤结果不明，常驻程序保留待人工核对状态。

`automation` 保留纯 Go 的任务计算与状态转换，调用方可使用自己的数据库和调度器。`automation.RegistrationLookup` 从 IANA RDAP 服务清单定位域名查询服务，再以 WHOIS 回退；到期日期缺失或网络失败时保留上次已知日期。`notify.Dispatcher` 按故障切换、证书、域名到期三类事件分配渠道。需要独立运行时，使用 `cmd/dnsgo-agent`；它已组合这些库能力并在 SQLite 中保存状态。

## 阿里云 DNS 的实测调用约定

- `FindZone` 返回的域名名称和 ID 可直接用于后续调用；中文与 Punycode 输入在域名发现阶段等价。
- CAA 值使用厂商格式，例如 `0 issue "letsencrypt.org"`，保留引号；SRV 值使用 `优先级 权重 端口 目标域名`。
- URL 转发使用 `REDIRECT_URL`（显性）和 `FORWARD_URL`（隐性）；兼容输入 `URL` 会映射为 `REDIRECT_URL`，回读返回厂商原生类型。API 记录写入与真实 HTTP 跳转分别验证；套餐配额可能限制同时存在的转发记录数。
- 阿里云详情接口省略负载均衡权重。DnsGo 对 A、AAAA、CNAME 的 `GetRecord` 会通过记录列表补充权重，因此该调用也需要 `DescribeDomainRecords` 权限；列表与详情不一致时返回结果不明。显式权重范围为 1–100，越界值在写入前拒绝。
- `AliyunExtras.SetWeightStatus` 的 `subdomain` 使用完整子域名；省略 `line` 操作整体权重开关，指定线路则操作该线路。`WeightedSubdomain.Open` 保留整体开关，线路覆盖状态在 `Extra.LineAlgorithms.LineAlgorithm` 中，二者分别核对。`ListWeightedSubdomains` 的关键词可使用相对主机名或使用同一 `Zone.Name` 的完整名称。
- `DeleteSubDomainRecords` 的 `subdomain` 使用相对主机名，会删除该主机名下所有类型的记录。调用方须确认每条目标记录均属于本次操作。
- 日志的 `Action`、`Message` 和 `CreatedAt` 分别保留操作行为、消息与时间。记录分组列表和默认分组归位已实测；当前测试账号没有自定义分组，其跨自定义分组移动仍待验证。

真实账号范围、权威查询和清理摘要由[适配器验证记录](ADAPTER-COVERAGE.md)维护。SDK 不保存凭据，也不购买或升级厂商套餐。

## 与现有业务系统的接入点

已有业务系统可能采用 RRset 所有权、租户凭据与变更审计等契约。接入时应建立显式映射：使用方负责授权、凭据解密、记录所有权、幂等键和写后回读；DnsGo 负责厂商协议与能力报告。现有厂商路径须先做行为对照，再逐个启用其他适配器。消费者集成需要独立验收。
