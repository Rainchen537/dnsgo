# DnsGo 实施与验证状态

本文只记录 Go 实现与验证的实际状态。上游源码入口和静态能力由[上游源码盘点](UPSTREAM-INVENTORY.md)维护；项目定位与发布范围由根目录 [README](../README.md) 维护。新增实现时同步更新本表，并区分编译、源码行为对照、真实厂商 API 和消费者集成证据。

## 当前状态

首版约定的源码功能范围已有 Go 实现：公共 DNS 契约、上游 22 家 DNS 适配器、8 类证书服务、50 类部署目标，以及故障切换、定时变更、证书续期/部署、到期提醒、通知和可选常驻程序。源码结构检查覆盖公共方法、证书工作流、68 个部署产品分支与 57 个可识别 API 动作；Go 1.24 测试、静态检查和双平台构建在本地通过。**这些证据不等于全部真实厂商、CA 或部署目标可用性证明**。2026-10-18，本地修正后的阿里云 DNS 通过两组真实账号的基础及扩展操作验证，范围和脱敏证据见[适配器验证记录](ADAPTER-COVERAGE.md#2026-10-18-阿里云真实验证)；其余厂商与未执行能力保持尚未实测。使用方仍需完成自己的集成验收，不能仅凭 SDK 的厂商验证直接切换生产。

上游 `app/lib/cert/huoshan.php` 存在，但没有出现在 `CertHelper` 的注册清单中；[上游盘点](UPSTREAM-INVENTORY.md)将其单列为未登记源码。现行首版范围的“8 类证书服务”指上游可调用的 8 类，后续若该入口转正需同步扩展 Go 注册与状态表。

| 领域 | 计划范围 | 当前状态 | 证据边界 |
| --- | --- | --- | --- |
| 公共 DNS 契约 | 上游公共操作、厂商能力、记录与错误模型 | 类型、接口、精确查找和错误分类已实现 | Go 1.24 测试与静态检查通过；厂商语义仍需真实回读 |
| DNS 厂商 | 22 个 | 22 家源码调用流程及非空壳公共方法已实现，厂商扩展见独立接口 | 名称/方法结构检查通过；阿里云两组账号的基础操作、启停、13 条线路、额外类型、权重、日志等扩展用例及权威查询通过；建域受 TXT 验证前置条件限制，其余厂商及未执行能力尚未实测 |
| 证书服务 | 8 类 | 5 类 ACME 共用签发核心，腾讯云、阿里云、UCloud 三类云证书覆盖下单、验证、下载、撤销/取消阶段 | 工作流方法检查通过；真实 CA/云订单尚未实测 |
| 证书部署 | 50 类 | 50 类目标与 68 个产品分支已有调用流程，异步目标保留待完成轮询 | 产品分派和动作名称检查通过；真实目标均尚未实测 |
| 自动化 | 故障切换、定时、证书续期/部署、到期提醒、通知 | 探测、切换、定时操作、证书编排、RDAP/WHOIS 和通知渠道已组合 | 本地状态/配置及代理路径检查通过；未运行真实厂商任务 |
| 独立常驻程序 | 配置文件、环境变量、SQLite | `dnsgo-agent` 支持配置检查、单次/常驻轮次、状态持久化、通知队列和人工恢复 | 示例 `check`、SQLite 权限/单实例锁、Linux amd64 与 macOS arm64 构建通过；未运行真实任务 |
| 使用方集成 | 复用 DnsGo Go 库且保留现有业务边界 | SDK 接入说明和只读示例已备好；面板侧尚未切换 | 消费者集成需要在对应业务系统中单独验证 |

## 实现证据与限制

NameSilo 的请求方法、记录 ID 类型、`host` 的完整域名形式，已对照[NameSilo 官方 API 总览](https://www.namesilo.com/api-reference)与[记录列表文档](https://www.namesilo.com/api-reference/pages?uid=dns%2Fdns-list-records)；Go 接口将完整域名转为相对记录名。此项仍缺真实账号调用验证。西部数码响应可能使用 GBK，适配器用 `golang.org/x/text` 解码；尚缺真实接口验证。

ACME 核心使用 [ACMEz](https://github.com/mholt/acmez)；ZeroSSL 自动 EAB 指向其官方接口，Google 自动 EAB 按上游实现指向第三方 `gts.rat.dev`，仅在调用方明确选择 `EABMode=auto` 时使用。调用方可提供自己的 HTTPS EAB 地址或手动填入 EAB 凭据。账号私钥和 URL 由调用方持久化，错误返回中如已生成账号密钥也会返还其状态。此流程尚未连接真实 CA 验证。

Technitium 上游用列表下标和一天缓存定位记录；Go 适配器使用记录内容标识并在修改前重新读取。完全相同的重复记录无法可靠区分时返回冲突，不执行修改。这一差异需要真实 Technitium 实例验证。

AWS Route 53 使用[官方 Go SDK](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/route53)。单值改动保留 RRset 其他值；跨 RRset 的修改提交同一批次，按 [Route 53 变更接口](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)构造。别名和策略记录不走普通记录操作。尚缺真实 AWS 账号验证。

Route 53 的建域和记录变更遇到传输中断、HTTP 408/5xx 时归为结果不明；SDK 包装的明确 4xx 拒绝仍保留具体错误类别。本地错误映射检查已通过，尚未进行真实 Route 53 故障回读。

华为云线路清单来自参考仓库的 `app/data/huawei_line.json`，运行时复制在 `providers/data/huawei_line.json`。上游更新时需重新对照并更新此文件。多值记录通过 `Record.Values` 保留整组；更新时缺少多值列表会返回冲突，避免覆盖其他值。

青云 DNS 以主机、记录组和值分层。Go 适配器展开所有主机的值，更新或删除单个值时保留同组其余值。上游默认 API 地址为 HTTP；Go 默认采用 HTTPS，是否可用尚未实测，调用方可明确配置端点。
青云的 `updateDomainRecordRemark` 实际写入整个主机的描述，而非单个值。Go 公共记录备注能力因此标为不支持；需要这项上游功能时通过 `providers.QingCloudHostRemarks.SetHostRemark` 明确操作主机级描述。显式的 `Record.Enabled` 现在通过值级状态接口执行，创建/更新后的状态步骤失败时保留已知记录 ID 并报结果不明。

PowerDNS 官方 [RRset API](https://doc.powerdns.com/authoritative/http-api/zone.html) 将注释定义为 RRset 级字段，空注释数组才表示清除。Go 适配器的备注更新和显式清空按此语义写入；跨 RRset 移动单个值时若目标 RRset 的备注不同，先返回冲突，避免覆盖其他成员的注释。真实 PowerDNS 实例尚未验证。

宝塔 DNS、彩虹 DNS、华为云和西部数码的记录创建/更新也已接入显式 `Record.Enabled` 处理：在主写入未覆盖状态时调用对应启停接口，附加状态写入失败会返回带记录 ID 的结果不明。是否有厂商计划或权限限制，仍需真实账号验证。

百度、火山引擎、腾讯云 EdgeOne、DNSLA、京东云和 Technitium 的显式启停字段也已逐条补到创建与更新流程；GoEdge 更新在同一请求提交状态，创建禁用记录时再调用启停接口。创建成功但厂商没有返回记录 ID 的路径会报告结果不明。部分厂商源码会忽略显式的零权重，Go 适配器现在直接拒绝这类值；青云只有 A/CNAME 的加权模式允许填写权重。以上仍缺真实账号验证。

阿里云和 DNSPod 的上游扩展入口已映射为 `providers.AliyunExtras`、`providers.DNSPodExtras` 与共同的 `providers.RecordGroups` 类型断言接口。它们覆盖记录分组、阿里云权重子域/启停/记录权重与子域记录删除、DNSPod 域名别名/账号/域名权限/按等级线路等调用。返回中的非统一厂商字段保留为 JSON；当前只完成源码动作和参数初步对照，尚无真实账号验证。

阿里云与 DNSPod 的更新路径现在对原备注不为空而目标备注为空的情况显式调用备注接口；两家的官方文档均规定空内容用于删除原备注：[阿里云](https://help.aliyun.com/en/dns/api-alidns-2015-01-09-updatedomainrecordremark)、[DNSPod](https://cloud.tencent.com/document/api/1427/56155)。彩虹 DNS 自身适配器更新时也补充调用独立备注接口清空已有备注。这些路径尚未通过真实记录回读。

上游真正调用单域名详情 API 的阿里云、DNSPod、Cloudflare、阿里云 ESA、DNSLA、彩虹 DNS、华为云、火山引擎和京东云已提供 `providers.ZoneDetails` 可选接口，保留非统一字段的 JSON。AWS 与百度上游通过域名列表模拟详情，其余上游 `getDomainInfo` 返回 false；调用方可使用公共 `ListZones`。该可选接口仍需真实账号核对响应字段。

记录写入新增统一字段预检：显式传入备注、权重、禁用状态、代理、非默认线路或多值时，适配器若不支持则返回 `unsupported`，不再静默丢弃。阿里云与 DNSPod 的创建/更新现在对需要额外 API 的状态和备注单独处理；主记录写入后若附加操作或回读失败，会保留已知记录 ID 并返回 `result_unknown`，供调用方先查询再重试。AWS Route 53 的批量变更若发生无响应传输错误也归为结果不明。通用 HTTP 部署请求发生写入传输错误、响应读取错误或服务端 5xx 时，也归为结果不明；常驻程序会暂停该目标自动重试，等待人工回读。这些是源码层面的安全性修正，尚缺真实账号回读验证。

Cloudflare 上游以改名为 `_pause` 实现解析记录暂停。Go 适配器的创建、更新和状态切换现在统一按 `Record.Enabled` 编码该名称；只配置 Zone ID 时会先读取域名名称，再处理 `@` 和相对记录名，避免写入空的 apex 名。按名称筛选时会分别查询正常名与暂停名、合并过滤后分页；仅按状态或值筛选时会读取完整页面后再过滤，超过 100 页时返回明确错误，避免返回错误的分页总数。真实 Cloudflare 响应仍待账号验证。

[Cloudflare DNS Records API](https://developers.cloudflare.com/api/resources/dns/subresources/records/) 将 CAA 与 SRV 同时表示为格式化 `content` 和可选 `data`。适配器读取时优先保留已有 `content`；缺失时从 `data` 组合值，并避免对已包含优先级的 SRV 文本重复加前缀。此行为只按官方文档和源码核对，未以真实记录验证。

UCloud 证书服务的订单对象会返回并由调用方持久化。下载证书时只在内存中解析 ZIP，按完整链优先搜索证书 PEM 与私钥组合并验证匹配，不会将压缩包解压到文件系统。真实申请、扣费情况和下载响应尚未实测。

部署目标已接入 `local`、`cachefly`、`gcore`、`proxmox`、`baishan`、`rainyun`、`xp`、`safeline`、`uusec`、`kuocai`、`mwpanel`、`lucky`、`axisnow`、`lecdn`、`doge`、`acepanel`、`ratpanel`、`btwaf`、`opanel`、`ucloud`、`cdnfly`、`goedge`、`west`、`baidu`、`qiniu`、`upyun`、`ksyun`、`s3storage`、`ftp`、`ssh`、`synology`、`amh`、`k8s`、`kangle`、`kangleadmin`、`btpanel`、`btwin`、`huawei`、`huoshan`、`fnos`、`aws`、`ctyun`、`directadmin`、`nginxproxymanager`、`cloudpanel`、`unicloud`、`qzyun`、`wangsu`、`tencent`、`aliyun`。其中 Rainyun 新上传后若响应没有 ID，会按上游流程查列表并把 ID 返回给调用方保存；查询失败时返回已写入状态和错误。多个站点或节点出现部分失败时，适配器尽量返回已写入状态与错误。DogeCloud、七牛云清理过期证书是显式选项 `cleanup_expired=true`，默认关闭。阿里云 ESA 配额满时删除旧证书也须显式设置 `replace_oldest_on_quota=true`，WAF 扩展证书清理须显式设置 `cleanup_expired=true`。又拍云 EC 私钥会转换成标准 SEC1 PEM，避免直接替换 PEM 标题。SSH 需要 `host_public_key` 或 `known_hosts_file`，也可由调用方显式设置 `insecure_skip_host_key=true`；远端命令需 `allow_commands=true`。Kubernetes Secret 使用证书实参，PATCH 使用 Kubernetes 合并补丁 Content-Type，TLS 验证依 kubeconfig 配置。飞牛 NAS 使用 SFTP 临时文件和定向权限修改，未复制上游的整目录 chmod。AWS CloudFront 通过官方 SDK 保留完整分配配置和 ETag 更新。全栈云依赖页面脚本中的 Next.js Server Action 标识和 RSC 数据，页面结构变化会导致明确错误。腾讯云 `update_new` 删除旧证书须显式设置 `delete_old_cert=true`。此处只有源码流程和编译检查，尚未进行真实目标验证。

Rainyun 无 ID 响应的回读改为上传前后分页比较，仅有唯一新增 ID 时才自动确认；否则返回已写入且待人工核对。常驻程序会保存 AxisNow、Rainyun、LeCDN、CDNFly 和 Nginx Proxy Manager 已确认的证书 ID，在续期部署时回填到该目标缺省的 `uuid` 或 `id` 配置；用户显式配置的 ID 优先。多目标写入中的无响应和解析失败路径继续逐项审查。

腾讯云、阿里云、UCloud 证书适配器共用 `cert.CloudOrder`，可分别读取 DNS 验证要求、提交验证、查询签发状态、下载、吊销和取消。阿里云测试证书需要预先存在待使用实例；UCloud 下单调用参考源码的购买接口。代码没有执行真实购买、签发或吊销调用，不能据此推断当前服务政策或费用。

`automation` 包保持任务状态由调用方提供和保存。故障切换的 `Cycle` 沿用上游计数行为：大于 1 时需要先累计到阈值，故 `Cycle=2` 在第 3 次同向结果时切换。定时任务支持一次、每日、每周、每月的启用、暂停、删除、改值；每月不存在的日期直接跳过该月，删除任务成功后结束。这两点是为避免 PHP 日期溢出和重复删除而做的明确差异。域名到期提醒筛选按上游的天数、20 小时冷却与本地 09:00 窗口实现。RDAP 查询使用 [IANA DNS bootstrap](https://www.iana.org/assignments/rdap-dns) 找到服务，并按 [RFC 9083 的注册与到期事件](https://www.rfc-editor.org/rfc/rfc9083.html)解析；WHOIS 是非标准格式回退，无法保证所有后缀都有日期。

常驻程序的定时写入先持久化执行意图，重启后通过 `ReconcileDueSchedule` 回读记录；无法自动确认时可用摘要与人工恢复命令处理。数据库旁的私有跨进程锁阻止两个执行进程同时运行同一批任务。此流程尚未在真实 DNS 写入中验证。

定时任务恢复时若记录仍不符合目标，常驻程序现在保留待核对意图，不会自动重复写入；意图包含任务配置指纹，任务参数在恢复期变化也会停下。人工核对后可重试或标记完成。

常驻故障切换也在写入 DNS 前保存目标意图，重启后先回读记录确认；不一致或记录 ID 变化时暂停自动写入，提供 `inspect-failover` 与 `resolve-failover` 人工恢复。首次运行从实际记录状态初始化计数和主备位置，避免默认值与已存在 DNS 状态相反。该逻辑尚未以真实厂商进行故障演练。

常驻 `run` 模式已将故障切换、定时、证书、域名到期与通知分成独立轮次，并对共享 DNS 账号的适配器调用加互斥锁，避免长时间证书申请阻塞探测，或并发访问上游 HTML 会话缓存。`once` 仍顺序执行一轮。并发运行尚未以真实任务验证。

`notify` 包已有 SMTP、SendCloud、阿里云邮件、WXPusher、Telegram、QQ 机器人、钉钉/企业微信/飞书群机器人、自定义 Webhook；配置支持按故障切换、证书、到期提醒分别选择发送全部、仅失败或关闭。`cert.ImportPEM` 可验证手动证书与私钥，常驻程序能在手动证书文件变化后部署，并在到期阈值内提醒一次。`agent` 包用 SQLite 保存任务状态、证书材料和通知待发送队列；`cmd/dnsgo-agent` 的 `check`、`once`、`run`、证书摘要和人工恢复命令已经可以编译。`check` 已用[示例 YAML](../examples/agent.example.yaml)做本地运行验证；未执行真实通知、购买、DNS 写入或部署。云证书订单创建和部署等结果无法确认的步骤会停在待核对状态。具体配置见[常驻程序指南](AGENT.md)。

通知待发送队列已保存每个渠道的成功回执；某渠道失败时，后续轮次跳过同一事件中已经确认成功的渠道。远端接受消息与本地回执写入之间仍存在不可消除的重复投递窗口，不能承诺恰好一次。

最近的源码审查还将 UCloud 证书密钥参数校验移到购买前，阿里云测试实例选择改成分页，ACME 账户密钥在联网前持久化，并限制参考云证书的通配符申请。部署方面，阿里云 CAS 复用搜索按[官方 `ListUserCertificateOrder` 分页参数](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-listusercertificateorder)遍历并精确比较证书序列号；腾讯云替换证书通过[获取证书详情](https://cloud.tencent.com/document/product/400/41673)的公钥证书指纹确定新 ID，不能确认时保留旧证书；飞牛 NAS、FTP、SSH、本地文件和火山引擎多资源写入会在可能部分成功时返回已写入或结果不明状态。常驻证书失败通知和运行日志输出使用脱敏分类，不记录厂商原始错误文本。这些更改尚未通过真实目标运行验证。

云证书状态接口在拒签时可能同时返回 `rejected` 和错误；常驻程序会先持久化拒签并通知，再清理自己创建的 DNS 挑战。若发现原本就存在相同挑战记录，会复用它但不把它当作自己拥有的记录删除。进程在创建记录后、保存 ID 前退出时可能留下待人工清理的 TXT/CNAME，选择保留他人记录优先。此恢复边界仍缺真实厂商验证。

云证书 DNS 验证记录创建结果不明时，常驻程序现在保存 `unknown_challenge` 并停止自动重复创建；提交验证前保存 `unknown_validation` 意图，进程中断后等待人工确认。清理自己创建的记录前先回读类型和值，发现内容已变化时拒绝删除。恢复摘要列出记录 ID 和归属，具体命令见[常驻程序指南](AGENT.md)。这仍不能消除远端写入和本地状态保存之间的崩溃窗口。

ACME DNS-01 求解器现在可将创建前意图、创建后的记录 ID 与清理结果回调给持久化调用方；常驻程序使用这三个时点保存挑战记录。进程在记录创建但未取得 ID 时停止自动重试，证书已签发而清理仍待确认时可保留证书并人工恢复部署。ACME 的真实 CA 与 DNS 传播流程尚未实测。

云证书和 ACME 的挑战记录定位现在使用公共精确子域列表，逐页复核同名同类型的现有记录。ACME 遇到已有相同且启用的 TXT 时复用，并通过可选 `Reused` 回调保存“非本程序拥有”的关系；清理时只删除自己创建的记录。该行为避免分页筛选过早结束后重复创建挑战；未经过真实 DNS 厂商和 CA 验证。

ACME 账户密钥和本次待签发证书的私钥均在联网前生成并分别保存；续期时旧证书材料不会被提前覆盖。私钥算法或位数与重用的密钥不一致会在联网前报错。持久化库返回的失败结果也可包含本次待签发私钥，调用方需按敏感资料处理。

网宿、CloudPanel、Kangle 和全栈云使用的自有 HTTP 请求路径也已将可能已执行的写入请求超时、响应读取失败或服务端 5xx 标为结果不明。登录等明确无证书写入的请求保持普通错误。仍需逐目标核对业务响应中的异步任务状态和部分成功语义。

部署通用 HTTP 传输和这四条自有请求路径也把写请求收到的 HTTP 408 归入结果不明；CloudPanel 的登录 POST 明确不算证书写入。通用传输有本地 408 分类检查，真实目标的部分执行情况仍未验证。

阿里云 RPC、百度 BCE、华为云、京东云、青云、腾讯云 TC3、UCloud 与火山引擎共用的签名传输层现在也把写请求后的 HTTP 408/5xx 标为结果不明。使用 POST 承载读取动作的接口也会保守归入这一类，常驻程序需要回读后才能安全继续。此分类没有真实厂商故障注入验证。

直接实现 HTTP 传输的 DNS 适配器也完成同一类故障分类：阿里云 DNS/ESA、Cloudflare、DNSLA、Spaceship、PowerDNS、dynv6、Technitium、宝塔、西部数码、DnsMgr、GoEdge、HE.net 与 NameSilo 的写请求遇到 HTTP 408/5xx 后要求回读。NameSilo 的写操作使用 GET 承载，按调用标志区分读取和写入；AWS SDK 错误映射见上段。此项有本地分类测试，尚未进行真实厂商故障验证。

常驻程序现可为 DNS 账号、HTTP(S) 故障探测、证书服务、部署目标和 HTTP 通知分别指定代理地址；使用对应适配器原有的 `HTTPClient` 注入点，不改变 SDK 调用方的存储模型。代理支持 HTTP、HTTPS、SOCKS5 与 SOCKS4（SOCKS4 仅 IPv4/用户名）。探测指定 IP 与 HTTP/HTTPS 代理同时配置时，通过 CONNECT 隧道访问该 IP，并保留原域名作为 Host 和 TLS 校验名；本地检查已确认代理连接目标 IP、HTTP Host 和 HTTPS SNI。代理配置变化会进入证书执行与部署版本判断。真实代理和厂商 API 尚未运行验证。

部署响应审查继续覆盖 DogeCloud、LeCDN、天翼云、雨云、AxisNow、Proxmox、七牛、金山云、阿里云 FC、又拍云、宽彩和 DirectAdmin。写请求收到不可解析或缺失关键字段的响应时，常驻程序现在会保留结果不明或已尝试写入状态，暂停自动重复部署；登录和读列表的解析失败仍按未写入处理。GoEdge 创建证书返回空 ID 时也保留待核对状态。此项只修正恢复语义，尚未证明各服务端的响应结构或异步生效时机。

UCloud 部署的 `AddCertificate` 成功后，后续读取域名配置或查找证书 ID 失败也保留“已上传证书”状态；`UpdateUcdnDomainHttpsConfigV2` 请求失败时保留已尝试写入及已知 ID。这样常驻程序不会因上传后的一次读故障而自动重复整个部署流程。上游的请求参数和证书命名已核对，真实 UCDN 状态仍未验证。

金山云 CDN 与阿里云 CLB 扩展域名部署现在要求配置中的全部目标都在预读取结果中找到后才开始绑定。上游只要求至少找到一个，可能把部分域名遗漏当成部署成功；Go 版本明确返回未找到目标的错误。阿里云 CLB 还会在写入前检查扩展域名 ID，并跳过重复配置项。该差异只用于避免静默部分成功，尚未进行真实服务验证。

火山引擎 CDN 的 [`BatchDeployCert`](https://api.volcengine.com/api-explorer/debug?action=BatchDeployCert&serviceCode=CDN&version=2021-03-01) 官方接口单次最多接受 50 个域名，并以 `DeployResult` 逐域名报告状态。Go 适配器现在分批提交，要求每个请求域名均有成功结果；遗漏或失败会保留已尝试写入状态，不把部分部署当成整体成功。尚未进行真实 CDN 回读。

火山引擎 DCDN 的 `CreateCertBind` 返回后，部署结果现保持待完成；常驻程序用官方 [`ListCertBind`](https://docs.volcengine.com/docs/Station-wideacceleration/QuerycertificatebindingrelationshipListCertBind?lang=zh) 按本次证书 ID 查绑定关系，要求配置中的每个域名都为 `Deployed` 才完成。缺少绑定或 `Waiting` 时继续轮询，未知状态或矛盾结果停止自动宣称成功。该读接口的官方示例同时列出了 `DeployStatus` 字段；真实账号状态尚未验证。火山引擎传输层还识别响应根部和 `ResponseMetadata` 内的两种 `Error` 字段。

腾讯云 CLB 的 [`DescribeListeners`](https://cloud.tencent.com/document/api/214/30686) 官方输入没有分页参数，并返回 `TotalCount` 与 `Listeners`。Go 部署在列表长度小于声明的总数时停止，避免只更新部分 HTTPS 监听器。此防护和前述异步部署轮询均尚未经过真实 CLB 任务验证。

上游部署调用会把证书域名列表作为 `domainList` 注入 GoEdge、SafeLine、飞牛、Lucky、1Panel、Nginx Proxy Manager、西部数码和阿里云 ESA 等目标。Go 的 `deploy.Config.Domains` 现在承担这个共享输入，常驻程序从签发/导入结果传入；目标配置显式给出 `domainList` 时优先。华为云 ELB 的更新请求改从证书 SAN 或主题名构造 `domain`，不再读取只供 CDN/OBS 使用的 `domain` 配置字段。这些输入路径尚未经过真实目标验证。

常驻证书部署的完成版本现在由证书内容、目标类型、端点、目标参数及证书域名共同决定；写入前将该版本与任务意图一同持久化。配置变化不会沿用同一证书的旧部署结果；异步部署过程中配置变化则暂停轮询，等待核对旧任务。此逻辑已做本地纯配置单元检查，未进行真实目标状态验证。

证书签发任务另保存已完成与当前执行的请求版本。颁发服务、域名集合、密钥算法/位数或 ACME 环境变化会让已签发证书进入重新申请流程；只改 DNS 验证区或凭据不会对未到期证书重复申请，但云订单验证中发生这些变化会阻止继续操作旧订单。版本比较和域名规范化已做本地单元检查，尚未以真实 CA 或云订单验证。

ECC 密钥位数的隐式默认值现按实际颁发器计算：ACME 与 UCloud 为 384，腾讯云和阿里云为 256。这样从隐式默认改为另一位数会产生新的签发版本，不会沿用旧证书；纯配置检查已覆盖这四类路径。

云证书下载结果在解析证书与私钥后，现逐个核对证书是否覆盖订单请求域名。厂商返回了可解析但与本次订单不匹配的证书时停止部署并保留待核对状态；此检查仍缺真实云证书下载验证。

部署失败路径的源码复审已覆盖 AcePanel/RatPanel、宝塔 WAF、SafeLine、AMH、Kangle、CloudPanel、XP、1Panel、MWPanel、Lucky、西部数码及阿里云 ESA 的多目标写入。结果不明时保留可能已写入状态，避免常驻程序自动再次部署；SafeLine 与 1Panel 找到匹配证书但更新失败时不会误走新建分支。阿里云 ESA 配额替换删除前会先标记已尝试写入。此处是本地代码审查，仍需真实服务验证。

Kangle 的网站账号会话初始化页现在要求得到可用 HTTP 响应才继续写证书；该只读预检失败时返回未写入，不再忽略请求失败后尝试部署。此分支仍缺真实 Kangle 面板回读。

AWS ACM/CloudFront 部署在 ImportCertificate 或 UpdateDistribution 请求可能已被接受但没有响应时，会保留已尝试写入的结果，等待目标回读后恢复；指定旧 ACM ARN 的查询失败时不再盲目上传新证书。成功返回的 CloudFront 分配状态写入部署结果元数据。常驻程序会保存各目标的 `deploy.Result`（含位置和异步任务 ID），但证书检查摘要只显示是否尝试写入，不显示私钥或原始元数据。

CloudFront 更新后改由只读 `GetDistribution` 轮询，核对分配使用本次 ACM ARN 且状态为 [`Deployed`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetDistribution.html) 才完成部署；`InProgress` 时保留待处理状态。常驻程序会保存成功使用的 ARN，后续续期优先回填缺省的 `cert_id`。此处仍未经过真实 AWS 分配验证。

[腾讯云 `DeployCertificateInstance`](https://cloud.tencent.com/document/product/400/91667) 只创建部署任务，[`DescribeHostDeployRecordDetail`](https://cloud.tencent.com/document/api/400/91658) 才给出各资源的进度和证书 ID。Go 适配器的通用产品部署现在返回 `Result.Pending` 和任务 ID；常驻程序持久化后轮询所有详情页，确认记录对应本次证书且全部成功才标记部署完成。旧版只凭配置中的历史 `record_id` 有成功计数就掩盖新任务错误的做法已移除。真实腾讯云任务状态尚未运行验证。

腾讯云 [`UploadUpdateCertificateInstance`](https://cloud.tencent.com/document/api/400/119791) 与 [`UpdateCertificateInstance`](https://cloud.tencent.com/document/api/400/91649) 同样是异步任务；`update` 与 `update_new` 分支现在保存任务 ID，按对应[更新详情](https://cloud.tencent.com/document/api/400/91652)或[原 ID 更新详情](https://cloud.tencent.com/document/api/400/120056)查询，再确认部署。`update_new` 只有在部署详情全部成功后才进入显式 `delete_old_cert` 清理；关联资源同步超时不会被当作“没有资源”并删除旧证书。此行为尚缺真实腾讯云账号验证，详情分页与状态字段仍需对照现场响应。

HE.net 上游以登录后的 HTML 页面作为管理接口。Go 适配器延续该方式并在内存中维护会话 Cookie；页面结构变化可能影响解析，尚缺真实账号验证。HE.net 的动态 DNS 文档只覆盖特定动态记录，与此处的普通记录管理不是同一接口。

Spaceship 的上游静态标记把 `redirect` 设为 true，但其记录转换代码没有专门的重定向字段；当前[官方 DNS Records API](https://docs.spaceship.dev/)也未列出 URL 转发记录类型。Go 适配器据已实现的结构化转换声明 A、AAAA、MX、TXT、CNAME、ALIAS、NS、PTR、CAA、SRV，不声明 Redirect；列表请求限制在官方 `take <= 500`。如果后续上游或官方接口补充转发类型，再更新能力与实现。

首个对外功能版本覆盖上游参考范围中的全部 22 个 DNS 适配器、8 类证书服务、50 类部署目标，以及已确定的自动化与常驻程序。代码入口和编译只是结构证据，厂商响应、账号权限、异步生效和真实 DNS 结果仍按逐项验证表标注“按源码实现，尚未实测”。CF 优选 IP 和 DDNS 引擎不在 DnsGo 范围内。

上游公共 `getSubDomainRecords` 的精确匹配语义已增加为 `dnsgo.ListSubdomainRecords` 辅助函数。调用方提供 `Zone.ID` 和 `Zone.Name`，函数遍历厂商列表页并按实际记录名复核，避免将阿里云等接口的模糊名称查询误当精确结果；尚未对 22 家真实分页响应逐一执行验证。

精确子域列表和 `FindZone` 的分页完成判断现在按每页实际返回条数累计，不再假设厂商会照请求的 20 条返回；本地分页检查覆盖了厂商单页只返回 1 条、总数为 3 的情况。真实厂商分页行为仍按各适配器单列为尚未实测。

这两个公共定位函数现在读取未筛选的分页结果后做精确匹配，避免适配器先对某一页做本地筛选时出现空页、却遗漏后续匹配记录。宝塔和 DnsMgr 的创建后 ID 查找同样改为未筛选的完整分页，再按名称、类型和值确认新增记录；其内部列表与西部数码、京东云的记录定位，以及阿里云证书实例/上传前查重，也改为累计实际返回条数。这样会增加大账号上的列表请求量，尚未用真实分页接口测量性能。

Go 适配器目前有相对名称和完整域名两种 `Record.Name` 返回形式。公共 `dnsgo.RecordFQDN` 通过 `Zone.Name` 给调用方一致的比较/展示名称，同时保留原名称供同一厂商回写；相对名、根域和完整域名的纯函数检查已通过。逐家写回仍须用真实账号验证。

Route 53、dynv6、HE.net、NameSilo、Spaceship、PowerDNS 与 Technitium 只提供默认线路。这些适配器现在将 `Capabilities.Lines` 设为 false，公共写入校验拒绝非默认线路；查询中的 `default` 和 `0` 作为默认别名处理。PowerDNS 记录列表也补上了线路过滤，防止传入不支持的线路时仍返回全部记录。

百度云与 Route 53 的上游 `getDomainInfo` 通过域名列表查找目标。Go 增加 `dnsgo.FindZone`，遍历分页并精确比较域名，供所有厂商复用；`providers.ZoneDetails` 继续仅用于独立详情 API 的原始响应。此查找函数尚未经过真实账号验证。

上游 `DnsHelper` 的静态能力标记与其适配器源码并非处处一致：百度 `status=false` 但实际实现了启停请求，青云 `add=false` 但实际实现了建域请求，阿里云 `weight=false` 但提供独立的权重和权重开关 API。DnsGo 当前按真实方法实现声明百度启停、青云建域和阿里云权重；阿里云权重调用仍受加权解析模式及账号权限约束。Spaceship 的 `redirect=true` 静态标记缺少上游记录转换和官方记录 API 的对应字段，Go 保持不声明此能力。这些差异不能用静态布尔值直接推导厂商真实可用性。

青云上游 `getDomainRecords` 无子域筛选时返回的是主机行，带主机级备注和记录数量；带子域筛选才返回记录值。Go 公共 `ListRecords` 统一返回记录值，现另以 `QingCloudHosts.ListHosts` 保留主机行，并以 `DeleteHost` 显式对应上游按主机域名删除全部记录的分支。该扩展与单值 `DeleteRecord` 分开，尚未执行真实青云 API 删除验证。

[上游源码盘点](UPSTREAM-INVENTORY.md)现在从固定提交生成 22 家公共 DNS 方法矩阵、8 类证书服务的静态限制和 50 类部署目标的产品选项。该表用于找缺口和同步上游；`✓` 只代表 PHP 方法有非空入口，具体条件、参数、失败分支仍须按适配器源码和 Go 实现核对。

上游更新后先运行 `python3 scripts/upstream_inventory.py --check`。出现差异时更新参考子模块、重新盘点、实现对应变更，再修改本文件和 README 的支持声明。常驻程序和编译产物不进入 Git。

另运行 `python3 scripts/check_go_coverage.py` 对比上游配置清单与 Go 注册入口，检查上游公共 DNS 方法中非 `return false` 的入口是否有非空壳 Go 方法、ACME 与三类云证书的工作流方法，并扫描部署配置中的产品选项、分派分支与可静态识别的 API 动作。当前 DNS 22、证书 8、部署 50 个名称一致，公共方法有非空壳入口，68 个产品选项均有 Go 分派路径，57 个 API 动作名称能在 Go 源码中找到；这个脚本仍只核对静态结构，不证明每个分支的行为、参数或真实 API 可用。
`getSubDomainRecords` 单独核对为共享的精确匹配 Go 辅助入口，而不是要求每家重复实现同一层过滤。

仓库的 [GitHub Actions 工作流](https://github.com/Rainchen537/dnsgo/actions/workflows/ci.yml)在公开推送后执行 Go 1.24 格式/依赖校验、`go test ./...`、`go vet ./...`、上游静态清单与覆盖检查，以及 Linux amd64 / macOS arm64 的常驻程序交叉编译。本机 macOS arm64 已分别用 Go 1.27.1 和 Go 1.24.0 跑过 `go test ./...`，Go 1.24.0 还通过 vet 与双平台交叉编译；发布时以对应提交的工作流结果为准。此处的构建通过仍不等于真实厂商验证。
