# DnsGo 常驻程序

本文维护 `dnsgo-agent` 的配置、运行、状态和故障恢复。公共 Go API 由根目录 [README](../README.md) 与后续 API 文档维护；每家厂商的验证状态只在[实施状态](IMPLEMENTATION.md)记录。修改 YAML 字段、命令或状态机时先更新本文，再更新示例和 README 中的入口。

## 安装与启动

在仓库根目录构建：

```sh
go build -o ./build/dnsgo-agent ./cmd/dnsgo-agent
```

复制[示例配置](../examples/agent.example.yaml)到仓库外，填入自己的域名、厂商 ID、任务 ID 和绝对文件路径。示例使用 `example.invalid`、保留地址和仅供 `check` 的 `/tmp/dnsgo-example-*` 目标路径，**不能直接执行**；正式运行前将证书目标改到运行用户专属目录。将每个 `${NAME}` 对应的凭据放进进程环境；不把实际令牌写入 YAML 或 Git。`DNSGO_STATE_DB` 应指向只有运行用户能访问的目录中的绝对路径。

```sh
./build/dnsgo-agent check -config /absolute/path/agent.yaml
./build/dnsgo-agent once -config /absolute/path/agent.yaml
./build/dnsgo-agent run -config /absolute/path/agent.yaml
```

`check` 只解析配置并构造适配器，校验故障探测、证书部署参数及 ACME 挑战区域绑定；不会连接厂商，也不会运行任务。`once` 执行一个任务轮次；`run` 立即启动故障切换、定时、证书、到期查询和通知五个独立循环，各自按 `interval_seconds` 推进，证书等待不会阻塞故障探测。同一 DNS 账号的适配器调用会串行保护其本地会话。后两条命令可能修改 DNS、购买/签发证书、部署证书和发送通知。常驻运行使用进程管理器保持单实例；程序用数据库旁的私有 `.lock` 文件拒绝第二个执行进程。

配置检查会拒绝两个故障切换或定时任务指向同一账号、Zone ID 和记录 ID；共享记录需要先在接入项目中定义明确的调度优先级，避免两个独立循环互相覆盖。

`providers` 与 `deploy-targets` 列出当前 Go 模块中注册的厂商和部署目标。此清单表示代码入口存在，不表示所有厂商 API 已实测。

## YAML 顶层字段

| 字段 | 用途 |
| --- | --- |
| `database` | SQLite 绝对路径。父目录须为 `0700`，数据库文件须为普通文件且仅所有者可访问。程序新建时设置 `0600`。证书私钥、ACME 账户材料和任务状态保存在这里。 |
| `interval_seconds` | 常驻轮次间隔，默认 60 秒。 |
| `providers` | 命名 DNS 账号配置；`kind` 是适配器名称，`domain`、`domain_id`、`endpoint`、`proxy_url` 和 `credentials` 对应 `dnsgo.Config`。`credentials` 的键与具体适配器一致。 |
| `failovers` | 故障切换任务列表。`mode` 为 `pause`、`value` 或 `conditional`；`probe.kind` 为 `ping`、`tcp` 或 `http`。`cycle` 沿用上游计数语义，2 表示第 3 次同向探测才切换。`conditional` 的 `siblings` 填其他任务 ID。 |
| `schedules` | 定时 DNS 操作。`action` 为 `enable`、`pause`、`delete` 或 `value`；`cycle` 为 `once`、`daily`、`weekly` 或 `monthly`。一次性任务使用 RFC3339 `at`；周期任务使用 `hour`、`minute`、`weekday` 或 `month_day`，可设 `timezone`。 |
| `certificates` | 证书申请、续期和部署任务。`authority` 为 `letsencrypt`、`zerossl`、`google`、`litessl`、`customacme`、`tencent`、`aliyun`、`ucloud` 或 `manual`。自动签发时 `domains` 是证书域名，`zones` 指定 DNS 验证使用的账号和区域；`deployments` 列出目标。默认到期前 7 天续期。 |
| `expiry` | `domains` 是需要查询注册日期和到期日期的可注册根域名，不接受子域名或重复项；`days` 是提醒阈值。每轮最多刷新 5 个域名，接近到期时每天重查；09:00 以后按 20 小时冷却发送提醒。 |
| `notifications` | 通知渠道及按事件的策略。`failover`、`cert`、`expiry` 可设 `off`、`all` 或 `failures`。失败发送保存在 SQLite 待发送队列，并逐渠道保存成功回执；下轮只重试未成功的渠道。进程在远端接受消息后、保存回执前退出时，该渠道仍可能收到重复投递。 |

配置中的 `${VARIABLE}` 会在启动时从环境变量展开；缺失或空值会让启动失败。厂商密钥和通知令牌建议只使用这种引用。`values` 中的普通非秘密设置，如证书文件路径或启用选项，可以写明文。

需要逐任务指定网络出口时，`providers` 下的账号、`failovers[].probe`、`certificates[]`、`certificates[].deployments[]` 和 `notifications[]` 可设 `proxy_url: ${DNSGO_PROXY_URL}`；未设置时仍使用 Go 默认环境代理规则。支持 `http://`、`https://`、`socks5://`、`socks5h://` 和 `socks4://`，必须包含主机与端口。SOCKS4 可带用户名，不支持密码，且目标须能解析到 IPv4。探测代理只用于 HTTP(S) 探测；可同时配置 `probe.ip`，此时 HTTP/HTTPS 代理通过 CONNECT 连接指定 IP，探测请求仍使用原域名的 Host 与 TLS 名称。SMTP 通知直接连接邮件服务器，不使用此 HTTP 代理字段。若代理地址含凭据，应放在环境变量，不写入 YAML；`check` 会验证地址格式，但不会连接代理。

## 证书服务配置

ACME 的 `zones` 为每个可能出现的 `_acme-challenge` 域名提供最长后缀匹配。已有 DNS 验证 CNAME 别名时，可在 `challenge_aliases` 将原始挑战全名映射到实际写入 TXT 的全名；公开 DNS 验证仍查询原始挑战名。`accept_terms: true` 只在已阅读并接受所用 CA 条款后配置；ZeroSSL、Google 和 LiteSSL 可能需要 EAB。手动 EAB 使用 `eab_key_id` 与 `eab_mac_key`；ZeroSSL 与 Google 也可明确选 `eab_mode: auto`。`customacme` 必须配置 HTTPS `directory`。首次申请与后续续期使用同一账户材料；数据库必须备份。

云证书服务的 `credentials` 键如下，值建议引用环境变量：

| `authority` | 必需的键 | 其他字段 |
| --- | --- | --- |
| `tencent` | `secret_id`、`secret_key`，顶层 `email` | `endpoint` |
| `aliyun` | `access_key_id`、`access_key_secret` | `endpoint` |
| `ucloud` | `public_key`、`private_key`、`user_name`、`phone`，顶层 `email` | `company_name`、`company_address`、`company_region`、`company_city`、`company_country`、`company_division`、`company_postal_code`、`admin_title`、`endpoint` |

云证书订单可能涉及费用和实例配额，运行前应核对账号、订单和厂商现行政策。程序先保存订单 ID，再按 `Challenges` 创建 DNS 记录、检查公开 DNS 传播、提交验证、轮询签发、下载证书并清理挑战记录。部署目标的 `target` 为 `deploy-targets` 输出之一；`values` 使用该适配器的参数名。证书内容与部署目标配置均未变化时，不会重复部署。
部署完成记录同时跟踪证书内容、目标类型、端点、目标参数和证书域名。更改部署配置后，即使证书未更新，下一轮也会重新部署；异步任务执行中更改配置会进入待核对状态。人工 `mark-deployed` 沿用写入前保存的那次目标配置版本。
证书签发完成后更改颁发服务、证书域名、密钥算法或大小，会触发新证书申请。云订单待验证期间若更改订单或 DNS 验证配置，程序停止处理该订单，直到配置恢复一致；需要更换配置时先核对并处理已有订单。

部署目标需要 `domainList` 时，常驻程序默认从本次签发或导入证书的域名填入。`deployments[].values.domainList` 可显式限定目标域名，优先于自动填入；其他目标专用的 `domain` 字段仍按各适配器配置。

AxisNow、Rainyun、LeCDN、CDNFly、Nginx Proxy Manager 首次部署若确认了证书 ID，程序会将其保存在 SQLite，续期时自动回填缺省的 `uuid` 或 `id`；AWS CloudFront 则回填已确认的 ACM ARN 到 `cert_id`。配置中显式填写的值始终优先。部署返回结果不明时不会自动猜测新的 ID，需按下面的恢复流程核对。

已有证书可设 `authority: manual`，并填写绝对路径 `cert_file` 与 `key_file`。私钥文件必须是仅所有者可读写的普通文件；程序验证证书与私钥匹配，文件中的证书变化时重新部署。手动证书不会由程序申请或续期，到期阈值内只发送一次提醒。

## 通知渠道

`notifications[].type` 支持 `smtp`、`sendcloud`、`aliyun_directmail`、`wxpusher`、`telegram`、`qqbot`、`webhook`、`custom_webhook`。SMTP 使用 TLS；`webhook` 根据钉钉、企业微信、飞书或 Lark 的主机名选择消息格式；`custom_webhook` 可配置 `method`、`content_type`、`format`、`headers`、`body`。通知地址须为 HTTPS。主要字段分别为：

- SMTP：`host`、`port`、`user`、`password`、`from`、`to`、`from_name`。
- SendCloud：`api_user`、`api_key`、`from`、`to`、`from_name`。
- 阿里云邮件：`key_id`、`secret`、`from`、`to`、`from_name`。
- WXPusher：`app_token`、`uid`；Telegram：`token`、`chat_id`、可选 `topic_id`、`base_url`。
- QQ 机器人：`app_id`、`app_secret`、`open_id`。
- 企业群机器人：`url`、可选 `at_users`；自定义 Webhook：`url` 及上述模板字段。

## 状态与恢复

程序在 SQLite 中保存故障切换计数、定时下次运行时间和执行意图、域名到期时间、证书订单及私钥、各目标部署指纹和待发送通知。定时任务会先保存执行意图；进程中断后先回读 DNS 状态，能确认操作已达目标时推进下次时间，无法确认时保留待核对状态。写入状态与通知入队在同一事务中完成。SQLite 文件以及伴随的 WAL/SHM 文件都须留在私有目录；备份应在停止程序后进行，并作为敏感资料保存。

定时任务的意图会记录写入时的配置指纹；待核对期间若修改动作、目标记录或周期参数，程序停止自动推进。回读结果与目标不一致时也不会自动重写，需按下文用 `resolve-schedule` 明确选择 `retry` 或 `mark-done`。

故障切换首次运行会回读记录并以实际启停或主备值建立初始状态；记录值与两端配置都不匹配时停下并报错。执行切换前持久化意图，重启后先回读记录确认目标状态，无法确认时停止该任务的自动写入。停止常驻进程并核对 DNS 后，可用 `inspect-failover -database 状态库 -id 任务ID` 查看意图；确认尚未切换时用 `resolve-failover -database 状态库 -id 任务ID -action retry`，确认已经切换时用 `-action mark-done`。如厂商换了记录 ID，`mark-done` 可加 `-record-id 新ID`。恢复操作只改本地状态，不直接写 DNS。

任务错误对外只输出厂商、操作、错误类别和可安全显示的请求 ID；原始厂商错误内容可能包含敏感字段，不进入通知或常驻日志。若需要排障，可凭请求 ID 到厂商后台查询对应请求。

证书签发、云订单创建、DNS 验证记录创建、验证提交或部署时如果进程中断，结果可能已经发生但本地未能确认。程序会停在 `issuing`、`unknown_start`、`unknown_challenge`、`unknown_validation`、`deploying:<id>`、`pending_deploy:<id>` 或 `unknown_deploy:<id>`，继续处理其他任务。先停止常驻进程，向厂商、DNS 或目标系统核对真实状态，再查看摘要；摘要列出待处理记录的厂商、区域、记录 ID、名称与归属，不显示验证值：

腾讯云通用云资源部署创建远端任务后进入 `pending_deploy:<id>`，常驻程序按轮次只读查询任务详情；全部资源确认成功后才记录部署完成。`inspect-cert` 摘要的 `pending_deployments` 提供任务 ID。任务明确失败时转入 `unknown_deploy:<id>`，等待核对部分成功的资源；人工确认后可用 `mark-deployed`，或在确认安全后用 `retry`。

```sh
./build/dnsgo-agent inspect-cert -database /absolute/path/state.db -id website-tls
```

确认操作没有成功，或确认可以安全重复时，执行 `resolve-cert ... -action retry`。若 `unknown_start` 的摘要包含 `order_id`，且已在厂商后台确认订单已进入 DNS 验证阶段，可执行 `resolve-cert ... -action resume-order`，沿用保存的订单。`unknown_challenge` 表示创建或清理验证记录的结果不明；先检查并清理残留的本程序记录，再 `retry`，该操作会清空本地旧订单与验证记录关联。若摘要表明证书材料已经签发并已清理残留记录，可用 `-action resume-issued` 保留证书并继续部署。`unknown_issue` 表示 ACME 申请结果无法确认，须核对 CA 状态后才能重试。`unknown_validation` 表示提交验证结果不明；确认尚未提交时可 `retry`，确认厂商已受理时用 `-action mark-validating` 继续查询同一订单。确认某个部署目标已经使用这张证书时，执行 `resolve-cert ... -action mark-deployed`。若同时确认了 AxisNow、Rainyun、LeCDN、CDNFly 或 Nginx Proxy Manager 的目标证书 ID，可附加 `-location 证书ID -target 目标类型`，让下一次续期复用该 ID；摘要的 `reusable_ids` 会列出已保存的值。若 `unknown_start` 没有本地订单 ID，只有确认没有发生有效购买或申请后才能重试；否则先在厂商后台核对，不应直接再次下单。`rejected` 云订单也停留等待核对。恢复命令只修改本地状态，不会直接调用厂商。

定时任务停在 `in_flight: true` 且无法自动回读确认时，先停止常驻进程，并在厂商后台核对目标记录：

```sh
./build/dnsgo-agent inspect-schedule -database /absolute/path/state.db -id maintenance-enable
./build/dnsgo-agent resolve-schedule -config /absolute/path/agent.yaml -id maintenance-enable -action retry
./build/dnsgo-agent resolve-schedule -config /absolute/path/agent.yaml -id maintenance-enable -action mark-done
```

`retry` 表示已确认任务尚未达到目标并允许下一轮重试；`mark-done` 表示已确认目标状态正确，仅推进本地任务。若改值后厂商返回了新的记录 ID，`mark-done` 可额外传 `-record-id 新ID`。恢复命令要求原配置和环境变量仍可读取，并取得同一个进程锁。

此版本仍未得到所有厂商的真实账号验证。具体缺口和已通过的检查见[实施状态](IMPLEMENTATION.md)。新增配置字段时同时更新示例；新增故障阶段时在此说明恢复方法。
