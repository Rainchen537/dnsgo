# 彩虹 DNS 上游源码盘点

本文记录参考子模块中可定位的源码入口、公共方法与静态配置标记，供 DnsGo 实现与上游更新对照。
不代表 Go 功能已实现，也不证明厂商 API 当前可用。新增厂商或改变能力时，先核对上游源码，
再重跑 `python3 scripts/upstream_inventory.py`；Go 实现与真实验证状态另行记录。

上游提交：`b4fcb182ff186ef2c650092e1c0de93e85cbada9`。DNS 适配器 22 个，证书服务 8 类，证书部署目标 50 类。

## DNS 适配器

下表标记来自上游 `DnsHelper::$dns_config`。数字和布尔值保留原文；`—` 表示未找到静态标记。
标记本身不等于该方法已经实测。

| 标识 | 源码 | remark | status | redirect | log | weight | page | add | sort | 额外公开方法 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `aliyun` | [源码](../reference/dnsmgr/app/lib/dns/aliyun.php) | 1 | true | true | true | false | false | true | true | `changeRecordGroup`, `deleteSubDomainRecords`, `getDomainInfo`, `getRecordGroups`, `getWeightSubDomains`, `setWeightStatus`, `updateRecordWeight` |
| `dnspod` | [源码](../reference/dnsmgr/app/lib/dns/dnspod.php) | 1 | true | true | true | true | false | true | true | `addDomainAlias`, `changeRecordGroup`, `deleteDomainAlias`, `domainAliasList`, `getAccountInfo`, `getDomainInfo`, `getDomainPurview`, `getRecordGroups`, `getRecordLineByGrade` |
| `huawei` | [源码](../reference/dnsmgr/app/lib/dns/huawei.php) | 2 | true | false | false | true | false | true | true | `getDomainInfo` |
| `baidu` | [源码](../reference/dnsmgr/app/lib/dns/baidu.php) | 2 | false | false | false | false | true | true | false | `getDomainInfo` |
| `west` | [源码](../reference/dnsmgr/app/lib/dns/west.php) | 0 | true | false | false | false | false | false | false | `getDomainInfo` |
| `huoshan` | [源码](../reference/dnsmgr/app/lib/dns/huoshan.php) | 2 | true | false | false | true | false | true | false | `getDomainInfo` |
| `jdcloud` | [源码](../reference/dnsmgr/app/lib/dns/jdcloud.php) | 0 | true | true | false | true | false | true | false | `getDomainInfo` |
| `dnsla` | [源码](../reference/dnsmgr/app/lib/dns/dnsla.php) | 0 | true | true | false | true | false | true | false | `getDomainInfo` |
| `qingcloud` | [源码](../reference/dnsmgr/app/lib/dns/qingcloud.php) | 0 | true | false | false | true | false | false | false | `getDomainInfo` |
| `bt` | [源码](../reference/dnsmgr/app/lib/dns/bt.php) | 2 | true | false | false | true | false | true | false | `getDomainInfo` |
| `cloudflare` | [源码](../reference/dnsmgr/app/lib/dns/cloudflare.php) | 2 | true | false | false | false | false | true | true | `getDomainInfo` |
| `aws` | [源码](../reference/dnsmgr/app/lib/dns/aws.php) | 0 | false | false | false | false | true | true | false | `getDomainInfo` |
| `namesilo` | [源码](../reference/dnsmgr/app/lib/dns/namesilo.php) | 0 | false | false | false | false | true | false | false | `getDomainInfo` |
| `henet` | [源码](../reference/dnsmgr/app/lib/dns/henet.php) | 0 | false | false | false | false | true | false | false | — |
| `spaceship` | [源码](../reference/dnsmgr/app/lib/dns/spaceship.php) | 0 | false | true | false | false | false | false | false | `getDomainInfo` |
| `powerdns` | [源码](../reference/dnsmgr/app/lib/dns/powerdns.php) | 2 | true | false | false | false | true | true | false | `getDomainInfo` |
| `technitium` | [源码](../reference/dnsmgr/app/lib/dns/technitium.php) | 2 | true | false | false | false | true | true | false | — |
| `aliyunesa` | [源码](../reference/dnsmgr/app/lib/dns/aliyunesa.php) | 2 | false | false | false | false | false | false | false | `getDomainInfo` |
| `tencenteo` | [源码](../reference/dnsmgr/app/lib/dns/tencenteo.php) | 0 | true | false | false | true | false | false | true | `getDomainInfo` |
| `dnsmgr` | [源码](../reference/dnsmgr/app/lib/dns/dnsmgr.php) | 2 | true | true | false | true | false | false | false | `getDomainInfo` |
| `goedge` | [源码](../reference/dnsmgr/app/lib/dns/goedge.php) | 2 | true | false | false | true | false | true | false | — |
| `dynv6` | [源码](../reference/dnsmgr/app/lib/dns/dynv6.php) | 0 | false | false | false | false | false | false | false | — |

## 公共 DNS 方法矩阵

下表逐个读取 `DnsInterface.php` 所列方法在每家 PHP 适配器中的方法体。`✓` 表示存在非空、非单纯 `return false` 的入口；`—` 表示未实现或明确返回不支持。
`getError` 在 Go 中由方法返回的错误值与 `dnsgo.Error` 代替，不作为独立状态方法。
该矩阵不核对方法内部所有分支，更不证明 Go 实现或厂商 API 可用；方法签名和参数以接口源码为准。

| 标识 | 检查 | 域名列表 | 记录列表 | 子域精查 | 记录详情 | 新增记录 | 更新记录 | 备注 | 删除记录 | 启停 | 记录日志 | 线路 | 最小 TTL | 建域 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `aliyun` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `dnspod` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `huawei` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | ✓ |
| `baidu` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | ✓ |
| `west` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | — |
| `huoshan` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| `jdcloud` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | ✓ |
| `dnsla` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| `qingcloud` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| `bt` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| `cloudflare` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | ✓ |
| `aws` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | — | ✓ | ✓ | ✓ |
| `namesilo` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | — | ✓ | — | — |
| `henet` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | — | ✓ | ✓ | — |
| `spaceship` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | — | ✓ | — | — |
| `powerdns` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | ✓ |
| `technitium` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | ✓ |
| `aliyunesa` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | — | ✓ | ✓ | — |
| `tencenteo` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | ✓ | — |
| `dnsmgr` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — |
| `goedge` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| `dynv6` | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | — | ✓ | — | — |

## 证书服务静态限制

数值来自 `CertHelper::$cert_config`；具体下单费用与服务端可用性须另行核对。

| 标识 | 类别 | 通配符 | 最多域名 | CNAME 验证 |
| --- | --- | --- | --- | --- |
| `letsencrypt` | 1 | true | 100 | true |
| `zerossl` | 1 | true | 100 | true |
| `google` | 1 | true | 100 | true |
| `litessl` | 1 | true | 100 | true |
| `tencent` | 2 | false | 1 | false |
| `aliyun` | 2 | false | 1 | false |
| `ucloud` | 2 | false | 1 | false |
| `customacme` | 1 | true | 100 | true |

## 部署目标产品选项

只列 `DeployHelper` 中显式的 `product` 选项；`—` 表示没有产品分支参数。

| 标识 | 产品选项 |
| --- | --- |
| `btpanel` | — |
| `btwin` | — |
| `kangle` | — |
| `kangleadmin` | — |
| `safeline` | — |
| `btwaf` | — |
| `cdnfly` | — |
| `lecdn` | — |
| `goedge` | — |
| `uusec` | — |
| `opanel` | — |
| `mwpanel` | — |
| `acepanel` | — |
| `ratpanel` | — |
| `xp` | — |
| `amh` | — |
| `cloudpanel` | — |
| `directadmin` | — |
| `synology` | — |
| `lucky` | — |
| `fnos` | — |
| `nginxproxymanager` | — |
| `proxmox` | — |
| `k8s` | — |
| `aliyun` | `cdn`, `dcdn`, `esa`, `esa_saas`, `oss`, `waf`, `wafres`, `waf2`, `clb`, `alb`, `nlb`, `api`, `ddoscoo`, `live`, `vod`, `fc`, `fc2`, `ga`, `upload` |
| `tencent` | `cdn`, `teo`, `waf`, `cos`, `clb`, `tke`, `scf`, `ddos`, `live`, `vod`, `tse`, `tcb`, `lighthouse`, `upload`, `update`, `update_new` |
| `huawei` | `cdn`, `elb`, `waf`, `obs`, `upload` |
| `ucloud` | — |
| `qiniu` | `cdn`, `oss`, `pili`, `upload` |
| `doge` | — |
| `axisnow` | — |
| `upyun` | — |
| `baidu` | `cdn`, `blb`, `appblb`, `upload` |
| `ksyun` | `cdn` |
| `huoshan` | `cdn`, `dcdn`, `clb`, `alb`, `tos`, `live`, `vod`, `imagex`, `upload` |
| `west` | — |
| `wangsu` | `cdn`, `cdnpro`, `cdnpro_certificate`, `certificate` |
| `baishan` | — |
| `ctyun` | `cdn`, `icdn`, `accessone`, `cf` |
| `kuocai` | — |
| `qzyun` | — |
| `rainyun` | — |
| `unicloud` | — |
| `aws` | `cloudfront`, `acm` |
| `gcore` | — |
| `cachefly` | — |
| `ssh` | — |
| `ftp` | — |
| `s3storage` | — |
| `local` | — |

## 证书服务

| 标识 | 源码 |
| --- | --- |
| `letsencrypt` | [源码](../reference/dnsmgr/app/lib/cert/letsencrypt.php) |
| `zerossl` | [源码](../reference/dnsmgr/app/lib/cert/zerossl.php) |
| `google` | [源码](../reference/dnsmgr/app/lib/cert/google.php) |
| `litessl` | [源码](../reference/dnsmgr/app/lib/cert/litessl.php) |
| `tencent` | [源码](../reference/dnsmgr/app/lib/cert/tencent.php) |
| `aliyun` | [源码](../reference/dnsmgr/app/lib/cert/aliyun.php) |
| `ucloud` | [源码](../reference/dnsmgr/app/lib/cert/ucloud.php) |
| `customacme` | [源码](../reference/dnsmgr/app/lib/cert/customacme.php) |

## 证书部署目标

| 标识 | 源码 |
| --- | --- |
| `btpanel` | [源码](../reference/dnsmgr/app/lib/deploy/btpanel.php) |
| `btwin` | [源码](../reference/dnsmgr/app/lib/deploy/btwin.php) |
| `kangle` | [源码](../reference/dnsmgr/app/lib/deploy/kangle.php) |
| `kangleadmin` | [源码](../reference/dnsmgr/app/lib/deploy/kangleadmin.php) |
| `safeline` | [源码](../reference/dnsmgr/app/lib/deploy/safeline.php) |
| `btwaf` | [源码](../reference/dnsmgr/app/lib/deploy/btwaf.php) |
| `cdnfly` | [源码](../reference/dnsmgr/app/lib/deploy/cdnfly.php) |
| `lecdn` | [源码](../reference/dnsmgr/app/lib/deploy/lecdn.php) |
| `goedge` | [源码](../reference/dnsmgr/app/lib/deploy/goedge.php) |
| `uusec` | [源码](../reference/dnsmgr/app/lib/deploy/uusec.php) |
| `opanel` | [源码](../reference/dnsmgr/app/lib/deploy/opanel.php) |
| `mwpanel` | [源码](../reference/dnsmgr/app/lib/deploy/mwpanel.php) |
| `acepanel` | [源码](../reference/dnsmgr/app/lib/deploy/acepanel.php) |
| `ratpanel` | [源码](../reference/dnsmgr/app/lib/deploy/ratpanel.php) |
| `xp` | [源码](../reference/dnsmgr/app/lib/deploy/xp.php) |
| `amh` | [源码](../reference/dnsmgr/app/lib/deploy/amh.php) |
| `cloudpanel` | [源码](../reference/dnsmgr/app/lib/deploy/cloudpanel.php) |
| `directadmin` | [源码](../reference/dnsmgr/app/lib/deploy/directadmin.php) |
| `synology` | [源码](../reference/dnsmgr/app/lib/deploy/synology.php) |
| `lucky` | [源码](../reference/dnsmgr/app/lib/deploy/lucky.php) |
| `fnos` | [源码](../reference/dnsmgr/app/lib/deploy/fnos.php) |
| `nginxproxymanager` | [源码](../reference/dnsmgr/app/lib/deploy/nginxproxymanager.php) |
| `proxmox` | [源码](../reference/dnsmgr/app/lib/deploy/proxmox.php) |
| `k8s` | [源码](../reference/dnsmgr/app/lib/deploy/k8s.php) |
| `aliyun` | [源码](../reference/dnsmgr/app/lib/deploy/aliyun.php) |
| `tencent` | [源码](../reference/dnsmgr/app/lib/deploy/tencent.php) |
| `huawei` | [源码](../reference/dnsmgr/app/lib/deploy/huawei.php) |
| `ucloud` | [源码](../reference/dnsmgr/app/lib/deploy/ucloud.php) |
| `qiniu` | [源码](../reference/dnsmgr/app/lib/deploy/qiniu.php) |
| `doge` | [源码](../reference/dnsmgr/app/lib/deploy/doge.php) |
| `axisnow` | [源码](../reference/dnsmgr/app/lib/deploy/axisnow.php) |
| `upyun` | [源码](../reference/dnsmgr/app/lib/deploy/upyun.php) |
| `baidu` | [源码](../reference/dnsmgr/app/lib/deploy/baidu.php) |
| `ksyun` | [源码](../reference/dnsmgr/app/lib/deploy/ksyun.php) |
| `huoshan` | [源码](../reference/dnsmgr/app/lib/deploy/huoshan.php) |
| `west` | [源码](../reference/dnsmgr/app/lib/deploy/west.php) |
| `wangsu` | [源码](../reference/dnsmgr/app/lib/deploy/wangsu.php) |
| `baishan` | [源码](../reference/dnsmgr/app/lib/deploy/baishan.php) |
| `ctyun` | [源码](../reference/dnsmgr/app/lib/deploy/ctyun.php) |
| `kuocai` | [源码](../reference/dnsmgr/app/lib/deploy/kuocai.php) |
| `qzyun` | [源码](../reference/dnsmgr/app/lib/deploy/qzyun.php) |
| `rainyun` | [源码](../reference/dnsmgr/app/lib/deploy/rainyun.php) |
| `unicloud` | [源码](../reference/dnsmgr/app/lib/deploy/unicloud.php) |
| `aws` | [源码](../reference/dnsmgr/app/lib/deploy/aws.php) |
| `gcore` | [源码](../reference/dnsmgr/app/lib/deploy/gcore.php) |
| `cachefly` | [源码](../reference/dnsmgr/app/lib/deploy/cachefly.php) |
| `ssh` | [源码](../reference/dnsmgr/app/lib/deploy/ssh.php) |
| `ftp` | [源码](../reference/dnsmgr/app/lib/deploy/ftp.php) |
| `s3storage` | [源码](../reference/dnsmgr/app/lib/deploy/s3storage.php) |
| `local` | [源码](../reference/dnsmgr/app/lib/deploy/local.php) |

## 源码存在但未登记的适配器

这些文件未出现在上游对应 Helper 的入口清单中，不计入上表的可调用范围。
上游同步时仍须复查它们是否已转正或应明确排除。

| 分类 | 标识 | 源码 |
| --- | --- | --- |
| `cert` | `huoshan` | [源码](../reference/dnsmgr/app/lib/cert/huoshan.php) |
