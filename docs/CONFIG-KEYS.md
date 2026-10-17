# 配置字段索引

本文件由 `scripts/config_keys.py` 从 Go 源码中的字面量字段生成，供 Go 项目及常驻程序配置时查找键名。
表中字段是适配器读取过的键，并不表示每个键在所有模式下都必填；具体必填组合由对应构造函数校验。
通用的 DNS 配置还包含 `dnsgo.Config.Domain`、`DomainID` 和 `Endpoint`；部署配置还包含 `deploy.Config.Endpoint`。
不要把真实凭据写入配置示例或仓库。上游入口、实现状态和验证等级分别见
[上游盘点](UPSTREAM-INVENTORY.md)、[实施状态](IMPLEMENTATION.md)与[适配器验证记录](ADAPTER-COVERAGE.md)。

## DNS 厂商凭据键

| 厂商 | `Config.Credentials` 中读取的键 | Go 源码 |
| --- | --- | --- |
| `aliyun` | `AccessKeyId`, `AccessKeySecret`, `access_key_id`, `access_key_secret` | [源码](../providers/aliyun.go) |
| `dnspod` | `SecretId`, `SecretKey`, `secret_id`, `secret_key` | [源码](../providers/dnspod.go) |
| `huawei` | `AccessKeyId`, `SecretAccessKey`, `access_key_id`, `secret_access_key` | [源码](../providers/huawei.go) |
| `baidu` | `AccessKeyId`, `SecretAccessKey`, `access_key_id`, `secret_access_key` | [源码](../providers/baidu.go) |
| `west` | `api_password`, `username` | [源码](../providers/west.go) |
| `huoshan` | `AccessKeyId`, `SecretAccessKey`, `access_key_id`, `secret_access_key` | [源码](../providers/huoshan.go) |
| `jdcloud` | `AccessKeyId`, `AccessKeySecret`, `access_key_id`, `access_key_secret` | [源码](../providers/jdcloud.go) |
| `dnsla` | `apiid`, `apisecret` | [源码](../providers/dnsla.go) |
| `qingcloud` | `access_key_id`, `secret_access_key` | [源码](../providers/qingcloud.go) |
| `bt` | `AccessKey`, `AccountID`, `SecretKey` | [源码](../providers/bt.go) |
| `cloudflare` | `account_id`, `apikey`, `auth`, `email`, `token` | [源码](../providers/cloudflare.go) |
| `aws` | `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `access_key_id`, `secret_access_key` | [源码](../providers/aws.go) |
| `namesilo` | `apikey` | [源码](../providers/namesilo.go) |
| `henet` | `password`, `username` | [源码](../providers/henet.go) |
| `spaceship` | `apikey`, `apisecret` | [源码](../providers/spaceship.go) |
| `powerdns` | `api_key`, `apikey`, `ip`, `port`, `server_id` | [源码](../providers/powerdns.go) |
| `technitium` | `token`, `url` | [源码](../providers/technitium.go) |
| `aliyunesa` | `AccessKeyId`, `AccessKeySecret`, `access_key_id`, `access_key_secret`, `region` | [源码](../providers/aliyunesa.go) |
| `tencenteo` | `SecretId`, `SecretKey`, `secret_id`, `secret_key`, `site_type` | [源码](../providers/tencenteo.go) |
| `dnsmgr` | `base_url`, `key`, `uid` | [源码](../providers/dnsmgr.go) |
| `goedge` | `accessKey`, `accessKeyId`, `base_url`, `nsClusterId`, `type`, `userId`, `usertype` | [源码](../providers/goedge.go) |
| `dynv6` | `token` | [源码](../providers/dynv6.go) |

AWS DNS 适配器也可使用 AWS SDK 的默认凭据链；Cloudflare 的 `auth=0` 使用全局密钥时还需 `email`。

## 证书部署目标配置键

| 目标 | `deploy.Config.Values` 中读取的键 | Go 源码 |
| --- | --- | --- |
| `btpanel` | `is_iis`, `key`, `sites`, `type`, `url` | [源码](../deploy/btpanel.go) |
| `btwin` | `is_iis`, `key`, `sites`, `type`, `url` | [源码](../deploy/btpanel.go) |
| `kangle` | `auth`, `domains`, `name`, `password`, `path`, `skey`, `type`, `url`, `username` | [源码](../deploy/kangle.go) |
| `kangleadmin` | `auth`, `domains`, `name`, `password`, `path`, `skey`, `type`, `url`, `username` | [源码](../deploy/kangle.go) |
| `safeline` | `domainList`, `token`, `url` | [源码](../deploy/safeline.go) |
| `btwaf` | `key`, `sites`, `type`, `url` | [源码](../deploy/btwaf.go) |
| `cdnfly` | `api_key`, `api_secret`, `auth`, `id`, `password`, `url`, `username` | [源码](../deploy/cdnfly.go) |
| `lecdn` | `api_key`, `auth`, `email`, `id`, `password`, `url` | [源码](../deploy/lecdn.go) |
| `goedge` | `accessKey`, `accessKeyId`, `domainList`, `systype`, `url`, `usertype` | [源码](../deploy/goedge.go) |
| `uusec` | `id`, `name`, `password`, `url`, `username` | [源码](../deploy/uusec.go) |
| `opanel` | `domainList`, `id`, `key`, `node_name`, `type`, `url`, `version` | [源码](../deploy/opanel.go) |
| `mwpanel` | `appid`, `appsecret`, `sites`, `type`, `url` | [源码](../deploy/mwpanel.go) |
| `acepanel` | `id`, `sites`, `token`, `type`, `url` | [源码](../deploy/acepanel.go) |
| `ratpanel` | `id`, `sites`, `token`, `type`, `url` | [源码](../deploy/acepanel.go) |
| `xp` | `apikey`, `sites`, `url` | [源码](../deploy/xp.go) |
| `amh` | `apikey`, `env_name`, `url`, `vhost_name` | [源码](../deploy/amh.go) |
| `cloudpanel` | `password`, `sites`, `url`, `username` | [源码](../deploy/cloudpanel.go) |
| `directadmin` | `domain`, `password`, `url`, `username` | [源码](../deploy/directadmin.go) |
| `synology` | `desc`, `password`, `url`, `username`, `version` | [源码](../deploy/synology.go) |
| `lucky` | `domainList`, `opentoken`, `path`, `url` | [源码](../deploy/lucky.go) |
| `fnos` | `domainList`, `host`, `host_public_key`, `insecure_skip_host_key`, `known_hosts_file`, `password`, `port`, `username` | [源码](../deploy/fnos.go) |
| `nginxproxymanager` | `domainList`, `email`, `host_id`, `id`, `password`, `url` | [源码](../deploy/nginxproxymanager.go) |
| `proxmox` | `api_key`, `api_user`, `node`, `url` | [源码](../deploy/proxmox.go) |
| `k8s` | `ingresses`, `kubeconfig`, `namespace`, `secret_name` | [源码](../deploy/k8s.go) |
| `aliyun` | `AccessKeyId`, `AccessKeySecret`, `api_groupid`, `clb_domain`, `clb_id`, `clb_port`, `cleanup_expired`, `deploy_type`, `domain`, `domainList`, `esa_saas_sitename`, `esa_sitename`, `fc_cname`, `ga_id`, `ga_listener_id`, `oss_bucket`, `oss_endpoint`, `product`, `region`, `regionid`, `replace_oldest_on_quota`, `waf_resource_id` | [源码](../deploy/aliyun.go) |
| `tencent` | `SecretId`, `SecretKey`, `cert_id`, `clb_domain`, `clb_id`, `clb_listener_id`, `cos_bucket`, `delete_old_cert`, `domain`, `lighthouse_id`, `product`, `region`, `regionid`, `site_id`, `site_type`, `tke_cluster_id`, `tke_namespace`, `tke_secret` | [源码](../deploy/tencent.go) |
| `huawei` | `AccessKeyId`, `SecretAccessKey`, `cert_id`, `domain`, `obs_bucket`, `obs_endpoint`, `product`, `project_id`, `region_id` | [源码](../deploy/huawei.go) |
| `ucloud` | `PrivateKey`, `PublicKey`, `domain_id` | [源码](../deploy/ucloud.go) |
| `qiniu` | `AccessKey`, `SecretKey`, `cleanup_expired`, `domain`, `pili_hub`, `product` | [源码](../deploy/qiniu.go) |
| `doge` | `AccessKey`, `SecretKey`, `cleanup_expired`, `domain` | [源码](../deploy/doge.go) |
| `axisnow` | `token`, `uuid` | [源码](../deploy/axisnow.go) |
| `upyun` | `password`, `username` | [源码](../deploy/upyun.go) |
| `baidu` | `AccessKeyId`, `SecretAccessKey`, `blb_id`, `blb_port`, `domain`, `product`, `region` | [源码](../deploy/baidu.go) |
| `ksyun` | `AccessKeyId`, `SecretAccessKey`, `domain` | [源码](../deploy/ksyun.go) |
| `huoshan` | `AccessKeyId`, `SecretAccessKey`, `bucket_domain`, `domain`, `listener_id`, `product`, `project_name`, `vod_domain_type`, `vod_space_name` | [源码](../deploy/huoshan.go) |
| `west` | `api_password`, `domainList`, `sitename`, `username` | [源码](../deploy/west.go) |
| `wangsu` | `apiKey`, `cert_id`, `domain`, `domains`, `product`, `spKey`, `username` | [源码](../deploy/wangsu.go) |
| `baishan` | `id`, `token` | [源码](../deploy/baishan.go) |
| `ctyun` | `AccessKeyId`, `SecretAccessKey`, `domain`, `product`, `region_id` | [源码](../deploy/ctyun.go) |
| `kuocai` | `id`, `password`, `username` | [源码](../deploy/kuocai.go) |
| `qzyun` | `certificate`, `domain`, `email`, `password` | [源码](../deploy/qzyun.go) |
| `rainyun` | `apikey`, `id` | [源码](../deploy/rainyun.go) |
| `unicloud` | `domains`, `password`, `provider`, `spaceId`, `username` | [源码](../deploy/unicloud.go) |
| `aws` | `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `acm_arn`, `cert_id`, `distribution_id`, `product` | [源码](../deploy/aws.go) |
| `gcore` | `apikey`, `id`, `name` | [源码](../deploy/gcore.go) |
| `cachefly` | `apikey` | [源码](../deploy/cachefly.go) |
| `ssh` | `allow_commands`, `auth`, `cmd`, `cmd_pre`, `format`, `host`, `host_public_key`, `iis_domain`, `insecure_skip_host_key`, `known_hosts_file`, `passphrase`, `password`, `pem_cert_file`, `pem_key_file`, `pfx_file`, `pfx_pass`, `port`, `privatekey`, `username`, `windows` | [源码](../deploy/ssh.go) |
| `ftp` | `format`, `host`, `insecure_skip_verify`, `password`, `pem_cert_file`, `pem_key_file`, `pfx_file`, `pfx_pass`, `port`, `secure`, `username` | [源码](../deploy/ftp.go) |
| `s3storage` | `AccessKeyId`, `SecretAccessKey`, `bucket`, `cert_path`, `endpoint`, `key_path`, `region` | [源码](../deploy/s3storage.go) |
| `local` | `allow_commands`, `cmd`, `format`, `pem_cert_file`, `pem_key_file`, `pfx_file`, `pfx_pass` | [源码](../deploy/local.go) |

## 续写规则

- 修改适配器配置键后重跑 `python3 scripts/config_keys.py`，再核对构造函数中的必填和模式条件。
- 本表不放真实密钥、默认密码或带令牌的 URL；字段含义和完整示例放在 SDK 与常驻程序指南中。
- 字面量扫描无法发现动态生成的键或推断条件必填；若增加此类配置，应在对应指南中显式说明。
