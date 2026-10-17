#!/usr/bin/env python3
"""Inventory literal configuration keys accepted by registered Go adapters."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from upstream_inventory import ROOT, UPSTREAM, entries


OUTPUT = ROOT / "docs" / "CONFIG-KEYS.md"
PROVIDER_KEY = re.compile(r'(?:config|c\.config)\.Credentials\s*\[\s*"([^"]+)"\s*\]')
DEPLOY_KEY = re.compile(r'(?:config\.Values|\bvalues|t\.values|t\.config)\s*\[\s*"([^"]+)"\s*\]')


def render() -> str:
    dns = entries(UPSTREAM / "app/lib/DnsHelper.php", "public static $line_name")
    deploy = entries(UPSTREAM / "app/lib/DeployHelper.php")
    lines = [
        "# 配置字段索引",
        "",
        "本文件由 `scripts/config_keys.py` 从 Go 源码中的字面量字段生成，供 Go 项目及常驻程序配置时查找键名。",
        "表中字段是适配器读取过的键，并不表示每个键在所有模式下都必填；具体必填组合由对应构造函数校验。",
        "通用的 DNS 配置还包含 `dnsgo.Config.Domain`、`DomainID` 和 `Endpoint`；部署配置还包含 `deploy.Config.Endpoint`。",
        "不要把真实凭据写入配置示例或仓库。上游入口、实现状态和验证等级分别见",
        "[上游盘点](UPSTREAM-INVENTORY.md)、[实施状态](IMPLEMENTATION.md)与[适配器验证记录](ADAPTER-COVERAGE.md)。",
        "",
        "## DNS 厂商凭据键",
        "",
        "| 厂商 | `Config.Credentials` 中读取的键 | Go 源码 |",
        "| --- | --- | --- |",
    ]
    for name, _ in dns:
        path = ROOT / "providers" / f"{name}.go"
        keys = sorted(set(PROVIDER_KEY.findall(path.read_text(encoding="utf-8"))))
        rendered = ", ".join(f"`{key}`" for key in keys) if keys else "—"
        lines.append(f"| `{name}` | {rendered} | [源码](../providers/{name}.go) |")
    lines += [
        "",
        "AWS DNS 适配器也可使用 AWS SDK 的默认凭据链；Cloudflare 的 `auth=0` 使用全局密钥时还需 `email`。",
        "",
        "## 证书部署目标配置键",
        "",
        "| 目标 | `deploy.Config.Values` 中读取的键 | Go 源码 |",
        "| --- | --- | --- |",
    ]
    for name, _ in deploy:
        stem = {"btwin": "btpanel", "kangleadmin": "kangle", "ratpanel": "acepanel"}.get(name, name)
        paths = sorted((ROOT / "deploy").glob(f"{stem}*.go"))
        if not paths:
            raise SystemExit(f"No Go source for deployment target {name}")
        source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        keys = sorted(set(DEPLOY_KEY.findall(source)))
        rendered = ", ".join(f"`{key}`" for key in keys) if keys else "—"
        path = paths[0].relative_to(ROOT)
        lines.append(f"| `{name}` | {rendered} | [源码](../{path.as_posix()}) |")
    lines += [
        "",
        "## 续写规则",
        "",
        "- 修改适配器配置键后重跑 `python3 scripts/config_keys.py`，再核对构造函数中的必填和模式条件。",
        "- 本表不放真实密钥、默认密码或带令牌的 URL；字段含义和完整示例放在 SDK 与常驻程序指南中。",
        "- 字面量扫描无法发现动态生成的键或推断条件必填；若增加此类配置，应在对应指南中显式说明。",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when generated output is stale")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit("Config key inventory is stale; run python3 scripts/config_keys.py")
        print("Config key inventory is current")
        return
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
