#!/usr/bin/env python3
"""Render the dnsmgr source inventory without executing the PHP application."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "reference" / "dnsmgr"
OUTPUT = ROOT / "docs" / "UPSTREAM-INVENTORY.md"
ENTRY = re.compile(r"(?m)^        '([a-z0-9_]+)' => \[")
FLAGS = ("remark", "status", "redirect", "log", "weight", "page", "add", "sort")
PUBLIC_METHOD = re.compile(r"(?m)^    public function ([A-Za-z_][A-Za-z0-9_]*)\(")
DNS_METHODS = (
    ("check", "检查"),
    ("getDomainList", "域名列表"),
    ("getDomainRecords", "记录列表"),
    ("getSubDomainRecords", "子域精查"),
    ("getDomainRecordInfo", "记录详情"),
    ("addDomainRecord", "新增记录"),
    ("updateDomainRecord", "更新记录"),
    ("updateDomainRecordRemark", "备注"),
    ("deleteDomainRecord", "删除记录"),
    ("setDomainRecordStatus", "启停"),
    ("getDomainRecordLog", "记录日志"),
    ("getRecordLine", "线路"),
    ("getMinTTL", "最小 TTL"),
    ("addDomain", "建域"),
)


def entries(config: Path, stop: str | None = None) -> list[tuple[str, str]]:
    source = config.read_text(encoding="utf-8")
    if stop is not None:
        source = source.split(stop, 1)[0]
    matches = list(ENTRY.finditer(source))
    return [
        (match.group(1), source[match.end() : matches[index + 1].start() if index + 1 < len(matches) else len(source)])
        for index, match in enumerate(matches)
    ]


def flag(body: str, name: str) -> str:
    match = re.search(rf"(?m)^            '{name}' => (true|false|[0-9]+)", body)
    return match.group(1) if match else "—"


def public_body(source: str, method: str) -> str | None:
    match = re.search(rf"public function {method}\([^)]*\)\s*\{{", source)
    if match is None:
        return None
    depth, index = 1, match.end()
    while depth and index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    return source[match.end() : index - 1].strip()


def product_options(body: str) -> list[str]:
    product = re.search(r"'product'\s*=>\s*\[(.*?)\n\s*\],", body, re.S)
    if product is None:
        return []
    return re.findall(r"\['value'\s*=>\s*'([^']+)'", product.group(1))


def render() -> str:
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=UPSTREAM, text=True).strip()
    dns = entries(UPSTREAM / "app/lib/DnsHelper.php", "public static $line_name")
    cert = entries(UPSTREAM / "app/lib/CertHelper.php")
    deploy = entries(UPSTREAM / "app/lib/DeployHelper.php")
    common_dns = set(re.findall(r"\bfunction ([A-Za-z_][A-Za-z0-9_]*)\(", (UPSTREAM / "app/lib/DnsInterface.php").read_text(encoding="utf-8")))
    expected = {"dns": 22, "cert": 8, "deploy": 50}
    actual = {"dns": len(dns), "cert": len(cert), "deploy": len(deploy)}
    if actual != expected:
        raise SystemExit(f"Upstream inventory changed: {actual}; review parser and README counts")

    lines = [
        "# 彩虹 DNS 上游源码盘点",
        "",
        "本文记录参考子模块中可定位的源码入口、公共方法与静态配置标记，供 DnsGo 实现与上游更新对照。",
        "不代表 Go 功能已实现，也不证明厂商 API 当前可用。新增厂商或改变能力时，先核对上游源码，",
        "再重跑 `python3 scripts/upstream_inventory.py`；Go 实现与真实验证状态另行记录。",
        "",
        f"上游提交：`{sha}`。DNS 适配器 {len(dns)} 个，证书服务 {len(cert)} 类，证书部署目标 {len(deploy)} 类。",
        "",
        "## DNS 适配器",
        "",
        "下表标记来自上游 `DnsHelper::$dns_config`。数字和布尔值保留原文；`—` 表示未找到静态标记。",
        "标记本身不等于该方法已经实测。",
        "",
        "| 标识 | 源码 | remark | status | redirect | log | weight | page | add | sort | 额外公开方法 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, body in dns:
        path = UPSTREAM / "app/lib/dns" / f"{name}.php"
        if not path.is_file():
            raise SystemExit(f"Missing DNS adapter: {path}")
        values = " | ".join(flag(body, key) for key in FLAGS)
        methods = PUBLIC_METHOD.findall(path.read_text(encoding="utf-8"))
        extra = sorted(set(methods) - common_dns - {"__construct"})
        extensions = ", ".join(f"`{method}`" for method in extra) if extra else "—"
        lines.append(f"| `{name}` | [源码](../reference/dnsmgr/app/lib/dns/{name}.php) | {values} | {extensions} |")

    lines += [
        "",
        "## 公共 DNS 方法矩阵",
        "",
        "下表逐个读取 `DnsInterface.php` 所列方法在每家 PHP 适配器中的方法体。`✓` 表示存在非空、非单纯 `return false` 的入口；`—` 表示未实现或明确返回不支持。",
        "`getError` 在 Go 中由方法返回的错误值与 `dnsgo.Error` 代替，不作为独立状态方法。",
        "该矩阵不核对方法内部所有分支，更不证明 Go 实现或厂商 API 可用；方法签名和参数以接口源码为准。",
        "",
        "| 标识 | " + " | ".join(label for _, label in DNS_METHODS) + " |",
        "| --- | " + " | ".join("---" for _ in DNS_METHODS) + " |",
    ]
    for name, _ in dns:
        source = (UPSTREAM / "app/lib/dns" / f"{name}.php").read_text(encoding="utf-8")
        flags = []
        for method, _ in DNS_METHODS:
            body = public_body(source, method)
            flags.append("✓" if body is not None and body not in ("", "return false;", "return null;") else "—")
        lines.append(f"| `{name}` | " + " | ".join(flags) + " |")

    lines += ["", "## 证书服务静态限制", "", "数值来自 `CertHelper::$cert_config`；具体下单费用与服务端可用性须另行核对。", "",
              "| 标识 | 类别 | 通配符 | 最多域名 | CNAME 验证 |", "| --- | --- | --- | --- | --- |"]
    for name, body in cert:
        values = " | ".join(flag(body, key) for key in ("class", "wildcard", "max_domains", "cname"))
        lines.append(f"| `{name}` | {values} |")

    lines += ["", "## 部署目标产品选项", "", "只列 `DeployHelper` 中显式的 `product` 选项；`—` 表示没有产品分支参数。", "",
              "| 标识 | 产品选项 |", "| --- | --- |"]
    for name, body in deploy:
        options = product_options(body)
        lines.append(f"| `{name}` | " + (", ".join(f"`{option}`" for option in options) if options else "—") + " |")

    for title, group, directory in (
        ("证书服务", cert, "cert"),
        ("证书部署目标", deploy, "deploy"),
    ):
        lines += ["", f"## {title}", "", "| 标识 | 源码 |", "| --- | --- |"]
        for name, _ in group:
            path = UPSTREAM / "app/lib" / directory / f"{name}.php"
            if not path.is_file():
                raise SystemExit(f"Missing {title} adapter: {path}")
            lines.append(f"| `{name}` | [源码](../reference/dnsmgr/app/lib/{directory}/{name}.php) |")
    orphaned: list[tuple[str, str]] = []
    for directory, group in (("dns", dns), ("cert", cert), ("deploy", deploy)):
        registered = {name for name, _ in group}
        for path in sorted((UPSTREAM / "app/lib" / directory).glob("*.php")):
            if path.stem not in registered:
                orphaned.append((directory, path.stem))
    lines += ["", "## 源码存在但未登记的适配器", "",
              "这些文件未出现在上游对应 Helper 的入口清单中，不计入上表的可调用范围。",
              "上游同步时仍须复查它们是否已转正或应明确排除。", "",
              "| 分类 | 标识 | 源码 |", "| --- | --- | --- |"]
    for directory, name in orphaned:
        lines.append(f"| `{directory}` | `{name}` | [源码](../reference/dnsmgr/app/lib/{directory}/{name}.php) |")
    if not orphaned:
        lines.append("| — | — | — |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the generated inventory differs")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit("Inventory is stale; run python3 scripts/upstream_inventory.py")
        print("Upstream inventory is current")
        return
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
