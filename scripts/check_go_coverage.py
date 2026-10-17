#!/usr/bin/env python3
"""Check that every configured upstream adapter has a Go registration entry.

This is a static name gate. It does not validate request behavior or live APIs.
"""

from __future__ import annotations

import re
from pathlib import Path

from upstream_inventory import ROOT, UPSTREAM, entries


COMMON_METHODS = {
    "check": "Check",
    "getDomainList": "ListZones",
    "getDomainRecords": "ListRecords",
    "getDomainRecordInfo": "GetRecord",
    "addDomainRecord": "CreateRecord",
    "updateDomainRecord": "UpdateRecord",
    "updateDomainRecordRemark": "SetRecordRemark",
    "deleteDomainRecord": "DeleteRecord",
    "setDomainRecordStatus": "SetRecordStatus",
    "getDomainRecordLog": "ListRecordLogs",
    "getRecordLine": "RecordLines",
    "getMinTTL": "MinTTL",
    "addDomain": "CreateZone",
}


def check_subdomain_listing(names: set[str]) -> bool:
    missing = []
    for name in sorted(names):
        source = (UPSTREAM / "app/lib/dns" / f"{name}.php").read_text(encoding="utf-8")
        body = php_body(source, "getSubDomainRecords")
        if body is None or body in ("return false;", "return null;"):
            missing.append(name)
    helper = (ROOT / "dns.go").read_text(encoding="utf-8")
    if missing or "func ListSubdomainRecords(" not in helper:
        print("exact subdomain listing is missing:", ", ".join(missing) if missing else "Go helper")
        return False
    print("DNS subdomain listing has a shared exact-match Go entry point")
    return True


def php_body(source: str, method: str) -> str | None:
    match = re.search(rf"public function {method}\([^)]*\)\s*\{{", source)
    if match is None:
        return None
    depth = 1
    index = match.end()
    while depth and index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    return source[match.end() : index - 1].strip()


def go_body(source: str, method: str) -> str | None:
    match = re.search(rf"func \([^)]+\) {method}\([^)]*\)[^{{]*\{{", source)
    if match is None:
        return None
    depth = 1
    index = match.end()
    while depth and index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    return source[match.end() : index - 1].strip()


def check_common_methods(names: set[str]) -> bool:
    missing: list[str] = []
    for name in sorted(names):
        upstream = (UPSTREAM / "app/lib/dns" / f"{name}.php").read_text(encoding="utf-8")
        adapter = (ROOT / "providers" / f"{name}.go").read_text(encoding="utf-8")
        for php_name, go_name in COMMON_METHODS.items():
            if name == "qingcloud" and php_name == "updateDomainRecordRemark":
                go_name = "SetHostRemark"  # source method writes a host-level description
            body = php_body(upstream, php_name)
            if body is None or body in ("return false;", "return null;"):
                continue
            implementation = go_body(adapter, go_name)
            if implementation is None or re.fullmatch(
                r"return (?:[^\n]+,\s*)?dnsgo\.Unsupported\([^\n]+\)", implementation
            ):
                missing.append(f"{name}:{php_name}->{go_name}")
    if missing:
        print("DNS nontrivial common methods missing:", ", ".join(missing))
        return False
    print("DNS nontrivial common methods have non-stub Go entry points")
    return True


def check_product_names(deploy: list[tuple[str, str]]) -> bool:
    missing: list[str] = []
    checked = 0
    for name, body in deploy:
        product = re.search(r"'product'\s*=>\s*\[(.*?)\n\s*\],", body, re.S)
        if product is None:
            continue
        options = re.findall(r"\['value'\s*=>\s*'([^']+)'", product.group(1))
        source = "\n".join(
            path.read_text(encoding="utf-8") for path in (ROOT / "deploy").glob(f"{name}*.go")
        )
        for option in options:
            checked += 1
            if f'"{option}"' not in source:
                missing.append(f"{name}:{option}")
    if missing:
        print("deployment product names absent from Go source:", ", ".join(missing))
        return False
    print(f"deployment product name references: {checked} upstream options present in Go source")
    return True


def check_product_branches(deploy: list[tuple[str, str]]) -> bool:
    missing: list[str] = []
    checked = 0
    for name, body in deploy:
        product = re.search(r"'product'\s*=>\s*\[(.*?)\n\s*\],", body, re.S)
        if product is None:
            continue
        options = re.findall(r"\['value'\s*=>\s*'([^']+)'", product.group(1))
        source = "\n".join(
            path.read_text(encoding="utf-8") for path in (ROOT / "deploy").glob(f"{name}*.go")
        )
        for option in options:
            checked += 1
            if len(options) == 1 and '"product"' not in source:
                continue  # this target is dedicated to its one upstream product
            branch = re.search(
                rf'case\s+[^\n]*"{re.escape(option)}"|(?:t\.product|product)\s*[!=]=\s*"{re.escape(option)}"',
                source,
            )
            if branch is None:
                missing.append(f"{name}:{option}")
    if missing:
        print("deployment product options without Go branches:", ", ".join(missing))
        return False
    print(f"deployment product branches: {checked} upstream options have Go dispatch paths")
    return True


def check_certificate_methods() -> bool:
    missing: list[str] = []
    common = ("CheckAccount", "Start", "Challenges", "SubmitValidation", "Status", "Download", "Revoke", "Cancel")
    for name in ("tencent", "aliyun", "ucloud"):
        source = (ROOT / "cert" / f"{name}.go").read_text(encoding="utf-8")
        for method in common:
            if go_body(source, method) is None:
                missing.append(f"{name}:{method}")
    acme = (ROOT / "cert/acme.go").read_text(encoding="utf-8")
    for method in ("Issue", "Renew", "Revoke"):
        if go_body(acme, method) is None:
            missing.append(f"acme:{method}")
    if missing:
        print("certificate workflow methods missing:", ", ".join(missing))
        return False
    print("certificate workflow methods: five ACME authorities and three cloud issuers have Go entry points")
    return True


def check_deploy_actions(deploy: list[tuple[str, str]]) -> bool:
    missing: list[str] = []
    checked = 0
    verbs = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    for name, _ in deploy:
        source = (UPSTREAM / "app/lib/deploy" / f"{name}.php").read_text(encoding="utf-8")
        actions = set(re.findall(r"['\"]Action['\"]\s*=>\s*['\"]([A-Z][A-Za-z0-9]+)['\"]", source))
        actions.update(re.findall(r"->request\(\s*['\"]([A-Z][A-Za-z0-9]+)['\"]", source))
        actions -= verbs
        implemented = "\n".join(
            path.read_text(encoding="utf-8") for path in (ROOT / "deploy").glob(f"{name}*.go")
        )
        for action in actions:
            checked += 1
            if f'"{action}"' not in implemented:
                missing.append(f"{name}:{action}")
    if missing:
        print("deployment API action references absent from Go source:", ", ".join(sorted(missing)))
        return False
    print(f"deployment API action references: {checked} upstream names present in Go source")
    return True


def registrations(directory: Path) -> set[str]:
    names: set[str] = set()
    for path in directory.glob("*.go"):
        source = path.read_text(encoding="utf-8")
        names.update(re.findall(r'\bregister\("([a-z0-9_]+)"\s*,', source))
        for group in re.findall(
            r'for _, name := range \[\]string\{([^}]*)\}\s*\{\s*kind := name\s*register\(kind\s*,',
            source,
        ):
            names.update(re.findall(r'"([a-z0-9_]+)"', group))
    return names


def check(label: str, expected: set[str], actual: set[str]) -> bool:
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        print(f"{label}: missing={missing}, extra={extra}")
        return False
    print(f"{label}: {len(actual)} registered names match upstream")
    return True


def main() -> None:
    dns = {name for name, _ in entries(UPSTREAM / "app/lib/DnsHelper.php", "public static $line_name")}
    deploy_entries = entries(UPSTREAM / "app/lib/DeployHelper.php")
    deploy = {name for name, _ in deploy_entries}
    cert = {name for name, _ in entries(UPSTREAM / "app/lib/CertHelper.php")}
    acme = set(re.findall(r'Authority = "([a-z0-9_]+)"', (ROOT / "cert/acme.go").read_text(encoding="utf-8")))
    cloud = set()
    for name in ("tencent", "aliyun", "ucloud"):
        source = (ROOT / "cert" / f"{name}.go").read_text(encoding="utf-8")
        if re.search(rf'func \([^)]+\) Kind\(\) string \{{ return "{name}" \}}', source):
            cloud.add(name)
    results = [
        check("DNS", dns, registrations(ROOT / "providers")),
        check("certificate", cert, acme | cloud),
        check("deployment", deploy, registrations(ROOT / "deploy")),
        check_common_methods(dns),
        check_subdomain_listing(dns),
        check_certificate_methods(),
        check_product_names(deploy_entries),
        check_product_branches(deploy_entries),
        check_deploy_actions(deploy_entries),
    ]
    if not all(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
