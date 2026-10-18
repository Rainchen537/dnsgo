#!/usr/bin/env python3
"""Require related Wiki updates alongside implementation and workflow changes."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATUS = "docs/IMPLEMENTATION.md"
RULES = (
    ("DNS 与公共 API", ("providers/",), ("docs/SDK.md", "docs/DNS-OPERATIONS.md", "docs/TROUBLESHOOTING.md", "docs/ADAPTER-COVERAGE.md", STATUS)),
    ("证书与部署", ("cert/", "deploy/"), ("docs/CERTIFICATES.md", "docs/SDK.md", "docs/ADAPTER-COVERAGE.md", STATUS)),
    ("自动化与通知", ("automation/", "notify/"), ("docs/AUTOMATION.md", "docs/AGENT.md", STATUS)),
    ("常驻程序", ("agent/", "cmd/"), ("docs/AGENT.md", STATUS)),
    ("接入示例", ("examples/",), ("docs/QUICKSTART.md", "docs/SDK.md", STATUS)),
    ("内部实现", ("internal/",), ("docs/SDK.md", "docs/CERTIFICATES.md", "docs/AUTOMATION.md", "docs/AGENT.md", STATUS)),
    ("工作流与维护脚本", (".github/workflows/", "scripts/"), ("docs/CONTRIBUTING.md", "docs/WIKI.md", "docs/CONFIG-KEYS.md", "docs/UPSTREAM-INVENTORY.md")),
)


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=ROOT)


def missing_updates(changed: set[str], deleted: set[str] | None = None) -> list[str]:
    documentation = changed - (deleted or set())
    implementation = {path for path in changed if not path.endswith("_test.go")}
    missing = []
    for label, prefixes, articles in RULES:
        affected = {path for path in implementation if path.startswith(prefixes)}
        if label == "DNS 与公共 API":
            affected.update(path for path in implementation if "/" not in path and path.endswith(".go"))
        if label == "接入示例":
            affected = {path for path in affected if path.endswith(".go")}
            affected.update(implementation & {"go.mod", "go.sum"})
        if label == "常驻程序" and "examples/agent.example.yaml" in implementation:
            affected.add("examples/agent.example.yaml")
        if affected and not documentation.intersection(articles):
            missing.append(f"{label}: {', '.join(sorted(affected))}\n  请同步至少一篇: {', '.join(articles)}")
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="HEAD")
    parser.add_argument("--head")
    args = parser.parse_args()
    base = args.base
    if not base or set(base) == {"0"}:
        base = subprocess.check_output(["git", "hash-object", "-t", "tree", "--stdin"], input=b"", cwd=ROOT).decode().strip()
    revisions = [base, args.head] if args.head else [base]
    changed = set(git("diff", "--name-only", "-z", *revisions, "--").decode().split("\0")) - {""}
    deleted = set(git("diff", "--name-only", "--diff-filter=D", "-z", *revisions, "--").decode().split("\0")) - {""}
    if not args.head:
        changed.update(set(git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")) - {""})
    failures = missing_updates(changed, deleted)
    if failures:
        print("Wiki 同步检查失败:\n" + "\n".join(failures))
        return 1
    print(f"Wiki 同步检查通过，核对 {len(changed)} 个变更文件")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
