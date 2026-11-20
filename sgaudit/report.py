"""Markdown summary of findings and a CSV of every ingress rule."""

from __future__ import annotations

import csv
import io
from dataclasses import asdict, fields

from sgaudit.rules import HIGH, LOW, MEDIUM, SEVERITY_ORDER, RuleRow, UnusedGroup


def to_csv(rows: list[RuleRow]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[f.name for f in fields(RuleRow)], lineterminator="\n")
    writer.writeheader()
    for r in _sorted(rows):
        writer.writerow(asdict(r))
    return buf.getvalue()


def _sorted(rows):
    return sorted(
        rows,
        key=lambda r: (SEVERITY_ORDER[r.severity], r.account_id, r.region, r.group_id, r.source),
    )


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def to_markdown(
    rows: list[RuleRow],
    unused: list[UnusedGroup],
    accounts: list[str],
    regions: list[str],
    group_count: int,
) -> str:
    findings = [r for r in rows if r.severity]
    count = {s: sum(1 for r in findings if r.severity == s) for s in (HIGH, MEDIUM, LOW)}
    count[LOW] += len(unused)

    lines = [
        "# Security group audit",
        "",
        f"Accounts: {', '.join(accounts)}. Regions: {', '.join(regions)}.",
        "",
        "## Summary",
        "",
        f"- Security groups reviewed: {group_count}. Ingress rules reviewed: {len(rows)}.",
        f"- HIGH: {count[HIGH]}, MEDIUM: {count[MEDIUM]}, LOW: {count[LOW]} "
        f"(LOW includes {len(unused)} unused group(s)).",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += [
            "| Severity | Account | Region | Group | Protocol | Ports | Source | Finding |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for r in _sorted(findings):
            lines.append(
                f"| {r.severity} | {r.account_id} | {r.region} | {r.group_id} "
                f"({_cell(r.group_name)}) | {r.protocol} | {r.ports} | {r.source} | {r.finding} |"
            )
    else:
        lines.append("No permissive ingress rules found.")

    lines += ["", "## Unused groups (not attached to any network interface)", ""]
    if unused:
        lines += ["| Account | Region | Group |", "|---|---|---|"]
        for u in sorted(unused, key=lambda u: (u.account_id, u.region, u.group_id)):
            lines.append(f"| {u.account_id} | {u.region} | {u.group_id} ({_cell(u.group_name)}) |")
    else:
        lines.append("None.")
    lines += ["", "Every ingress rule is listed in the CSV output. Nothing was changed."]
    return "\n".join(lines) + "\n"
