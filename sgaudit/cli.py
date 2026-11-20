"""python -m sgaudit --account 123456789012 --region eu-west-2 --role-name SecurityAudit"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sgaudit.accounts import AssumeRoleFactory
from sgaudit.collect import collect
from sgaudit.report import to_csv, to_markdown
from sgaudit.rules import HIGH, flatten

EXIT_ERROR = 1
EXIT_HIGH_FINDINGS = 2


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Read-only security group audit across accounts.")
    p.add_argument("--account", action="append", required=True, dest="accounts")
    p.add_argument("--region", action="append", required=True, dest="regions")
    p.add_argument("--role-name", default="SecurityGroupAudit", help="role to assume per account")
    p.add_argument("--markdown", type=Path, default=Path("sg-audit.md"))
    p.add_argument("--csv", type=Path, default=Path("sg-audit.csv"))
    p.add_argument("--fail-on-high", action="store_true", help="exit 2 if any HIGH finding")
    return p.parse_args(argv)


def main(argv=None, factory=None) -> int:
    args = parse_args(argv)
    try:
        if factory is None:
            import boto3

            factory = AssumeRoleFactory(boto3.client("sts"), args.role_name)
        snapshots = collect(factory, args.accounts, args.regions)
        rows, unused = flatten(snapshots)
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    args.markdown.write_text(
        to_markdown(
            rows, unused, args.accounts, args.regions, sum(len(s.groups) for s in snapshots)
        ),
        encoding="utf-8",
    )
    args.csv.write_text(to_csv(rows), encoding="utf-8")
    high = sum(1 for r in rows if r.severity == HIGH)
    print(f"{len(rows)} rules, {high} HIGH. Wrote {args.markdown} and {args.csv}.")
    if args.fail_on_high and high:
        return EXIT_HIGH_FINDINGS
    return 0
