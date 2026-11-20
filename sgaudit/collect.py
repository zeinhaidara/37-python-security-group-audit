"""Read security groups and the ENIs that use them. Read-only, paged."""

from __future__ import annotations

from dataclasses import dataclass

from sgaudit.accounts import ClientFactory


class AccountError(RuntimeError):
    """One account or region failed. The message names it."""


@dataclass
class RegionSnapshot:
    account_id: str
    region: str
    groups: list[dict]
    used_group_ids: set[str]


def _paged(call, key: str) -> list[dict]:
    items, kwargs = [], {}
    while True:
        page = call(**kwargs)
        items.extend(page.get(key, []))
        token = page.get("NextToken")
        if not token:
            return items
        kwargs["NextToken"] = token


def collect(
    factory: ClientFactory, accounts: list[str], regions: list[str]
) -> list[RegionSnapshot]:
    snapshots = []
    for account_id in accounts:
        for region in regions:
            try:
                ec2 = factory.ec2_client(account_id, region)
                groups = _paged(ec2.describe_security_groups, "SecurityGroups")
                enis = _paged(ec2.describe_network_interfaces, "NetworkInterfaces")
            except Exception as exc:
                # Stop the whole run: a report missing an account looks clean when it isn't.
                raise AccountError(f"account {account_id} region {region}: {exc}") from exc
            used = {g["GroupId"] for eni in enis for g in eni.get("Groups", [])}
            snapshots.append(RegionSnapshot(account_id, region, groups, used))
    return snapshots
