"""Flatten ingress rules and grade them."""

from __future__ import annotations

from dataclasses import dataclass

from sgaudit.collect import RegionSnapshot

OPEN = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
}
WEB_PORTS = {80, 443}

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, "": 3}


@dataclass(frozen=True)
class RuleRow:
    account_id: str
    region: str
    group_id: str
    group_name: str
    vpc_id: str
    protocol: str
    ports: str
    source: str
    description: str
    severity: str  # "" when nothing to flag
    finding: str


@dataclass(frozen=True)
class UnusedGroup:
    account_id: str
    region: str
    group_id: str
    group_name: str
    severity: str = LOW


def _port_range(perm: dict) -> tuple[int, int] | None:
    """None means every port (protocol -1, or 0-65535 for tcp/udp)."""
    if perm["IpProtocol"] == "-1":
        return None
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if perm["IpProtocol"] in ("tcp", "udp", "6", "17") and (lo, hi) == (0, 65535):
        return None
    return (lo, hi)


def _ports_text(perm: dict, rng) -> str:
    if rng is None:
        return "all"
    if perm["IpProtocol"] in ("icmp", "icmpv6", "1", "58"):
        return "n/a"
    lo, hi = rng
    return str(lo) if lo == hi else f"{lo}-{hi}"


def grade(perm: dict, source: str) -> tuple[str, str]:
    rng = _port_range(perm)
    is_open = source in OPEN
    port_based = perm["IpProtocol"] in ("tcp", "udp", "6", "17")

    if rng is None:
        if is_open:
            return HIGH, "all ports open to the internet"
        return MEDIUM, f"all ports open to {source}"
    if not is_open:
        return "", ""
    if port_based:
        lo, hi = rng
        hits = [name for port, name in SENSITIVE_PORTS.items() if lo <= port <= hi]
        if hits:
            return HIGH, f"{', '.join(sorted(hits))} open to the internet"
        if lo == hi and lo in WEB_PORTS:
            return LOW, "web port open to the internet"
    return MEDIUM, "open to the internet"


def flatten(snapshots: list[RegionSnapshot]) -> tuple[list[RuleRow], list[UnusedGroup]]:
    rows: list[RuleRow] = []
    unused: list[UnusedGroup] = []
    for snap in snapshots:
        for g in snap.groups:
            if g["GroupId"] not in snap.used_group_ids and g["GroupName"] != "default":
                unused.append(
                    UnusedGroup(snap.account_id, snap.region, g["GroupId"], g["GroupName"])
                )
            for perm in g.get("IpPermissions", []):
                rng = _port_range(perm)
                sources = (
                    [(r["CidrIp"], r.get("Description", "")) for r in perm.get("IpRanges", [])]
                    + [
                        (r["CidrIpv6"], r.get("Description", ""))
                        for r in perm.get("Ipv6Ranges", [])
                    ]
                    + [
                        (p["GroupId"], p.get("Description", ""))
                        for p in perm.get("UserIdGroupPairs", [])
                    ]
                    + [
                        (p["PrefixListId"], p.get("Description", ""))
                        for p in perm.get("PrefixListIds", [])
                    ]
                )
                for source, desc in sources:
                    severity, finding = grade(perm, source)
                    rows.append(
                        RuleRow(
                            account_id=snap.account_id,
                            region=snap.region,
                            group_id=g["GroupId"],
                            group_name=g["GroupName"],
                            vpc_id=g.get("VpcId", ""),
                            protocol="all" if perm["IpProtocol"] == "-1" else perm["IpProtocol"],
                            ports=_ports_text(perm, rng),
                            source=source,
                            description=desc,
                            severity=severity,
                            finding=finding,
                        )
                    )
    return rows, unused
