"""Hand-written fakes for EC2 (describe calls only), STS and the client factory."""

from __future__ import annotations

from botocore.exceptions import ClientError


def sg(group_id, name="app", rules=(), vpc="vpc-0aaaaaaaaaaaaaaa1"):
    return {"GroupId": group_id, "GroupName": name, "VpcId": vpc, "IpPermissions": list(rules)}


def rule(proto="tcp", lo=None, hi=None, cidrs=(), cidrs6=(), groups=()):
    perm = {
        "IpProtocol": proto,
        "IpRanges": [{"CidrIp": c} for c in cidrs],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in cidrs6],
        "UserIdGroupPairs": [{"GroupId": g} for g in groups],
        "PrefixListIds": [],
    }
    if lo is not None:
        perm["FromPort"], perm["ToPort"] = lo, hi if hi is not None else lo
    return perm


def eni(*group_ids):
    return {"NetworkInterfaceId": "eni-0123", "Groups": [{"GroupId": g} for g in group_ids]}


def _page(items, key, token, size):
    start = int(token or 0)
    page = {key: items[start : start + size]}
    if start + size < len(items):
        page["NextToken"] = str(start + size)
    return page


class FakeEC2:
    def __init__(self, groups, enis, page_size=2, error_code=None):
        self.groups, self.enis = groups, enis
        self.page_size = page_size
        self.error_code = error_code
        self.tokens: dict[str, list] = {"sg": [], "eni": []}

    def describe_security_groups(self, NextToken=None):
        if self.error_code:
            raise ClientError(
                {"Error": {"Code": self.error_code, "Message": "x"}}, "DescribeSecurityGroups"
            )
        self.tokens["sg"].append(NextToken)
        return _page(self.groups, "SecurityGroups", NextToken, self.page_size)

    def describe_network_interfaces(self, NextToken=None):
        self.tokens["eni"].append(NextToken)
        return _page(self.enis, "NetworkInterfaces", NextToken, self.page_size)


class FakeFactory:
    """Maps (account, region) to a FakeEC2. Unknown pairs fail like a denied AssumeRole."""

    def __init__(self, clients: dict[tuple[str, str], FakeEC2]):
        self.clients = clients
        self.requested: list[tuple[str, str]] = []

    def ec2_client(self, account_id, region):
        self.requested.append((account_id, region))
        if (account_id, region) not in self.clients:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no role"}}, "AssumeRole"
            )
        return self.clients[(account_id, region)]


class FakeSTS:
    def __init__(self):
        self.calls = []

    def assume_role(self, RoleArn, RoleSessionName):
        self.calls.append(RoleArn)
        return {
            "Credentials": {
                "AccessKeyId": "AKIAEXAMPLE",
                "SecretAccessKey": "fake",
                "SessionToken": "fake-token",
            }
        }
