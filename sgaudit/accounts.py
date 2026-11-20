"""Get an EC2 client for an account and region by assuming a role."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol

ACCOUNT_RE = re.compile(r"^\d{12}$")


class ClientFactory(Protocol):
    def ec2_client(self, account_id: str, region: str): ...


class AssumeRoleFactory:
    """Assumes `role_name` in each account. Read-only use only."""

    def __init__(self, sts, role_name: str, client_builder: Callable | None = None):
        self.sts = sts
        self.role_name = role_name
        self._build = client_builder
        self._creds: dict[str, dict] = {}

    def role_arn(self, account_id: str) -> str:
        if not ACCOUNT_RE.match(account_id):
            raise ValueError(f"not a 12-digit account id: {account_id!r}")
        return f"arn:aws:iam::{account_id}:role/{self.role_name}"

    def ec2_client(self, account_id: str, region: str):
        if account_id not in self._creds:
            resp = self.sts.assume_role(
                RoleArn=self.role_arn(account_id), RoleSessionName="sg-audit"
            )
            self._creds[account_id] = resp["Credentials"]
        c = self._creds[account_id]
        build = self._build or _boto3_client
        return build(
            "ec2",
            region_name=region,
            aws_access_key_id=c["AccessKeyId"],
            aws_secret_access_key=c["SecretAccessKey"],
            aws_session_token=c["SessionToken"],
        )


def _boto3_client(*args, **kwargs):
    import boto3

    return boto3.client(*args, **kwargs)
