import csv

import pytest

from sgaudit.accounts import AssumeRoleFactory
from sgaudit.cli import main
from sgaudit.collect import AccountError, collect
from tests.fakes import FakeEC2, FakeFactory, FakeSTS, eni, rule, sg

A1, A2 = "123456789012", "210987654321"


def prod_ec2():
    return FakeEC2(
        groups=[
            sg("sg-0000000000000001", "bastion", [rule("tcp", 22, cidrs=["0.0.0.0/0"])]),
            sg("sg-0000000000000002", "web", [rule("tcp", 443, cidrs=["0.0.0.0/0"])]),
            sg("sg-0000000000000003", "db", [rule("tcp", 5432, groups=["sg-0000000000000002"])]),
            sg("sg-0000000000000004", "old-test", [rule("-1", cidrs=["10.0.0.0/8"])]),
            sg("sg-0000000000000005", "default"),
        ],
        enis=[
            eni("sg-0000000000000001"),
            eni("sg-0000000000000002"),
            eni("sg-0000000000000002", "sg-0000000000000003"),
        ],
    )


def clean_ec2():
    return FakeEC2(
        groups=[sg("sg-00000000000000a1", "app", [rule("tcp", 8443, cidrs=["10.1.0.0/16"])])],
        enis=[eni("sg-00000000000000a1")],
    )


def test_collect_reads_every_page():
    ec2 = prod_ec2()
    [snap] = collect(FakeFactory({(A1, "eu-west-2"): ec2}), [A1], ["eu-west-2"])
    assert len(snap.groups) == 5
    assert ec2.tokens["sg"] == [None, "2", "4"]
    assert ec2.tokens["eni"] == [None, "2"]
    assert snap.used_group_ids == {
        "sg-0000000000000001",
        "sg-0000000000000002",
        "sg-0000000000000003",
    }


def test_failing_account_is_named():
    factory = FakeFactory({(A1, "eu-west-2"): prod_ec2()})  # A2 has no role
    with pytest.raises(AccountError, match=f"account {A2} region eu-west-2.*AccessDenied"):
        collect(factory, [A1, A2], ["eu-west-2"])


def test_api_error_inside_account_is_named():
    factory = FakeFactory({(A1, "us-east-1"): FakeEC2([], [], error_code="UnauthorizedOperation")})
    with pytest.raises(AccountError, match=f"account {A1} region us-east-1"):
        collect(factory, [A1], ["us-east-1"])


def test_assume_role_factory_builds_role_arn_and_reuses_credentials():
    sts, built = FakeSTS(), []
    f = AssumeRoleFactory(sts, "SecurityGroupAudit", client_builder=lambda *a, **k: built.append(k))
    f.ec2_client(A1, "eu-west-2")
    f.ec2_client(A1, "us-east-1")
    assert sts.calls == [f"arn:aws:iam::{A1}:role/SecurityGroupAudit"]
    assert [b["region_name"] for b in built] == ["eu-west-2", "us-east-1"]
    assert built[0]["aws_session_token"] == "fake-token"


def test_bad_account_id_rejected():
    with pytest.raises(ValueError):
        AssumeRoleFactory(FakeSTS(), "r").role_arn("12345")


def run(tmp_path, factory, *extra):
    md, out_csv = tmp_path / "a.md", tmp_path / "a.csv"
    args = [
        "--account",
        A1,
        "--account",
        A2,
        "--region",
        "eu-west-2",
        "--markdown",
        str(md),
        "--csv",
        str(out_csv),
        *extra,
    ]
    return main(args, factory=factory), md, out_csv


def two_accounts():
    return FakeFactory({(A1, "eu-west-2"): prod_ec2(), (A2, "eu-west-2"): clean_ec2()})


def test_reports_written(tmp_path):
    code, md, out_csv = run(tmp_path, two_accounts())
    assert code == 0
    text = md.read_text(encoding="utf-8")
    assert "- Security groups reviewed: 6. Ingress rules reviewed: 5." in text
    assert "- HIGH: 1, MEDIUM: 1, LOW: 2 (LOW includes 1 unused group(s))." in text
    assert (
        f"| HIGH | {A1} | eu-west-2 | sg-0000000000000001 (bastion) | tcp | 22 | 0.0.0.0/0 |"
        in text
    )
    assert f"| {A1} | eu-west-2 | sg-0000000000000004 (old-test) |" in text

    rows = list(csv.DictReader(out_csv.open(encoding="utf-8")))
    assert len(rows) == 5  # every ingress rule, flagged or not
    assert rows[0]["severity"] == "HIGH"
    assert {r["account_id"] for r in rows} == {A1, A2}
    assert any(r["severity"] == "" and r["account_id"] == A2 for r in rows)


def test_fail_on_high_exit_code(tmp_path):
    assert run(tmp_path, two_accounts(), "--fail-on-high")[0] == 2


def test_fail_on_high_is_zero_when_clean(tmp_path):
    factory = FakeFactory({(A1, "eu-west-2"): clean_ec2(), (A2, "eu-west-2"): clean_ec2()})
    assert run(tmp_path, factory, "--fail-on-high")[0] == 0


def test_account_error_exits_1_and_writes_nothing(tmp_path, capsys):
    factory = FakeFactory({(A1, "eu-west-2"): prod_ec2()})
    code, md, out_csv = run(tmp_path, factory)
    assert code == 1
    assert not md.exists() and not out_csv.exists()
    assert A2 in capsys.readouterr().err
