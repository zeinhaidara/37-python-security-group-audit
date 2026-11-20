import pytest

from sgaudit.collect import RegionSnapshot
from sgaudit.rules import HIGH, LOW, MEDIUM, flatten, grade
from tests.fakes import rule, sg


@pytest.mark.parametrize(
    ("perm", "source", "severity", "text"),
    [
        (rule("tcp", 22), "0.0.0.0/0", HIGH, "SSH"),
        (rule("tcp", 3389), "::/0", HIGH, "RDP"),
        (rule("tcp", 5432), "0.0.0.0/0", HIGH, "PostgreSQL"),
        (rule("tcp", 6379), "0.0.0.0/0", HIGH, "Redis"),
        (rule("tcp", 0, 1024), "0.0.0.0/0", HIGH, "SSH"),  # range covers 22
        (rule("-1"), "0.0.0.0/0", HIGH, "all ports"),
        (rule("tcp", 0, 65535), "::/0", HIGH, "all ports"),
        (rule("-1"), "10.0.0.0/8", MEDIUM, "all ports open to 10.0.0.0/8"),
        (rule("tcp", 8080), "0.0.0.0/0", MEDIUM, "open to the internet"),
        (rule("icmp", -1, -1), "0.0.0.0/0", MEDIUM, "open to the internet"),
        (rule("tcp", 443), "0.0.0.0/0", LOW, "web port"),
        (rule("tcp", 80), "::/0", LOW, "web port"),
    ],
)
def test_grading(perm, source, severity, text):
    got_severity, finding = grade(perm, source)
    assert got_severity == severity
    assert text in finding


@pytest.mark.parametrize(
    ("perm", "source"),
    [
        (rule("tcp", 22), "10.0.0.0/8"),
        (rule("tcp", 5432), "sg-0bbbbbbbbbbbbbbb1"),
        (rule("tcp", 443), "192.0.2.0/24"),
    ],
)
def test_restricted_sources_are_not_flagged(perm, source):
    assert grade(perm, source) == ("", "")


def test_web_range_wider_than_one_port_is_medium():
    assert grade(rule("tcp", 80, 443), "0.0.0.0/0")[0] == MEDIUM


def snapshot(groups, used=()):
    return RegionSnapshot("123456789012", "eu-west-2", groups, set(used))


def test_flatten_one_row_per_source():
    g = sg(
        "sg-01",
        rules=[
            rule("tcp", 22, cidrs=["0.0.0.0/0", "10.0.0.0/8"], cidrs6=["::/0"], groups=["sg-02"])
        ],
    )
    rows, _ = flatten([snapshot([g], used=["sg-01"])])
    assert [(r.source, r.severity) for r in rows] == [
        ("0.0.0.0/0", HIGH),
        ("10.0.0.0/8", ""),
        ("::/0", HIGH),
        ("sg-02", ""),
    ]
    assert rows[0].ports == "22"
    assert rows[0].vpc_id == "vpc-0aaaaaaaaaaaaaaa1"


def test_unused_groups_skip_default():
    groups = [sg("sg-01", "web"), sg("sg-02", "old"), sg("sg-03", "default")]
    _, unused = flatten([snapshot(groups, used=["sg-01"])])
    assert [u.group_id for u in unused] == ["sg-02"]
    assert unused[0].severity == LOW


def test_protocol_all_is_labelled():
    rows, _ = flatten([snapshot([sg("sg-01", rules=[rule("-1", cidrs=["0.0.0.0/0"])])], ["sg-01"])])
    assert (rows[0].protocol, rows[0].ports) == ("all", "all")
