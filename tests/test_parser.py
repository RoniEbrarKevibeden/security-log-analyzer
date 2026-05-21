from src.parser import parse_line


def test_parse_failed_login():
    line = (
        "Jan 05 12:01:10 host sshd[1234]: "
        "Failed password for root from 10.0.0.5 port 51234 ssh2"
    )

    event = parse_line(line, default_year=2026)

    assert event is not None
    assert event.outcome == "failed"
    assert event.username == "root"
    assert event.ip == "10.0.0.5"
    assert event.process == "sshd"
    assert event.pid == 1234
    assert event.invalid_user is False


def test_parse_invalid_user_login():
    line = (
        "Jan 05 12:01:10 host sshd[1234]: "
        "Failed password for invalid user admin from 10.0.0.5 port 51234 ssh2"
    )

    event = parse_line(line, default_year=2026)

    assert event is not None
    assert event.outcome == "failed"
    assert event.username == "admin"
    assert event.ip == "10.0.0.5"
    assert event.invalid_user is True


def test_parse_accepted_login():
    line = (
        "Jan 05 12:02:20 host sshd[1234]: "
        "Accepted password for roni from 192.168.1.10 port 51422 ssh2"
    )

    event = parse_line(line, default_year=2026)

    assert event is not None
    assert event.outcome == "accepted"
    assert event.username == "roni"
    assert event.ip == "192.168.1.10"