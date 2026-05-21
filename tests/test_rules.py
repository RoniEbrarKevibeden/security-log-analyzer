from datetime import datetime, timedelta

from src.models import AuthEvent
from src.rules import detect_bruteforce, detect_invalid_user_attempts


def make_event(
    timestamp,
    ip="10.0.0.5",
    username="root",
    outcome="failed",
    invalid_user=False,
):
    return AuthEvent(
        timestamp=timestamp,
        host="host",
        process="sshd",
        pid=1234,
        outcome=outcome,
        username=username,
        ip=ip,
        raw="sample log line",
        invalid_user=invalid_user,
    )


def test_detect_bruteforce():
    start = datetime(2026, 1, 5, 12, 1, 0)

    events = [
        make_event(start + timedelta(seconds=10 * i))
        for i in range(5)
    ]

    findings = detect_bruteforce(
        events,
        window_minutes=5,
        threshold=5,
    )

    assert len(findings) == 1
    assert findings[0]["type"] == "bruteforce_suspected"
    assert findings[0]["ip"] == "10.0.0.5"


def test_detect_invalid_user_attempts():
    timestamp = datetime(2026, 1, 5, 12, 1, 0)

    events = [
        make_event(
            timestamp,
            username="admin",
            invalid_user=True,
        )
    ]

    findings = detect_invalid_user_attempts(events)

    assert len(findings) == 1
    assert findings[0]["type"] == "invalid_user_attempts"
    assert findings[0]["ip"] == "10.0.0.5"