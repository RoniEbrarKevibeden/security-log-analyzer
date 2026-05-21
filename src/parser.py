import re
from datetime import datetime
from typing import List, Optional

from dateutil import parser as dtparser

from .models import AuthEvent


FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)

ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)"
)

PROC_RE = re.compile(
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)


def parse_line(line: str, default_year: int) -> Optional[AuthEvent]:
    line = line.strip()

    if not line:
        return None

    try:
        prefix = line[:15]
        timestamp = dtparser.parse(f"{default_year} {prefix}")
    except Exception:
        return None

    rest = line[16:]
    process_match = PROC_RE.search(rest)

    if not process_match:
        return AuthEvent(
            timestamp=timestamp,
            host="unknown",
            process="unknown",
            pid=None,
            outcome="other",
            username=None,
            ip=None,
            raw=line,
        )

    host = process_match.group("host")
    process = process_match.group("proc")
    pid = int(process_match.group("pid")) if process_match.group("pid") else None
    message = process_match.group("msg")

    outcome = "other"
    username = None
    ip = None
    invalid_user = False

    failed_match = FAILED_RE.search(message)

    if failed_match:
        outcome = "failed"
        username = failed_match.group("user")
        ip = failed_match.group("ip")
        invalid_user = "invalid user" in message
    else:
        accepted_match = ACCEPTED_RE.search(message)

        if accepted_match:
            outcome = "accepted"
            username = accepted_match.group("user")
            ip = accepted_match.group("ip")

    return AuthEvent(
        timestamp=timestamp,
        host=host,
        process=process,
        pid=pid,
        outcome=outcome,
        username=username,
        ip=ip,
        raw=line,
        invalid_user=invalid_user,
    )


def parse_lines(lines: List[str]) -> List[AuthEvent]:
    default_year = datetime.now().year
    events: List[AuthEvent] = []

    for line in lines:
        event = parse_line(line, default_year)

        if event is not None:
            events.append(event)

    return events