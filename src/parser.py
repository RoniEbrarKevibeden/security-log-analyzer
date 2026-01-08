import re
from datetime import datetime
from dateutil import parser as dtparser
from typing import List, Optional
from .models import AuthEvent

FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
PROC_RE = re.compile(r"(?P<host>\S+)\s+(?P<proc>\S+?)(\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")

def parse_line(line: str, default_year: int) -> Optional[AuthEvent]:
    line = line.strip()
    if not line:
        return None

    # First 15 chars are usually: "Jan 05 12:01:10"
    try:
        prefix = line[:15]
        ts = dtparser.parse(f"{default_year} {prefix}")
    except Exception:
        return None

    rest = line[16:]  # after timestamp + space
    mproc = PROC_RE.search(rest)
    if not mproc:
        return AuthEvent(ts, "unknown", "unknown", None, "other", None, None, line)

    host = mproc.group("host")
    proc = mproc.group("proc")
    pid = int(mproc.group("pid")) if mproc.group("pid") else None
    msg = mproc.group("msg")

    outcome = "other"
    user = None
    ip = None
    invalid_user = False

    mf = FAILED_RE.search(msg)
    if mf:
        outcome = "failed"
        user = mf.group("user")
        ip = mf.group("ip")
        invalid_user = "invalid user" in msg
    else:
        ma = ACCEPTED_RE.search(msg)
        if ma:
            outcome = "accepted"
            user = ma.group("user")
            ip = ma.group("ip")

    return AuthEvent(
        timestamp=ts,
        host=host,
        process=proc,
        pid=pid,
        outcome=outcome,
        username=user,
        ip=ip,
        raw=line,
        invalid_user=invalid_user
    )

def parse_lines(lines: List[str]) -> List[AuthEvent]:
    default_year = datetime.now().year
    events: List[AuthEvent] = []
    for line in lines:
        ev = parse_line(line, default_year)
        if ev is not None:
            events.append(ev)
    return events
