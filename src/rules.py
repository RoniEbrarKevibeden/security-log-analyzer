from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any
from .models import AuthEvent

def detect_invalid_user_attempts(events: List[AuthEvent]) -> List[Dict[str, Any]]:
    counts = defaultdict(int)
    for e in events:
        if e.outcome == "failed" and e.invalid_user and e.ip:
            counts[e.ip] += 1

    findings = []
    for ip, cnt in counts.items():
        findings.append({
            "type": "invalid_user_attempts",
            "ip": ip,
            "count": cnt,
            "severity": "medium" if cnt < 10 else "high",
        })
    return findings

def detect_bruteforce(events: List[AuthEvent], window_minutes: int = 5, threshold: int = 5) -> List[Dict[str, Any]]:
    failed = [e for e in events if e.outcome == "failed" and e.ip]
    failed.sort(key=lambda x: x.timestamp)

    by_ip = defaultdict(list)
    for e in failed:
        by_ip[e.ip].append(e.timestamp)

    findings = []
    window = timedelta(minutes=window_minutes)

    for ip, times in by_ip.items():
        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > window:
                i += 1
            count = j - i + 1
            if count >= threshold:
                findings.append({
                    "type": "bruteforce_suspected",
                    "ip": ip,
                    "window_minutes": window_minutes,
                    "threshold": threshold,
                    "count_in_window": count,
                    "first_seen": times[i].isoformat(),
                    "last_seen": times[j].isoformat(),
                    "severity": "high" if count >= threshold * 2 else "medium",
                })
                break
    return findings
