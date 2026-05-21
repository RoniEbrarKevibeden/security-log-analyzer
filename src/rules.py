from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, List

from .models import AuthEvent


def detect_invalid_user_attempts(events: List[AuthEvent]) -> List[Dict[str, Any]]:
    counts = defaultdict(int)

    for event in events:
        if event.outcome == "failed" and event.invalid_user and event.ip:
            counts[event.ip] += 1

    findings = []

    for ip, count in counts.items():
        findings.append(
            {
                "type": "invalid_user_attempts",
                "ip": ip,
                "count": count,
                "severity": "medium" if count < 10 else "high",
            }
        )

    return findings


def detect_bruteforce(
    events: List[AuthEvent],
    window_minutes: int = 5,
    threshold: int = 5,
) -> List[Dict[str, Any]]:
    failed_events = [
        event for event in events if event.outcome == "failed" and event.ip
    ]

    failed_events.sort(key=lambda event: event.timestamp)

    events_by_ip = defaultdict(list)

    for event in failed_events:
        events_by_ip[event.ip].append(event.timestamp)

    findings = []
    window = timedelta(minutes=window_minutes)

    for ip, timestamps in events_by_ip.items():
        start_index = 0

        for end_index in range(len(timestamps)):
            while timestamps[end_index] - timestamps[start_index] > window:
                start_index += 1

            count = end_index - start_index + 1

            if count >= threshold:
                findings.append(
                    {
                        "type": "bruteforce_suspected",
                        "ip": ip,
                        "window_minutes": window_minutes,
                        "threshold": threshold,
                        "count_in_window": count,
                        "first_seen": timestamps[start_index].isoformat(),
                        "last_seen": timestamps[end_index].isoformat(),
                        "severity": "high" if count >= threshold * 2 else "medium",
                    }
                )
                break

    return findings