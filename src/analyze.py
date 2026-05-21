import argparse
from pathlib import Path

from .parser import parse_lines
from .report import write_json
from .rules import detect_bruteforce, detect_invalid_user_attempts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs for suspicious login activity."
    )

    parser.add_argument(
        "logfile",
        help="Path to SSH/authentication log file",
    )

    parser.add_argument(
        "--window-min",
        type=int,
        default=5,
        help="Time window in minutes for brute-force detection",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed logins required to trigger a finding",
    )

    parser.add_argument(
        "--out",
        default="report.json",
        help="Output JSON report path",
    )

    args = parser.parse_args()

    log_path = Path(args.logfile)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    lines = log_path.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines()

    events = parse_lines(lines)

    findings = []
    findings.extend(
        detect_bruteforce(
            events,
            window_minutes=args.window_min,
            threshold=args.threshold,
        )
    )
    findings.extend(detect_invalid_user_attempts(events))

    write_json(findings, args.out)

    print(f"Parsed events: {len(events)}")
    print(f"Findings: {len(findings)}")
    print(f"Report written to: {args.out}")


if __name__ == "__main__":
    main()