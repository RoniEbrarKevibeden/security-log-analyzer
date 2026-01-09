import argparse
from pathlib import Path
from .parser import parse_lines
from .rules import detect_bruteforce, detect_invalid_user_attempts
from .report import write_json

def main():
    ap = argparse.ArgumentParser(description="Security Log Analyzer (SSH/auth logs)")
    ap.add_argument("logfile", help="Path to SSH/auth log file")
    ap.add_argument("--window-min", type=int, default=5)
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--out", default="report.json", help="Output JSON path")
    args = ap.parse_args()

    log_path = Path(args.logfile)
    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    events = parse_lines(lines)

    findings = []
    findings += detect_bruteforce(events, window_minutes=args.window_min, threshold=args.threshold)
    findings += detect_invalid_user_attempts(events)

    write_json(findings, args.out)

    print(f"Parsed events: {len(events)}")
    print(f"Findings: {len(findings)}")
    print(f"Report written to: {args.out}")

if __name__ == "__main__":
    main()
