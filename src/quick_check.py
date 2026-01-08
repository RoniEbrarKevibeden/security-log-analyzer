from pathlib import Path
from .parser import parse_lines

def main():
    log_path = Path("data/sample_auth.log")
    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    events = parse_lines(lines)

    print("Total events:", len(events))
    print("First 3:")
    for e in events[:3]:
        print(e.outcome, e.username, e.ip, e.invalid_user)

if __name__ == "__main__":
    main()
