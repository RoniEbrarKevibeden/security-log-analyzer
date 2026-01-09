# Security Log Analyzer (SSH)

I built this small security-focused tool to practice how real-world systems detect suspicious login activity from logs.
The program parses SSH authentication logs and creates a JSON report with simple security findings.

## Why I built this
In cyber security, a lot of detection starts from logs. I wanted a hands-on project where I:
- read and parse real log formats
- extract meaningful events (failed/accepted logins)
- apply simple detection logic (rules)
- generate a structured report

## What it does
- Parses SSH authentication log lines and extracts:
  - timestamp, username, IP address, outcome (failed/accepted)
- Detects:
  - **Brute-force attempts** (many failed logins from the same IP in a short time window)
  - **Invalid user attempts** (logins for non-existing users)
- Generates a JSON report containing findings

## How to run
Install dependencies:
```bash
pip install -r requirements.txt
```

Run the analyzer on the sample log:
```bash
python -m src.analyze data/sample_auth.log --window-min 5 --threshold 5 --out report.json
```

## What I learned

-How to work with log formats and parsing (regex + structured events)

-Turning raw logs into a clean data model (AuthEvent)

-Implementing rule-based detection with time windows and thresholds

-Writing usable CLI tools with arguments and clear output

-Basic “security mindset”: detecting patterns instead of looking at single lines

## Next improvements

-Support more auth log formats and edge cases

-Add CSV/HTML reports

-Add unit tests for parsing and rule logic

-Make rule thresholds configurable via a config file

## Ethical use

This project is for educational purposes. It should only be used on systems and log files you own or have explicit permission to analyze.
