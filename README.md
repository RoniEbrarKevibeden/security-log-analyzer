# Security Log Analyzer SSH

A small Python command-line tool that analyzes SSH authentication logs and detects suspicious login activity.

I built this project to practice a basic SOC-style workflow: reading raw logs, extracting useful fields, applying simple detection rules, and writing a structured report.

## Why I Built This

When I started learning about blue team and SOC work, I noticed that many security investigations begin with logs. A single failed login is not always important, but repeated failed logins from the same IP address can be a useful signal.

This project helped me understand how raw SSH log lines can be turned into structured events and simple security findings.

## What It Detects

The tool currently detects:

- failed SSH login attempts
- accepted SSH logins
- invalid user login attempts
- possible brute-force activity from the same IP address

## Example Log Line

```text
Jan 05 12:01:10 host sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 51234 ssh2
```

The parser extracts:

```text
timestamp: Jan 05 12:01:10
process: sshd
username: admin
ip: 10.0.0.5
outcome: failed
invalid_user: true
```

## Project Structure

```text
security-log-analyzer/
├── data/
│   └── sample_auth.log
├── src/
│   ├── analyze.py
│   ├── models.py
│   ├── parser.py
│   ├── report.py
│   └── rules.py
├── tests/
│   ├── test_parser.py
│   └── test_rules.py
├── requirements.txt
└── README.md
```

## How to Run

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the analyzer on the sample log file:

```bash
python -m src.analyze data/sample_auth.log --window-min 5 --threshold 5 --out report.json
```

Expected terminal output:

```text
Parsed events: 7
Findings: 2
Report written to: report.json
```

## Example JSON Report

```json
{
  "findings": [
    {
      "type": "bruteforce_suspected",
      "ip": "10.0.0.5",
      "window_minutes": 5,
      "threshold": 5,
      "count_in_window": 5,
      "severity": "medium"
    },
    {
      "type": "invalid_user_attempts",
      "ip": "10.0.0.5",
      "count": 1,
      "severity": "medium"
    }
  ],
  "total_findings": 2
}
```

## How to Run Tests

```bash
python -m pytest
```

## What I Learned

While building this project, I practiced:

- parsing Linux-style SSH authentication logs
- using regular expressions to extract usernames, IP addresses, and login outcomes
- grouping failed login attempts by IP address
- detecting simple brute-force patterns with a time window and threshold
- writing basic unit tests for parser and detection logic
- generating structured JSON reports for investigation notes

## Limitations

This is a learning project, not a production SIEM tool.

Current limitations:

- supports only a small set of SSH log formats
- does not process live logs
- does not enrich IP addresses with geolocation or threat intelligence
- does not support CSV or HTML reporting yet
- detection rules are simple and rule-based

## Possible Improvements

Things I would improve next:

- support more authentication log formats
- add CSV and HTML report output
- add configuration file support for detection thresholds
- add more test cases for edge cases
- add a simple dashboard or summary table

## Ethical Use

This project is for educational and defensive security practice. It should only be used on log files from systems you own or have permission to analyze.