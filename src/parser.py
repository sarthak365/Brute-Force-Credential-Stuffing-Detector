"""
parser.py

Parses SSH auth log lines (like /var/log/auth.log) into a structured
pandas DataFrame with columns: timestamp, outcome, username, src_ip

Usage:
    from parser import parse_log_file
    df = parse_log_file("data/sample_auth.log")
"""

import re
import pandas as pd
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<outcome>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?'
    r'(?P<username>\S+)\s+from\s+(?P<src_ip>[\d.]+)\s+port\s+\d+'
)


def parse_log_file(path, year=2026):
    """Read a log file and return a DataFrame of parsed entries."""
    records = []
    with open(path) as f:
        for line in f:
            m = LOG_PATTERN.search(line)
            if m:
                d = m.groupdict()
                d['timestamp'] = datetime.strptime(
                    f"{year} {d['timestamp']}", "%Y %b %d %H:%M:%S"
                )
                records.append(d)

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values('timestamp').reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = parse_log_file("data/sample_auth.log")
    print(f"Parsed {len(df)} log entries\n")
    print(df.head(10))
    print("\nOutcome counts:")
    print(df['outcome'].value_counts())
    print("\nTop source IPs by event count:")
    print(df['src_ip'].value_counts().head(10))
