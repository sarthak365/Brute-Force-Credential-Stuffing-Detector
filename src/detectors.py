"""
detectors.py

Detection logic for identifying attack patterns in parsed SSH auth logs.

Three detectors:
  1. detect_brute_force()        - one IP, one/few usernames, many fails
  2. detect_credential_stuffing() - one IP, many different usernames
  3. detect_compromise()          - failure burst followed by a success (CRITICAL)
"""

import pandas as pd

def detect_brute_force(df, window_minutes=5, fail_threshold=10, max_usernames=2):
    """
    Flags an IP that racks up many failed attempts within a rolling
    time window AGAINST ONE ACCOUNT (or a couple at most) - the classic
    'guess the password' pattern.

    The max_usernames check is what separates this from credential
    stuffing: true brute force hammers ONE username repeatedly, while
    credential stuffing spreads attempts across MANY usernames. Without
    this check, a credential-stuffing IP could accidentally also match
    the brute-force rule just because its total fail count is high.
    """
    failed = df[df.outcome == 'Failed'].copy()
    alerts = []

    for ip, group in failed.groupby('src_ip'):
        if group['username'].nunique() > max_usernames:
            continue

        group = group.sort_values('timestamp').set_index('timestamp')
        counts = group['outcome'].rolling(f'{window_minutes}min').count()
        if counts.max() >= fail_threshold:
            alerts.append({
                'type': 'Brute Force',
                'src_ip': ip,
                'fail_count': int(counts.max()),
                'window_minutes': window_minutes,
                'usernames_targeted': group['username'].nunique()
            })
    return alerts


def detect_credential_stuffing(df, unique_user_threshold=8):
    """
    Flags an IP that tries many DIFFERENT usernames - a breach-list
    replay pattern, distinct from brute force (which hits one username hard).
    """
    failed = df[df.outcome == 'Failed']
    alerts = []

    for ip, group in failed.groupby('src_ip'):
        unique_users = group['username'].nunique()
        if unique_users >= unique_user_threshold:
            alerts.append({
               'type': 'Credential Stuffing',
                'src_ip': ip,
                'unique_usernames_tried': unique_users,
                'total_attempts': len(group)
            })
    return alerts


def detect_compromise(df, lookback_minutes=5, fail_threshold=5):
    """
    Flags a successful login that was immediately preceded by a burst
    of failures from the same IP - the highest-severity pattern, since
    it suggests the attacker eventually guessed correctly.
    """
    df = df.sort_values('timestamp')
    alerts = []
    successes = df[df.outcome == 'Accepted']

    for _, row in successes.iterrows():
        window_start = row['timestamp'] - pd.Timedelta(minutes=lookback_minutes)
        recent_fails = df[
            (df.src_ip == row['src_ip']) &
            (df.outcome == 'Failed') &
            (df.timestamp.between(window_start, row['timestamp']))
        ]
        if len(recent_fails) >= fail_threshold:
            alerts.append({
                'type': 'Possible Compromise',
                'src_ip': row['src_ip'],
                'username': row['username'],
                'failed_attempts_before_success': len(recent_fails),
                'success_time': str(row['timestamp'])
            })
    return alerts


def run_all_detectors(df):
    """Run all three detectors and return a combined list of alerts."""
    alerts = []
    alerts += detect_brute_force(df)
    alerts += detect_credential_stuffing(df)
    alerts += detect_compromise(df)
    return alerts


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from src.parser import parse_log_file

    df = parse_log_file("data/sample_auth.log")
    alerts = run_all_detectors(df)

    print(f"Found {len(alerts)} alert(s):\n")
    for a in alerts:
        print(a)
