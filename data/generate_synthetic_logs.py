"""
generate_synthetic_logs.py

Generates a synthetic SSH authentication log (formatted like Linux's
/var/log/auth.log) containing:
  1. Normal legitimate traffic
  2. A classic brute-force pattern
  3. A credential-stuffing pattern
  4. A compromise pattern (fail burst -> success)
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

HOSTNAME = "server"
PROCESS = "sshd"
PID = 1234

USERNAMES = ["mark", "sara", "devops", "backup", "jenkins"]
NORMAL_IPS = ["10.0.0.15", "10.0.0.22", "10.0.0.31"]

BRUTE_FORCE_IP = "203.0.113.45"
BRUTE_FORCE_USER = "admin"

CRED_STUFFING_IP = "198.51.100.77"
CRED_STUFFING_USERS = ["admin", "root", "test", "user", "oracle",
                        "postgres", "ubuntu", "deploy", "git", "svn"]

COMPROMISE_IP = "185.220.101.4"
COMPROMISE_USER = "root"


def fmt(dt):
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")


def log_line(dt, outcome, username, ip, port):
    return (f"{fmt(dt)} {HOSTNAME} {PROCESS}[{PID}]: "
            f"{outcome} password for {username} from {ip} port {port} ssh2")


def random_port():
    return random.randint(40000, 65000)


def generate_normal_traffic(start, count):
    lines = []
    t = start
    for _ in range(count):
        t += timedelta(minutes=random.randint(5, 90))
        user = random.choice(USERNAMES)
        ip = random.choice(NORMAL_IPS)
        if random.random() < 0.15:
            lines.append(log_line(t, "Failed", user, ip, random_port()))
            t += timedelta(seconds=random.randint(3, 10))
        lines.append(log_line(t, "Accepted", user, ip, random_port()))
    return lines


def generate_brute_force(start, attempts=25):
    lines = []
    t = start
    for _ in range(attempts):
        t += timedelta(seconds=random.randint(1, 6))
        lines.append(log_line(t, "Failed", BRUTE_FORCE_USER, BRUTE_FORCE_IP, random_port()))
    return lines


def generate_credential_stuffing(start):
    lines = []
    t = start
    for user in CRED_STUFFING_USERS:
        t += timedelta(seconds=random.randint(2, 8))
        lines.append(log_line(t, "Failed", user, CRED_STUFFING_IP, random_port()))
    return lines


def generate_compromise(start, fails_before_success=14):
    lines = []
    t = start
    for _ in range(fails_before_success):
        t += timedelta(seconds=random.randint(1, 4))
        lines.append(log_line(t, "Failed", COMPROMISE_USER, COMPROMISE_IP, random_port()))
    t += timedelta(seconds=random.randint(1, 4))
    lines.append(log_line(t, "Accepted", COMPROMISE_USER, COMPROMISE_IP, random_port()))
    return lines


def main():
    base = datetime(2026, 1, 15, 8, 0, 0)

    all_lines = []
    all_lines += generate_normal_traffic(base, count=40)
    all_lines += generate_brute_force(base + timedelta(hours=6, minutes=2))
    all_lines += generate_credential_stuffing(base + timedelta(hours=7, minutes=15))
    all_lines += generate_compromise(base + timedelta(hours=9, minutes=40))
    all_lines += generate_normal_traffic(base + timedelta(hours=10), count=15)

    def parse_ts(line):
        ts_str = " ".join(line.split()[:3])
        return datetime.strptime(f"2026 {ts_str}", "%Y %b %d %H:%M:%S")

    all_lines.sort(key=parse_ts)

    out_path = Path(__file__).resolve().parent / "sample_auth.log"
    out_path.write_text("\n".join(all_lines) + "\n")

    print(f"Wrote {len(all_lines)} log lines to {out_path}")
    print("\nGround truth for validating detectors:")
    print(f"  Brute force IP:        {BRUTE_FORCE_IP}  (user: {BRUTE_FORCE_USER}, ~25 fails, 0 success)")
    print(f"  Credential stuffing IP:{CRED_STUFFING_IP}  ({len(CRED_STUFFING_USERS)} distinct usernames)")
    print(f"  Compromise IP:         {COMPROMISE_IP}  (14 fails then 1 success, user: {COMPROMISE_USER})")


if __name__ == "__main__":
    main()
