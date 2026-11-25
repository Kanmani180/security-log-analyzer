import re
from pathlib import Path

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_failed_logins(log_path: str) -> list[dict]:
    """Extract timestamp, target username, and source IP from failed SSH login lines."""
    events = []
    path = Path(log_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if match:
                events.append(match.groupdict())

    return events


if __name__ == "__main__":
    failed_events = parse_failed_logins("sample_auth.log")
    print(f"Total failed login attempts detected: {len(failed_events)}\n")
    for event in failed_events:
        print(
            f"[{event['timestamp']}] User: {event['user']:<10} | Source IP: {event['ip']}")
