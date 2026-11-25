import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
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


def detect_bruteforce(events: list[dict], threshold: int = 3) -> list[dict]:
    """Flag source IPs exceeding the allowed failed-login threshold."""
    ip_counts = Counter(event["ip"] for event in events)
    targeted_users = defaultdict(set)

    for event in events:
        targeted_users[event["ip"]].add(event["user"])

    alerts = []
    for ip, count in ip_counts.most_common():
        if count > threshold:
            alerts.append({
                "source_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH",
                "targeted_users": sorted(targeted_users[ip]),
            })

    return alerts


def export_report(events: list[dict], alerts: list[dict], output_path: str = "incident_report.json") -> None:
    """Save a structured JSON security incident report."""
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_failed_attempts": len(events),
        "high_severity_alerts": len(alerts),
        "brute_force_suspects": alerts,
    }
    Path(output_path).write_text(json.dumps(
        report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    failed_events = parse_failed_logins("sample_auth.log")
    brute_force_alerts = detect_bruteforce(failed_events, threshold=3)
    export_report(failed_events, brute_force_alerts)

    print(f"Total failed attempts: {len(failed_events)}")
    print(
        f"Brute-force IPs flagged (>3 attempts): {len(brute_force_alerts)}\n")

    for alert in brute_force_alerts:
        print(
            f"[{alert['severity']}] IP: {alert['source_ip']} | "
            f"Attempts: {alert['failed_attempts']} | "
            f"Users targeted: {', '.join(alert['targeted_users'])}"
        )
    print("\nSaved full report to incident_report.json")
