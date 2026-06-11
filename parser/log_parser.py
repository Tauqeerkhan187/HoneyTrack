# Author: TK
# Date: 09-06-2026
# Purpose: Reads the JSONL session logs your honeypot generates and turns them
# into structured session objects.

import json
import os
from collections import defaultdict

from config import LOG_DIR


def load_session(log_path: str) -> dict:
    """Load one JSONL session log and return a structured session object."""

    events = []

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not events:
        return {}

    commands = [e for e in events if e.get("event") == "command"]
    downloads = [e for e in events if e.get("event") == "download_attempt"]
    persistence = [e for e in events if e.get("event") == "persistence_attempt"]
    files_dropped = [e for e in events if e.get("event") == "file_drop"]

    return {
        "session_id": events[0].get("session_id"),
        "peer_ip": events[0].get("peer_ip"),
        "peer_port": events[0].get("peer_port"),
        "start_time": events[0].get("timestamp"),
        "end_time": events[-1].get("timestamp"),
        "total_events": len(events),
        "commands": [c.get("value", "") for c in commands],
        "downloads": [d.get("value", "") for d in downloads],
        "persistence_attempts": [p.get("value", "") for p in persistence],
        "files_dropped": [f.get("value", "") for f in files_dropped],
        "raw_events": events,
    }


def load_all_sessions() -> list[dict]:
    """Load every session log file in LOG_DIR."""

    sessions = []

    if not os.path.exists(LOG_DIR):
        return sessions

    for fname in sorted(os.listdir(LOG_DIR)):
        if fname.startswith("session_") and fname.endswith(".json"):
            path = os.path.join(LOG_DIR, fname)
            session = load_session(path)

            if session:
                sessions.append(session)

    return sessions


def aggregate_by_ip(sessions: list[dict]) -> dict:
    """Group sessions by source IP for attacker profiling."""

    by_ip = defaultdict(list)

    for session in sessions:
        by_ip[session.get("peer_ip", "unknown")].append(session)

    return dict(by_ip)

