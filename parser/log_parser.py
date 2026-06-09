# Author: TK
# Date: 09-06-2026
# Purpose: Reads the JSONL session logs your honeypot generates and turns them
# into structured session objects.

import json
import os
from collections import defaultdict
from config import LOG_DIR


def load_session(log_path: str) -> dict:
    """Load a single session log file and return structured data,"""
    events = []
    with open(log_path, "r") as file:
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

    session_id = events[0],get("session_id")
    peer_ip = events[0].get("peer_ip")

    commands = [e for e in events if e["event"] == "command"]
    downloads = [e for e in events if e["event"] == "download_attempt"]
    persistence = [e for e in events if e["event"] == "persistence_attempt"]

    start = events[0]["timestamp"]
    end = events[-1]["timestamp"]

    return {
        "session_id": session_id,
        "peer_ip": peer_ip,
        "start_time": start,
        "end_time": end,
        "total_events": len(events),
        "commands": [c["value"] for c in commands],
        "downloads": [d["value"] for d in downloads],
        "persistence_attempts": [p["value"] for p in persistence],
        "raw_events": events,
    }

def load_all_sessions() -> list:
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

def aggregate_by_ip(sessions: list) -> dict:
    """Group sessions by source IP for attacker profiling."""
    by_ip = defaultdict(list)
    for s in sessions:
        by_ip[s["peer_ip"]].append(s)
    return dict(by_ip)

