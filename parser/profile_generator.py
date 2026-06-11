# Author: TK
# Date: 11-06-2026
# Purpose: Generates a profile of the attacker.

import json
import os
from datetime import datetime, timezone

from config import REPORTS_DIR
from parser.attack_classifier import AttackClassifier
from enrichment.ioc_enricher import IOCEnricher


def generate_session_report(session: dict, enrich: bool = False) -> dict:
    classifier = AttackClassifier()
    classification = classifier.classify_session(session)

    enrichment = None

    if enrich and session.get("peer_ip"):
        enrichment = IOCEnricher(),enrich_ip(session["peer_ip"])

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session.get("session_id"),
        "attacker_ip": session.get("peer_ip"),
        "start_time": session.get("start_time"),
        "end_time": session.get("end_time"),
        "commands_run": session.get("commands", []),
        "files_dropped": session.get("files_dropped", []),
        "downloads": session.get("downloads", []),
        "persistence_attempts": session.get("persistence_attempts", []),
        "mitre": classification,
        "ioc_enrichment": enrichment,
        "summary": {
            "total_commands": len(session.get("commands", [])),
            "unique_techniques": classification.get("technique_count", 0),
            "risk_score": enrichment.get("risk_score") if enrichment else None,
        },
    }

    return report


def write_report(report: dict) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)

    path = os.path.join(REPORTS_DIR, f"report_{report['session_id']}.json")

    with open(path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return path
