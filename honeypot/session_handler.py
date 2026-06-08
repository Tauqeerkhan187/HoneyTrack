# Author: TK
# Date: 06-06-2026
# Purpose: Handles everything that happens inside a session - command processing, logging.

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from honeypot.fake_fs import (
    fake_ls, fake_cat, fake_pwd, fake_uname,
    fake_whoami, fake_id, fake_ifconfig
)
from config import LOG_DIR, FAKE_HOSTNAME, FAKE_USER

def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


class SessionHandler:
    def __init__(self, peer_addr):
        self.session_id = str(uuid.uuid4())[:8]
        self.peer_ip = peer_addr[0]
        self.peer_port = peer_addr[1]
        self.cwd = "/root"
        self.commands = []
        self.start_time = datetime.now(timezone.utc)
        self.log_path = os.path.join(LOG_DIR, f"session_{self.session_id}.json")
        ensure_log_dir()
        self._log_event("session_start", "")

    def handle_command(self, raw_input: str) -> str:
        """Process a command and return a fake response."""
        cmd = raw_input.strip()
        if not cmd:
            return ""

        self._log_event("command", cmd)

        # parse base command
        parts = cmd.split()
        base = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # cmd dispatcher
        if base in ("ls", "dir"):
            path = args[0] if args else self.cwd
            return fake_ls(path)

        elif base == "cat":
            if not args:
                return "cat: missing operand"
            return fake_cat(args[0])

        elif base == "pwd":
            return fake_pwd(self.cwd)

        elif base == "cd":
            target = args[0] if args else "/root"
            self.cwd = target
            return ""

        elif base == "whoami":
            return fake_whoami()

        elif base == "id":
            return fake_id()

        elif base in ("uname",):
            return fake_uname()

        elif base in ("ifconfig", "ip"):
            return fake_ifconfig()

        elif base in ("wget", "curl"):
            # Log download attempt but fake a failure
            url = args[0] if args else ""
            self._log_event("download_attempt", url)
            return f"curl: (6) Could not resolve host: {url.split('/')[2] if '//' in url else url}"

        elif base in ("python", "python3", "perl", "bash", "sh"):
            self._log_event("interpreter_exec", cmd)
            return ""

        elif base in ("chmod", "chown"):
            self._log_event("permission_change", cmd)
            return ""

        elif base in ("crontab",):
            self._log_event("persistence_attempt", cmd)
            return ""

        elif base in ("exit", "logout", "quit"):
            return "__EXIT__"

        elif base in ("clear", "reset"):
            return ""

        else:
            return f"{base}: command not found"

    def _log_event(self, event_type: str, value: str):
        """Append a structured event to the session log."""
        entry = {
            "session_id": self.session_id,
            "peer_ip": self.peer_ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "value": value,
        }
        self.commands.append(entry)
        # Append to JSONL log file
        with open(self.log_path, "a") as file:
            file.write(json.dumps(entry) + "\n")

    def close(self):
        duration = (datetime.now(timezone.utc) - self.start_time).seconds
        self._log_event("session_end", f"duration={duration}s")
        print(f"[SESSION CLOSED] {self.session_id} | {self.peer_ip}
              {duration}s | {len(self.commands)} events")




