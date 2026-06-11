# Author: TK
# Date: 08-06-2026
# Purpose: Handles everything that happens inside a session. Command process, logging.

import json
import os
import shlex
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath

from config import LOG_DIR, FAKE_HOSTNAME, FAKE_USER

from honeypot.fake_fs import (
    FAKE_FILESYSTEM,
    fake_ls,
    fake_cat,
    fake_pwd,
    fake_uname,
    fake_whoami,
    fake_id,
    fake_ifconfig,
)


AUTH_LOG = os.path.join(LOG_DIR, "auth_attempts.jsonl")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_log_dir() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)


def write_jsonl(path: str, entry: dict) -> None:
    ensure_log_dir()

    with open(path, "a", encoding="utf-8") as file:
        file.write(json.dumps(entry, ensure_ascii=False) + "\n")


def log_auth_attempt(peer_addr, username: str, password: str, accepted: bool = True) -> None:
    """Log SSH credential attempts before a shell session exists."""

    peer_ip, peer_port = peer_addr if peer_addr else ("unknown", 0)

    entry = {
        "timestamp": utc_now(),
        "event": "auth_attempt",
        "peer_ip": peer_ip,
        "peer_port": peer_port,
        "username": username,
        "password": password,
        "accepted": accepted,
    }

    write_jsonl(AUTH_LOG, entry)


class SessionHandler:
    def __init__(self, peer_addr):
        peer_addr = peer_addr or ("unknown", 0)

        self.session_id = str(uuid.uuid4())[:8]
        self.peer_ip = peer_addr[0]
        self.peer_port = peer_addr[1]
        self.cwd = "/root"
        self.events = []
        self.closed = False
        self.start_time = datetime.now(timezone.utc)
        self.log_path = os.path.join(LOG_DIR, f"session_{self.session_id}.json")

        ensure_log_dir()
        self._log_event("session_start", "", {"cwd": self.cwd})

    def handle_command(self, raw_input: str) -> str:
        cmd = raw_input.strip()

        if not cmd:
            return ""

        self._log_event("command", cmd)

        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()

        if not parts:
            return ""

        base = parts[0]
        args = parts[1:]

        if base in ("ls", "dir"):
            path = self._resolve_path(args[0]) if args else self.cwd
            return fake_ls(path)

        if base == "cat":
            if not args:
                return "cat: missing operand"
            return fake_cat(self._resolve_path(args[0]))

        if base == "pwd":
            return fake_pwd(self.cwd)

        if base == "cd":
            target = self._resolve_path(args[0]) if args else "/root"

            if target in FAKE_FILESYSTEM:
                self.cwd = target
                self._log_event("cwd_change", target)
                return ""

            return f"cd: {target}: No such file or directory"

        if base == "whoami":
            return fake_whoami()

        if base == "id":
            return fake_id()

        if base == "uname":
            return fake_uname()

        if base in ("ifconfig", "ip"):
            return fake_ifconfig()

        if base in ("wget", "curl"):
            url = self._extract_url(args)

            self._log_event("download_attempt", url, {"command": cmd})

            dropped_name = self._guess_download_name(url, args)

            if dropped_name:
                self._log_event(
                    "file_drop",
                    dropped_name,
                    {
                        "source_url": url,
                        "method": base,
                    },
                )

            host = url.split("/")[2] if "://" in url and len(url.split("/")) > 2 else url
            return f"{base}: unable to resolve host address '{host}'"

        if base in ("python", "python3", "perl", "bash", "sh"):
            self._log_event("interpreter_exec", cmd)
            return ""

        if base in ("chmod", "chown", "chattr"):
            self._log_event("permission_change", cmd)
            return ""

        if base == "crontab" or "/etc/cron" in cmd:
            self._log_event("persistence_attempt", cmd)
            return ""

        if base == "touch":
            for filename in args:
                self._log_event(
                    "file_drop",
                    self._resolve_path(filename),
                    {"method": "touch"},
                )
            return ""

        if ">" in cmd and "echo" in cmd:
            target = cmd.split(">", 1)[1].strip().split()[0]

            self._log_event(
                "file_drop",
                self._resolve_path(target),
                {"method": "redirect"},
            )

            return ""

        if base in ("exit", "logout", "quit"):
            return "__EXIT__"

        if base in ("clear", "reset"):
            return ""

        return f"{base}: command not found"

    def close(self) -> None:
        if self.closed:
            return

        self.closed = True

        duration = int((datetime.now(timezone.utc) - self.start_time).total_seconds())

        self._log_event(
            "session_end",
            f"duration={duration}s",
            {"duration_seconds": duration},
        )

        print(
            f"[SESSION CLOSED] {self.session_id} | "
            f"{self.peer_ip} | {duration}s | {len(self.events)} events"
        )

    def _log_event(self, event_type: str, value: str, extra: dict | None = None) -> None:
        entry = {
            "session_id": self.session_id,
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port,
            "timestamp": utc_now(),
            "event": event_type,
            "value": value,
        }

        if extra:
            entry.update(extra)

        self.events.append(entry)
        write_jsonl(self.log_path, entry)

    def _resolve_path(self, path: str) -> str:
        if not path:
            return self.cwd

        if path.startswith("~"):
            path = path.replace("~", "/root", 1)

        if not path.startswith("/"):
            path = str(PurePosixPath(self.cwd) / path)

        return str(PurePosixPath(path))

    @staticmethod
    def _extract_url(args: list[str]) -> str:
        for arg in args:
            if arg.startswith(("http://", "https://", "ftp://")):
                return arg

        return args[0] if args else ""

    @staticmethod
    def _guess_download_name(url: str, args: list[str]) -> str:
        if "-O" in args:
            index = args.index("-O")

            if index + 1 < len(args):
                return args[index + 1]

        if not url:
            return ""

        name = url.rstrip("/").split("/")[-1]

        return name or "downloaded_file"

