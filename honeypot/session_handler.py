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
from shell_utils import split_compound

from honeypot.fake_fs import (
    FAKE_FILESYSTEM,
    FAKE_USERS,
    fake_ls,
    fake_cat,
    fake_pwd,
    fake_uname,
    fake_whoami,
    fake_id,
    fake_ifconfig,
    fake_ps,
    fake_netstat,
    fake_ss,
    fake_w,
    fake_who,
    fake_last,
    fake_uptime,
    fake_env,
    fake_free,
    fake_df,
    expand_vars,
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
    def __init__(self, peer_addr, protocol="ssh"):
        peer_addr = peer_addr or ("unknown", 0)

        self.session_id = str(uuid.uuid4())[:8]
        self.peer_ip = peer_addr[0]
        self.peer_port = peer_addr[1]
        self.cwd = "/root"
        self.protocol = protocol
        self.events = []
        self.closed = False
        self.start_time = datetime.now(timezone.utc)
        self.log_path = os.path.join(LOG_DIR, f"session_{self.session_id}.json")

        ensure_log_dir()
        self._log_event("session_start", "", {"cwd": self.cwd, "protocol": protocol})

    def handle_command(self, raw_input: str) -> str:
        """Handle a full command line, splitting compound commands.

        The full line is logged once as a 'command' event (so the dashboard
        shows what the attacker actually typed). Each sub-command is then run
        through the dispatcher so chained commands behave like a real shell
        and every specialized event (downloads, file drops, etc.) still fires.
        """
        line = raw_input.strip()

        if not line:
            return ""

        self._log_event("command", line)

        sub_commands = split_compound(line)

        outputs = []
        for sub in sub_commands:
            result = self._handle_single(sub)
            if result == "__EXIT__":
                return "__EXIT__"
            if result:
                outputs.append(result)

        return "\n".join(outputs)

    def _handle_single(self, raw_input: str, as_user: str = "root") -> str:
        """Handle ONE already split sub-command, acting as `as_user`.

        `as_user` is normally "root". It changes only when a command is
        re-dispatched through `sudo -u <user>`, so identity-aware commands
        (whoami, id, echo $HOME) answer as that user. It is per-call, so the
        identity never leaks into the next command -- same as real sudo.
        """
        cmd = raw_input.strip()

        if not cmd:
            return ""

        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()

        if not parts:
            return ""

        base = parts[0]
        args = parts[1:]

        # --- sudo -------------------------------------------------------
        # On a root shell, `sudo <cmd>` is just `<cmd>`. Strip the prefix and
        # re-dispatch so every wrapped command keeps its normal behaviour and
        # its ATT&CK logging, without special-casing each one.
        # NOTE: this must stay first -- it re-enters this method.
        if base == "sudo":
            self._log_event("privilege_escalation", cmd, {"technique": "sudo"})

            # sudo with no arguments -> usage text
            if not args:
                return ("usage: sudo [-h] [-K] [-k] [-V]\n"
                        "usage: sudo -l [-U user] [command]\n"
                        "usage: sudo [-u user] command")

            # sudo -l -> list privileges (root may do everything)
            if args[0] in ("-l", "--list"):
                return ("Matching Defaults entries for root on ubuntu-server:\n"
                        "    env_reset, mail_badpass,\n"
                        "    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:"
                        "/usr/bin\\:/sbin\\:/bin\n\n"
                        "User root may run the following commands on ubuntu-server:\n"
                        "    (ALL : ALL) ALL")

            # sudo su / sudo -i / sudo -s -> already root, stay at the shell
            if args[0] in ("su", "-i", "-s"):
                self._log_event("interpreter_exec", cmd, {"shell": "root"})
                return ""

            # sudo -u <user> <cmd> -> run the rest AS that user
            target_user = "root"
            rest = args

            if rest[0] in ("-u", "--user") and len(rest) >= 2:
                target_user = rest[1]
                rest = rest[2:]

                if target_user not in FAKE_USERS:
                    return f"sudo: unknown user {target_user}"

            if rest:
                return self._handle_single(" ".join(rest), as_user=target_user)

            return ""

        # --- filesystem -------------------------------------------------
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

        # --- identity ---------------------------------------------------
        if base == "whoami":
            return fake_whoami(as_user)

        if base == "id":
            return fake_id(as_user)

        if base == "uname":
            return fake_uname()

        if base in ("ifconfig", "ip"):
            return fake_ifconfig()

        # --- ingress / execution / persistence --------------------------
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

        # --- recon ------------------------------------------------------
        if base == "ps":
            return fake_ps(args)

        if base == "netstat":
            return fake_netstat(args)

        if base == "ss":
            return fake_ss(args)

        if base == "w":
            return fake_w(self.peer_ip)

        if base == "who":
            return fake_who(self.peer_ip)

        if base == "last":
            return fake_last(self.peer_ip)

        if base == "uptime":
            return fake_uptime()

        if base in ("env", "printenv"):
            return fake_env(self.cwd, as_user)

        if base == "free":
            return fake_free(args)

        if base == "df":
            return fake_df(args)

        if base == "history":
            commands = [e["value"] for e in self.events if e.get("event") == "command"]
            return "\n".join(f"{i:5}  {c}" for i, c in enumerate(commands, 1))

        # --- output redirection -----------------------------------------
        # Must stay AHEAD of the plain `echo` branch so that
        # `echo pwned > /root/.ssh/authorized_keys` is logged as a file drop
        # rather than being swallowed as ordinary echo output.
        if ">" in cmd and "echo" in cmd:
            target = cmd.split(">", 1)[1].strip().split()[0]

            self._log_event(
                "file_drop",
                self._resolve_path(target),
                {"method": "redirect"},
            )

            return ""

        if base == "echo":
            return expand_vars(" ".join(args), self.cwd, as_user)

        # --- session ----------------------------------------------------
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

