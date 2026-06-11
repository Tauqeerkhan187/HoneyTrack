# Author: TK
# Date: 08-06-2026
# Purpose: listens for connections and accepts credentials.

import asyncio
import os

import asyncssh

from config import (
    HONEYPOT_HOST,
    HONEYPOT_PORT,
    HONEYPOT_BANNER,
    FAKE_HOSTNAME,
    FAKE_USER,
    FAKE_AUTH_DELAY,
)

from honeypot.session_handler import SessionHandler, log_auth_attempt


HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "host_key")


def ensure_host_key() -> None:
    if not os.path.exists(HOST_KEY_PATH):
        print("[*] Generating SSH host key...")
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(HOST_KEY_PATH)
        print(f"[*] Host key saved to {HOST_KEY_PATH}")


class HoneypotSSHServer(asyncssh.SSHServer):
    """Accepts password authentication and logs every credential attempt."""

    def __init__(self):
        self._conn = None
        self._peer_addr = ("unknown", 0)

    def connection_made(self, conn):
        self._conn = conn
        self._peer_addr = conn.get_extra_info("peername") or ("unknown", 0)
        print(f"[+] SSH connection from {self._peer_addr[0]}:{self._peer_addr[1]}")

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        log_auth_attempt(self._peer_addr, username, password, accepted=True)
        print(f"[CRED] {self._peer_addr[0]} tried {username}:{password}")
        await asyncio.sleep(FAKE_AUTH_DELAY)
        return True

    def session_requested(self):
        return HoneypotSSHServerSession(self._peer_addr)


class HoneypotSSHServerSession(asyncssh.SSHServerSession):
    """Handles an interactive fake shell."""

    def __init__(self, peer_addr):
        self._handler = SessionHandler(peer_addr)
        self._input_buf = ""
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan

    def pty_requested(self, term_type, term_size, term_modes):
        return True

    def shell_requested(self):
        return True

    def session_started(self):
        self._chan.write("Welcome to Ubuntu 22.04.3 LTS\r\n")
        self._send_prompt()

    def data_received(self, data, datatype):
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="ignore")

        self._input_buf += data

        while "\n" in self._input_buf:
            line, self._input_buf = self._input_buf.split("\n", 1)
            line = line.replace("\r", "").strip()

            response = self._handler.handle_command(line)

            if response == "__EXIT__":
                self._chan.write("logout\r\n")
                self._handler.close()
                self._chan.exit(0)
                return

            if response:
                self._chan.write(response + "\r\n")

            self._send_prompt()

    def eof_received(self):
        self._handler.close()
        return False

    def connection_lost(self, exc):
        self._handler.close()

    def _send_prompt(self):
        self._chan.write(f"{FAKE_USER}@{FAKE_HOSTNAME}:{self._handler.cwd}# ")


async def start_honeypot():
    ensure_host_key()

    await asyncssh.create_server(
        HoneypotSSHServer,
        HONEYPOT_HOST,
        HONEYPOT_PORT,
        server_host_keys=[HOST_KEY_PATH],
        server_version=HONEYPOT_BANNER,
        encoding="utf-8",
    )

    print(f"[*] HoneyTrack SSH honeypot listening on {HONEYPOT_HOST}:{HONEYPOT_PORT}")

    await asyncio.Future()
