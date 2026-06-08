# Author: TK
# Date: 08-06-2026
# Purpose: listens for connections and accepts credentials

import asyncio
import asyncssh
import os
from datetime import datetime
from honeypot.session_handler import SessionHandler
from config import (
    HONEYPOT_HOST, HONEYPOT_PORT, HONEYPOT_BANNER,
    FAKE_HOSTNAME, FAKE_USER, FAKE_AUTH_DELAY
)

# Generate a host key if one doesn't exist.
HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "host_key")


def ensure_host_key():
    if not os.path.exists(HOST_KEY_PATH):
        print("[*] Generating SSH host key...")
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(HOST_KEY_PATH)
        print(f"[*] Host key saved to {HOST_KEY_PATH}")


class HoneypotSSHServer(asyncssh.SSHServer):
    """Accepts all authentication attempts."""

    def __init__(self):
        self._peer_addr = None

    def connection_made(self, conn):
        self._peer_addr = conn.get_extra_info("peername")
        print(f"[+] Connection from {self._peer_addr[0]}:{self._peer_addr[1]}")

    def connection_lost(self, exc):
        pass

    def begin_auth(self, username):
        # Accept all usrnames, move to passwrd check
        return True

    def passwrd_auth_supported(self):
        return True

    async def validate_passwrd(self, username, password):
        # Log the credential attempt
        print(f"[CRED] {self._peer_addr[0]} tried {username}:{password}")
        await asyncio.sleep(FAKE_AUTH_DELAY) # simulate real auth delay
        return True # accept everything

class HoneypotSSHServerSession(asyncssh.SSHServerSession):
    """Handles an interactive shell session."""

    def __init__(self, peer_addr):
        self._handler = SessionHandler(peer_addr)
        self._input_buf = ""

    def shell_requested(self):
        return True

    def session_started(self):
        self._send_prompt()

    def data_received(self, data, datatype):
        self.input_buf += data
        # process line by line
        while "\n" in self._input_buf:
            line, self._input_buf = self._input_buf.split("\n", 1)
            line = line.replace("\r", "").strip()
            response = self._handler.handle_command(line)
            if response == "__EXIT__":
                self._chan.write("logout\r\n")
                self._chan.exit(0)
                self._handler.close()
                return
            if response:
                self._chan.write(response + "\r\n")
            self._send_prompt()

    def _send_prompt(self):
        self._chan.write(f"{FAKE_USER}@{FAKE_HOSTNAME}:{self._handler.cwd}# ")

    def eof_received(self):
        self._handler.close()
        return False

    def connection_lost(self, exc):
        self._handler.close()

async def start_honeypot():
    ensure_host_key()

    def server_factory():
        return HoneypotSSHServer()

    def session_factory(peer_addr):
        return lambda: HoneypotSSHServerSession(peer_addr)

    # Patch: pass peer_addr into session
    class PeerAwareServer(HoneypotSSHServer):
        def __init__(self):
            super().__init__()

        def connection_made(self, conn):
            super().connection_made(conn)
            self._conn = conn

        def session_requested(self, channel, request, *args, **kwargs):
            peer = self._conn.get_extra_info("peername")
            return HoneypotSSHServerSession(peer)

    await asyncssh.create_server(
        PeerAwareServer,
        HONEYPOT_HOST,
        HONEYPOT_PORT,
        server_host_keys=[HOST_KEY_PATH],
        process_factory=None,
        allow_pty=True,
    )
    print(f"[*] HoneyTrack SSH honeypot listening on {HONEYPOT_HOST}: {HONEYPOT_PORT}")
    await asyncio.Future() # Runs forever


