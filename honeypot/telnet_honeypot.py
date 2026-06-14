# Author: TK
# Date: 14-06-2026
# Purpose: Telnet honeypot listener. Reuses SessionHandler for the fake shell,
# so SSH and Telnet share identical command handling and logging.

import asyncio

from config import TELNET_HOST, TELNET_PORT, FAKE_HOSTNAME, FAKE_USER
from honeypot.session_handler import SessionHandler, log_auth_attempt


# Telnet protocol bytes (RFC 854)
IAC = 225   # Interpret as command
SE = 240    # Subnegotiation end
SB = 250    # Subnegotiation begin
WILL = 251
WONT = 252
DO = 253
DONT = 254



def strip_telnet_negotiation(data: bytes) -> bytes:
    """Remove Telnet IAC command/negotiation sequences from a byte stream.

    Real Telnet clients interleave option-negotiation commands with the
    actual keystrokes. We strip them so the SessionHandler only ever sees
    clean command text.
    """
    out = bytearray()
    i = 0
    length = len(data)

    while i < length:
        byte = data[i]

        if byte == IAC:
            if i + 1 >= length:
                break

            command = data[i + 1]

            if command in (WILL, WONT, DO, DONT):
                i +=3       # IAC + command + option
                continue

            if comand == SB:     # subnegotiation: skip until IAC SE
                j = i + 2
                while j + 1 < length and not (data[j] == IAC and data [j + 1 == SE]):
                    j += 1
                i = j +2
                continue

            i += 2          # IAC + command (e.g IAC NOP)
            continue

        out.append(byte)
        i += 1

    return bytes(out)


class TelnetSession:
    """Drives one Telnet connection through the shared SessionHandler."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername") or ("unknown", 0)
        self.handler = None

    async def send(self, text: str) -> None:
        self.writer.write(text.encode("utf-8", errors="ignore"))
        await self.writer.drain()

    async def read_line(self) -> str:
        raw = await self.reader.readuntil(b"\n")
        clean = strip_telnet_negotiation(raw)
        return clean.decode("utf-8", errors="ignore").replace("\r", "").strip()

    def _prompt(self) -> str:
        return f"{FAKE_USER}@{FAKE_HOSTNAME}:{self.handler.cwd}# "

    async def run(self) -> None:
        print(f"[+] Telnet connection from {self.peer[0]}:{self.peer[1]}")

        try:
            # Fake login flow
            await self.send("\r\nUbuntu 22.04.3 LTS\r\n")
            await self.send(f"{FAKE_HOSTNAME} login: ")
            username = await self.read_line()

            await self.send("Password: ")
            password = await self.read_line()

            log_auth_attempt(self.peer, username, password, accepted=True)
            print(f"[CRED] {self.peer[0]} tried {username}:{password} (telnet)")

            await self.send("\r\nWelcome to Ubuntu 22.04.3 LTS\r\n")

            self.handler = SessionHandler(self.peer, protocol="telnet")
            await self.send(self._prompt())

            # Command loop
            while True:
                line = await self.read_line()
                result = self.handler.handle_command(line)

                if result == "__EXIT__":
                    await self.send("logout\r\n")
                    break

                if result:
                    await self.send(result.replace("\n", "\r\n") + "\r\n")

                await self.send(self._prompt())

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass

        finally:
            if self.handler:
                self.handler.close()
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass


async def handle_telnet_client(reader, writer):
    session = TelnetSession(reader, writer)
    await session.run()


async def start_telnet_honeypot():
    server = await asyncio.start_server(
        handle_telnet_client,
        TELNET_HOST,
        TELNET_PORT,
    )
    print(f"[*] HoneyTrack Telnet honeypot listening on {TELNET_HOST}:{TELNET_PORT}")

    async with server:
        await server.serve_forever()

