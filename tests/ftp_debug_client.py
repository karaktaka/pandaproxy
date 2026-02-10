#!/usr/bin/env python3
"""FTP Debug Client - Diagnose FTP connectivity issues with PandaProxy.

This script simulates different FTP client behaviors to help debug
compatibility issues with clients like OctoApp and Bambuddy.

Usage:
    python tests/ftp_debug_client.py --host 127.0.0.1 --port 990 --user bblp --pass ACCESS_CODE

    # Test different client behaviors:
    python tests/ftp_debug_client.py --host 127.0.0.1 --port 990 --user bblp --pass CODE --mode octoapp
    python tests/ftp_debug_client.py --host 127.0.0.1 --port 990 --user bblp --pass CODE --mode bambuddy
    python tests/ftp_debug_client.py --host 127.0.0.1 --port 990 --user bblp --pass CODE --mode aggressive
"""

import argparse
import asyncio
import contextlib
import logging
import ssl
import sys
from dataclasses import dataclass
from datetime import datetime

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class FTPResponse:
    """Parsed FTP response."""

    code: int
    message: str
    raw: bytes

    @classmethod
    def parse(cls, data: bytes) -> "FTPResponse":
        text = data.decode("utf-8", errors="replace").strip()
        try:
            code = int(text[:3])
        except (ValueError, IndexError):
            code = 0
        return cls(code=code, message=text, raw=data)


class FTPDebugClient:
    """Debug FTP client that logs all interactions."""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.ssl_session: ssl.SSLSession | None = None
        self.command_log: list[tuple[str, str, float]] = []  # (direction, data, timestamp)

    async def connect(self) -> bool:
        """Connect to FTP server with implicit TLS."""
        logger.info("=" * 60)
        logger.info("Connecting to %s:%d (implicit FTPS)", self.host, self.port)
        logger.info("=" * 60)

        # Create SSL context that accepts self-signed certs
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            start = asyncio.get_event_loop().time()
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ssl_ctx),
                timeout=10.0,
            )
            elapsed = asyncio.get_event_loop().time() - start
            logger.info("✅ TLS connection established in %.3fs", elapsed)

            # Extract SSL session for potential reuse
            ssl_obj = self.writer.get_extra_info("ssl_object")
            if ssl_obj:
                self.ssl_session = ssl_obj.session
                session_id = "None"
                if ssl_obj.session and ssl_obj.session.id:
                    session_id = ssl_obj.session.id.hex()[:16] + "..."
                logger.info("📋 SSL session ID: %s", session_id)
                logger.info("📋 SSL version: %s", ssl_obj.version())
                logger.info("📋 SSL cipher: %s", ssl_obj.cipher())

            # Read welcome message
            response = await self._read_response()
            if response.code != 220:
                logger.error("❌ Unexpected welcome: %s", response.message)
                return False

            return True

        except TimeoutError:
            logger.error("❌ Connection timeout after 10s")
            return False
        except Exception as e:
            logger.error("❌ Connection failed: %s", e)
            return False

    async def _send_command(self, cmd: str, mask_password: bool = True) -> None:
        """Send a command to the FTP server."""
        display_cmd = "PASS ****" if mask_password and cmd.startswith("PASS ") else cmd
        timestamp = datetime.now().timestamp()
        self.command_log.append(("C->S", display_cmd, timestamp))
        logger.info(">>> %s", display_cmd)

        self.writer.write(f"{cmd}\r\n".encode())
        await self.writer.drain()

    async def _read_response(self, timeout: float = 10.0) -> FTPResponse:
        """Read a response from the FTP server."""
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
            response = FTPResponse.parse(data)
            timestamp = datetime.now().timestamp()
            self.command_log.append(("S->C", response.message, timestamp))
            logger.info("<<< %s", response.message)
            return response
        except TimeoutError:
            logger.error("❌ Response timeout after %.1fs", timeout)
            raise

    async def login(self) -> bool:
        """Perform FTP login."""
        logger.info("-" * 40)
        logger.info("Logging in as '%s'", self.username)
        logger.info("-" * 40)

        await self._send_command(f"USER {self.username}")
        response = await self._read_response()
        if response.code not in (230, 331):
            logger.error("❌ USER failed: %s", response.message)
            return False

        if response.code == 331:
            await self._send_command(f"PASS {self.password}")
            response = await self._read_response()
            if response.code != 230:
                logger.error("❌ PASS failed: %s", response.message)
                return False

        logger.info("✅ Login successful")
        return True

    async def test_pasv(self) -> dict | None:
        """Test PASV command and parse response."""
        logger.info("-" * 40)
        logger.info("Testing PASV (Passive Mode)")
        logger.info("-" * 40)

        await self._send_command("PASV")
        response = await self._read_response()

        if response.code != 227:
            logger.error("❌ PASV failed: %s", response.message)
            return None

        # Parse PASV response: 227 ... (h1,h2,h3,h4,p1,p2)
        import re

        match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response.message)
        if not match:
            logger.error("❌ Could not parse PASV response")
            return None

        h1, h2, h3, h4, p1, p2 = map(int, match.groups())
        ip = f"{h1}.{h2}.{h3}.{h4}"
        port = p1 * 256 + p2

        logger.info("✅ PASV: %s:%d", ip, port)
        return {"ip": ip, "port": port}

    async def test_epsv(self) -> dict | None:
        """Test EPSV command (Extended Passive Mode)."""
        logger.info("-" * 40)
        logger.info("Testing EPSV (Extended Passive Mode)")
        logger.info("-" * 40)

        await self._send_command("EPSV")
        response = await self._read_response()

        if response.code == 502:
            logger.info("ℹ️  EPSV not implemented (expected for proxy)")
            return None
        elif response.code == 229:
            # Parse: 229 ... (|||PORT|)
            import re

            match = re.search(r"\(\|\|\|(\d+)\|\)", response.message)
            if match:
                port = int(match.group(1))
                logger.info("✅ EPSV port: %d", port)
                return {"port": port}

        logger.warning("⚠️  Unexpected EPSV response: %s", response.message)
        return None

    async def test_features(self) -> list[str]:
        """Test FEAT command to list server features."""
        logger.info("-" * 40)
        logger.info("Testing FEAT (Features)")
        logger.info("-" * 40)

        await self._send_command("FEAT")

        features = []
        while True:
            response = await self._read_response()
            if response.code == 211:
                if "End" in response.message:
                    break
            elif response.code == 500 or response.code == 502:
                logger.info("ℹ️  FEAT not supported")
                break

            # Parse feature line (starts with space)
            if response.message.startswith(" "):
                feat = response.message.strip()
                features.append(feat)
                logger.info("  Feature: %s", feat)

        return features

    async def test_syst(self) -> str | None:
        """Test SYST command."""
        await self._send_command("SYST")
        response = await self._read_response()
        if response.code == 215:
            return response.message
        return None

    async def test_pwd(self) -> str | None:
        """Test PWD command."""
        await self._send_command("PWD")
        response = await self._read_response()
        if response.code == 257:
            return response.message
        return None

    async def quit(self) -> None:
        """Send QUIT and close connection."""
        logger.info("-" * 40)
        logger.info("Closing connection")
        logger.info("-" * 40)

        try:
            await self._send_command("QUIT")
            await self._read_response(timeout=5.0)
        except Exception:
            pass

        if self.writer:
            self.writer.close()
            with contextlib.suppress(Exception):
                await self.writer.wait_closed()

        logger.info("✅ Connection closed")

    def print_summary(self) -> None:
        """Print session summary."""
        logger.info("")
        logger.info("=" * 60)
        logger.info("SESSION SUMMARY")
        logger.info("=" * 60)
        logger.info("Total commands: %d", len([c for c in self.command_log if c[0] == "C->S"]))
        logger.info("Total responses: %d", len([c for c in self.command_log if c[0] == "S->C"]))

        if len(self.command_log) >= 2:
            duration = self.command_log[-1][2] - self.command_log[0][2]
            logger.info("Session duration: %.3fs", duration)


async def run_standard_test(client: FTPDebugClient) -> None:
    """Run standard FTP test sequence."""
    if not await client.connect():
        return

    if not await client.login():
        await client.quit()
        return

    await client.test_syst()
    await client.test_pwd()
    await client.test_features()
    await client.test_epsv()
    await client.test_pasv()
    await client.quit()
    client.print_summary()


async def run_octoapp_simulation(client: FTPDebugClient) -> None:
    """Simulate OctoApp-like FTP behavior.

    OctoApp may use specific command sequences or timing that differs
    from standard FTP clients.
    """
    logger.info("🔧 Simulating OctoApp-style FTP behavior")

    if not await client.connect():
        return

    if not await client.login():
        await client.quit()
        return

    # OctoApp might send commands in quick succession
    await client._send_command("TYPE I")
    await client._read_response()

    await client._send_command("PWD")
    await client._read_response()

    # Try EPSV first (some modern clients prefer this)
    await client._send_command("EPSV")
    response = await client._read_response()

    if response.code == 502:
        # Fallback to PASV
        logger.info("ℹ️  EPSV blocked, falling back to PASV")
        await client._send_command("PASV")
        await client._read_response()

    # Simulate directory listing attempt
    await client._send_command("CWD /")
    await client._read_response()

    await client.quit()
    client.print_summary()


async def run_bambuddy_simulation(client: FTPDebugClient) -> None:
    """Simulate Bambuddy-like FTP behavior.

    Bambuddy works with FTP but is slow initially - let's see why.
    """
    logger.info("🔧 Simulating Bambuddy-style FTP behavior")

    if not await client.connect():
        return

    if not await client.login():
        await client.quit()
        return

    # Bambuddy might have different timing
    await asyncio.sleep(0.5)  # Simulate slower client

    await client._send_command("SYST")
    await client._read_response()

    await asyncio.sleep(0.2)

    await client._send_command("FEAT")
    # Read multi-line FEAT response
    while True:
        response = await client._read_response()
        if response.code == 211 and "End" in response.message:
            break
        if response.code in (500, 502):
            break

    await client._send_command("TYPE I")
    await client._read_response()

    await client._send_command("PASV")
    await client._read_response()

    await client.quit()
    client.print_summary()


async def run_aggressive_test(client: FTPDebugClient) -> None:
    """Run aggressive test with rapid commands (stress test)."""
    logger.info("🔧 Running aggressive/rapid command test")

    if not await client.connect():
        return

    if not await client.login():
        await client.quit()
        return

    # Send multiple commands rapidly without waiting
    commands = ["SYST", "PWD", "TYPE I", "PASV"]

    for cmd in commands:
        await client._send_command(cmd)

    # Now read all responses
    for _ in commands:
        await client._read_response()

    await client.quit()
    client.print_summary()


async def main():
    parser = argparse.ArgumentParser(description="FTP Debug Client for PandaProxy")
    parser.add_argument("--host", required=True, help="FTP server host")
    parser.add_argument("--port", type=int, default=990, help="FTP server port")
    parser.add_argument("--user", default="bblp", help="FTP username")
    parser.add_argument("--pass", dest="password", required=True, help="FTP password (access code)")
    parser.add_argument(
        "--mode",
        choices=["standard", "octoapp", "bambuddy", "aggressive"],
        default="standard",
        help="Test mode to simulate different client behaviors",
    )

    args = parser.parse_args()

    client = FTPDebugClient(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
    )

    if args.mode == "standard":
        await run_standard_test(client)
    elif args.mode == "octoapp":
        await run_octoapp_simulation(client)
    elif args.mode == "bambuddy":
        await run_bambuddy_simulation(client)
    elif args.mode == "aggressive":
        await run_aggressive_test(client)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(1)
