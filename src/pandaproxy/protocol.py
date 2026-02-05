"""BambuLab protocol constants and utilities.

Shared utilities for camera proxies, MQTT proxy, and detection modules.
"""

import asyncio
import contextlib
import ssl
import struct

# Protocol ports
RTSP_PORT = 322
CHAMBER_PORT = 6000
MQTT_PORT = 8883


# Chamber image protocol constants
AUTH_MAGIC = 0x40
AUTH_COMMAND = 0x3000
MAX_PAYLOAD_SIZE = 10_000_000  # 10MB sanity limit


def create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context that verifies BambuLab printer certificates.

    Uses the bundled printer.cer CA certificates to verify the printer's identity.
    """
    from importlib.resources import files

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Load the bundled CA certificates
    cert_path = files("pandaproxy").joinpath("printer.cer")
    ctx.load_verify_locations(str(cert_path))

    return ctx


def create_auth_payload(access_code: str) -> bytes:
    """Create the 80-byte authentication payload for chamber image protocol.

    Format:
    - Bytes 0-3: 0x40 0x00 0x00 0x00 (magic)
    - Bytes 4-7: 0x00 0x30 0x00 0x00 (command)
    - Bytes 8-15: zeros (padding)
    - Bytes 16-47: username "bblp" (32 bytes, null-padded)
    - Bytes 48-79: access code (32 bytes, null-padded)
    """
    username = b"bblp"
    access_code_bytes = access_code.encode("utf-8")

    return struct.pack(
        "<II8s32s32s",
        AUTH_MAGIC,
        AUTH_COMMAND,
        b"\x00" * 8,
        username.ljust(32, b"\x00"),
        access_code_bytes.ljust(32, b"\x00"),
    )


def parse_auth_payload(data: bytes) -> str | None:
    """Parse authentication payload and extract access code.

    Returns the access code if valid, None otherwise.
    """
    if len(data) != 80:
        return None

    try:
        magic, command, _, username, access_code = struct.unpack("<II8s32s32s", data)

        if magic != AUTH_MAGIC or command != AUTH_COMMAND:
            return None

        # Strip null padding from access code
        return access_code.rstrip(b"\x00").decode("utf-8")
    except (struct.error, UnicodeDecodeError):
        return None


def create_server_ssl_context() -> ssl.SSLContext:
    """Create SSL context for server side with self-signed cert."""
    import os
    import subprocess
    import tempfile

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Create temporary files for cert and key
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(suffix=".pem")
    os.close(cert_fd)
    os.close(key_fd)

    try:
        # Generate self-signed certificate
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=PandaProxy",
            ],
            check=True,
            capture_output=True,
        )

        ctx.load_cert_chain(cert_path, key_path)
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)

    return ctx


async def close_writer(writer: asyncio.StreamWriter) -> None:
    """Safely close an asyncio StreamWriter."""
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
