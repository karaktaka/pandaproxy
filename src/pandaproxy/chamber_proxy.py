"""Chamber image proxy for BambuLab camera stream on port 6000.

BambuLab A1/P1 printers expose a camera stream via a custom binary protocol
over TLS on port 6000. This proxy maintains a single connection to the printer
and redistributes JPEG frames to multiple clients using the same protocol.

Protocol details:
- Connection: TLS socket (self-signed cert)
- Authentication: 80-byte binary payload
- Response: 16-byte header + JPEG data, continuously streamed
"""

import asyncio
import contextlib
import logging
import ssl
import struct
from pathlib import Path

from pandaproxy.fanout import StreamFanout
from pandaproxy.helper import (
    close_writer,
    create_auth_payload,
    create_ssl_context,
    parse_auth_payload,
)
from pandaproxy.protocol import CHAMBER_PORT, MAX_PAYLOAD_SIZE

logger = logging.getLogger(__name__)


class ChamberImageProxy:
    """Chamber image fan-out proxy for BambuLab camera stream.

    Connects to the printer's chamber image endpoint (port 6000) via TLS
    and serves multiple clients on the same port with the same protocol.
    """

    def __init__(
        self,
        printer_ip: str,
        access_code: str,
        cert_path: Path,
        key_path: Path,
        bind_address: str = "0.0.0.0",
    ) -> None:
        self.printer_ip = printer_ip
        self.access_code = access_code
        self.cert_path = cert_path
        self.key_path = key_path
        self.bind_address = bind_address
        self.port = CHAMBER_PORT

        self._fanout = StreamFanout(name="chamber_image")
        self._upstream_task: asyncio.Task | None = None
        self._server: asyncio.Server | None = None
        self._running = False
        self._upstream_connected = asyncio.Event()
        self._ssl_context = create_ssl_context()

    async def start(self) -> None:
        """Start the chamber image proxy server."""
        logger.info("Starting chamber image proxy on %s:%d", self.bind_address, self.port)
        self._running = True

        if not self.cert_path.exists() or not self.key_path.exists():
            raise FileNotFoundError(
                f"TLS certificates not found at {self.cert_path} or {self.key_path}. "
                "Please ensure the CLI entry point has generated them."
            )

        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ssl.load_cert_chain(self.cert_path, self.key_path)

        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
            ssl=server_ssl,
        )
        logger.info("Chamber image proxy listening on %s:%d (TLS)", self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the chamber image proxy server."""
        logger.info("Stopping chamber image proxy")
        self._running = False
        self._fanout.stop()

        if self._upstream_task:
            self._upstream_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._upstream_task

        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def run_upstream_loop(self) -> None:
        """Run the upstream connection loop as a standalone coroutine."""
        self._upstream_task = asyncio.create_task(self._upstream_connection_loop())
        with contextlib.suppress(asyncio.CancelledError):
            await self._upstream_task
        logger.debug("Upstream task stopped.")

    async def _upstream_connection_loop(self) -> None:
        """Maintain connection to printer chamber image stream, reconnecting on failure."""
        while self._running:
            reader: asyncio.StreamReader | None = None
            writer: asyncio.StreamWriter | None = None

            try:
                logger.info(
                    "Connecting to printer chamber image at %s:%d", self.printer_ip, self.port
                )

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.printer_ip,
                        self.port,
                        ssl=self._ssl_context,
                    ),
                    timeout=10.0,
                )

                logger.info("Connected to printer chamber image stream")

                # Send authentication
                auth_payload = create_auth_payload(self.access_code)
                writer.write(auth_payload)
                await writer.drain()
                logger.debug("Sent authentication payload")

                self._fanout.start()
                self._upstream_connected.set()

                # Continuously read frames and broadcast
                while self._running:
                    # Read 16-byte header
                    header = await asyncio.wait_for(reader.readexactly(16), timeout=30.0)

                    # Parse payload size (little-endian uint32 at offset 0)
                    payload_size = struct.unpack("<I", header[0:4])[0]

                    if payload_size == 0 or payload_size > MAX_PAYLOAD_SIZE:
                        logger.error("Invalid payload size: %d", payload_size)
                        break

                    # Read JPEG data
                    jpeg_data = await asyncio.wait_for(
                        reader.readexactly(payload_size),
                        timeout=30.0,
                    )

                    # Broadcast header + jpeg to all clients (same format as printer sends)
                    await self._fanout.broadcast([header, jpeg_data])

            except TimeoutError:
                logger.warning("Upstream connection timeout")
            except asyncio.IncompleteReadError as e:
                logger.warning(
                    "Upstream connection closed: incomplete read (%d bytes)", len(e.partial)
                )
            except ConnectionRefusedError:
                logger.error("Connection refused by printer")
            except Exception as e:
                logger.error("Upstream connection error: %s", e)
            finally:
                self._upstream_connected.clear()
                self._fanout.stop()

                if writer:
                    await close_writer(writer)

            if self._running:
                logger.info("Reconnecting to printer in 5 seconds...")
                await asyncio.sleep(5)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming client connection."""
        client_addr = writer.get_extra_info("peername")
        logger.info("Client connected from %s", client_addr)

        try:
            # Wait for client to send 80-byte auth payload
            try:
                auth_data = await asyncio.wait_for(reader.readexactly(80), timeout=10.0)
            except TimeoutError:
                logger.warning("Client %s auth timeout", client_addr)
                return
            except asyncio.IncompleteReadError:
                logger.warning("Client %s disconnected during auth", client_addr)
                return

            # Validate access code
            client_access_code = parse_auth_payload(auth_data)
            if client_access_code != self.access_code:
                logger.warning("Client %s authentication failed", client_addr)
                return

            logger.info("Client %s authenticated", client_addr)

            # Wait for upstream to be connected
            if not self._upstream_connected.is_set():
                logger.info("Waiting for upstream connection...")
                try:
                    await asyncio.wait_for(self._upstream_connected.wait(), timeout=30.0)
                except TimeoutError:
                    logger.warning("Upstream connection timeout for client %s", client_addr)
                    return

            # Register client with fanout
            client = await self._fanout.register_client(str(client_addr))

            try:
                # Send frames to client
                while self._running and client.connected:
                    data = await client.receive()
                    if data is None:
                        break
                    try:
                        if isinstance(data, list):
                            for chunk in data:
                                writer.write(chunk)
                                await writer.drain()
                        else:
                            writer.write(data)
                            await writer.drain()
                    except (ConnectionResetError, BrokenPipeError):
                        break
            finally:
                await self._fanout.unregister_client(client)

        except Exception as e:
            logger.error("Client %s error: %s", client_addr, e)
        finally:
            logger.info("Client %s disconnected", client_addr)
            await close_writer(writer)


# Alias for backward compatibility
WebSocketProxy = ChamberImageProxy
