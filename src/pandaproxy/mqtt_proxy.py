"""MQTT proxy for BambuLab printer control and status on port 8883.

BambuLab printers expose an MQTT interface via MQTTS (MQTT over TLS) on port 8883.
This proxy uses a custom paho-mqtt based implementation to forward all MQTT messages
bidirectionally, acting as a transparent man-in-the-middle.

Protocol details:
- Connection: TLS socket (self-signed cert for clients, printer.cer for upstream)
- Authentication: MQTT CONNECT with username "bblp" and access code as password
- Messages: All MQTT messages forwarded transparently via broker bridge
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path

from pandaproxy.helper import close_writer
from pandaproxy.protocol import MQTT_PORT

logger = logging.getLogger(__name__)

# Keepalive interval (seconds)
MQTT_KEEPALIVE = 60


class MQTTProxy:
    """MQTT proxy for BambuLab printer control and status.

    Uses a simple TCP proxy with TLS termination to accept client connections
    and forward traffic to the printer.
    """

    def __init__(
        self,
        printer_ip: str,
        access_code: str,
        serial_number: str,
        cert_path: Path,
        key_path: Path,
        bind_address: str = "0.0.0.0",
    ) -> None:
        self.printer_ip = printer_ip
        self.access_code = access_code
        self.serial_number = serial_number
        self.cert_path = cert_path
        self.key_path = key_path
        self.bind_address = bind_address
        self.port = MQTT_PORT

        self._running = False
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the MQTT proxy."""
        logger.info("Starting MQTT proxy on %s:%d", self.bind_address, self.port)
        self._running = True

        if not self.cert_path.exists() or not self.key_path.exists():
            raise FileNotFoundError(
                f"TLS certificates not found at {self.cert_path} or {self.key_path}. "
                "Please ensure the CLI entry point has generated them."
            )

        # Create SSL context for the server
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        # Start the TCP server
        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
            ssl=ssl_context,
        )

        logger.info("MQTT proxy started on %s:%d (TLS)", self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the MQTT proxy."""
        logger.info("Stopping MQTT proxy")
        self._running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        logger.info("MQTT proxy stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection."""
        peer_addr = writer.get_extra_info("peername")
        logger.info("New MQTT connection from %s", peer_addr)

        printer_writer = None
        try:
            # Connect to the printer
            printer_reader, printer_writer = await self._connect_to_printer()

            # Create tasks to forward data in both directions
            client_to_printer = asyncio.create_task(
                self._forward_stream(reader, printer_writer, "client->printer")
            )
            printer_to_client = asyncio.create_task(
                self._forward_stream(printer_reader, writer, "printer->client")
            )

            # Wait for either task to finish (connection closed)
            done, pending = await asyncio.wait(
                [client_to_printer, printer_to_client], return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel pending tasks
            for task in pending:
                task.cancel()

            # Wait for cancelled tasks to finish cleaning up
            await asyncio.gather(*pending, return_exceptions=True)

        except Exception as e:
            logger.error("Error handling client %s: %s", peer_addr, e)
        finally:
            await close_writer(writer)
            if printer_writer:
                await close_writer(printer_writer)
            logger.info("Connection from %s closed", peer_addr)

    async def _connect_to_printer(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to the printer's MQTT port."""
        ca_file = self._get_ca_file()

        # Create SSL context for printer connection
        printer_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        printer_ssl_context.load_verify_locations(ca_file)
        printer_ssl_context.check_hostname = False
        printer_ssl_context.verify_mode = ssl.CERT_REQUIRED

        return await asyncio.open_connection(
            self.printer_ip,
            self.port,
            ssl=printer_ssl_context,
        )

    async def _forward_stream(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str
    ) -> None:
        """Forward data from reader to writer."""
        try:
            while self._running:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("Error forwarding %s: %s", direction, e)
        finally:
            await close_writer(writer)

    @staticmethod
    def _get_ca_file() -> str:
        """Get the path to the printer CA certificate."""
        from importlib.resources import files

        cert_path = files("pandaproxy").joinpath("printer.cer")
        return str(cert_path)
