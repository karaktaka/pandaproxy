"""MQTT multiplexing proxy for BambuLab printers on port 8883.

Maintains a single MQTT connection to the printer (via aiomqtt) and accepts
multiple client connections, fanning out printer messages to all clients and
forwarding client commands to the printer.

Architecture:
- Upstream (printer): Single persistent aiomqtt client with auto-reconnect.
  Subscribes to all topics (#) and publishes client commands.
- Clients: TLS server accepting MQTT connections. Each client's CONNECT,
  SUBSCRIBE, PINGREQ, and DISCONNECT are handled locally by the proxy.
  PUBLISH messages from clients are forwarded to the upstream printer.
  PUBLISH messages from the printer are broadcast to all connected clients.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from pathlib import Path

import aiomqtt

from pandaproxy.helper import close_writer, create_ssl_context
from pandaproxy.mqtt_protocol import (
    CONNACK_ACCEPTED,
    CONNACK_NOT_AUTHORIZED,
    PacketType,
    build_connack,
    build_pingresp,
    build_puback,
    build_publish,
    build_suback,
    build_unsuback,
    parse_connect,
    parse_publish,
    parse_subscribe,
    parse_unsubscribe,
    read_packet,
)
from pandaproxy.protocol import MQTT_PORT

logger = logging.getLogger(__name__)

# Keepalive interval for the upstream printer connection (seconds)
UPSTREAM_KEEPALIVE = 60

# How long to wait before reconnecting to the printer after a failure
RECONNECT_DELAY = 5

# Maximum queued packets per client before disconnecting slow clients
CLIENT_QUEUE_SIZE = 200

# Timeout for initial client MQTT CONNECT handshake
CLIENT_CONNECT_TIMEOUT = 10.0

# Timeout for upstream connection establishment
UPSTREAM_CONNECT_TIMEOUT = 10.0

# How long clients wait for upstream to become available
UPSTREAM_WAIT_TIMEOUT = 30.0


class MQTTProxy:
    """MQTT multiplexing proxy for BambuLab printers.

    Maintains one upstream MQTT connection to the printer and fans out
    messages to multiple connected clients.
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

        # Upstream state
        self._upstream_client: aiomqtt.Client | None = None
        self._upstream_connected = asyncio.Event()
        self._upstream_lock = asyncio.Lock()
        self._upstream_task: asyncio.Task | None = None

        # Client tracking: client_id -> asyncio.Queue
        self._clients: dict[str, asyncio.Queue[bytes | None]] = {}
        self._clients_lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the MQTT proxy server (TLS listener for clients)."""
        logger.info("Starting MQTT proxy on %s:%d", self.bind_address, self.port)
        self._running = True

        if not self.cert_path.exists() or not self.key_path.exists():
            raise FileNotFoundError(
                f"TLS certificates not found at {self.cert_path} or {self.key_path}. "
                "Please ensure the CLI entry point has generated them."
            )

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
            ssl=ssl_context,
        )

        logger.info("MQTT proxy started on %s:%d (TLS)", self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the MQTT proxy.

        Shutdown order matters: stop clients first (so they stop publishing
        to upstream), then disconnect the upstream aiomqtt client. This
        prevents paho-mqtt internal futures from going unhandled.
        """
        logger.info("Stopping MQTT proxy")
        self._running = False

        # 1. Prevent any new publishes to upstream
        self._upstream_client = None

        # 2. Signal all client queues to stop (so recv/send loops exit)
        async with self._clients_lock:
            for queue in self._clients.values():
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(None)

        # 3. Close the TLS server (stop accepting new connections)
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # 4. Now cancel the upstream task (exits aiomqtt context cleanly)
        if self._upstream_task:
            self._upstream_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._upstream_task

        logger.info("MQTT proxy stopped")

    async def run_upstream_loop(self) -> None:
        """Run the upstream connection loop as a standalone coroutine.

        Called from cli.py as a background task, matching the ChamberImageProxy pattern.
        """
        self._upstream_task = asyncio.current_task()
        await self._upstream_connection_loop()

    # ------------------------------------------------------------------
    # Upstream (printer) connection
    # ------------------------------------------------------------------

    async def _upstream_connection_loop(self) -> None:
        """Maintain a persistent MQTT connection to the printer, reconnecting on failure."""
        printer_ssl = create_ssl_context()

        while self._running:
            try:
                logger.info("Connecting to printer MQTT at %s:%d", self.printer_ip, self.port)

                async with aiomqtt.Client(
                    hostname=self.printer_ip,
                    port=self.port,
                    username="bblp",
                    password=self.access_code,
                    tls_context=printer_ssl,
                    keepalive=UPSTREAM_KEEPALIVE,
                    timeout=UPSTREAM_CONNECT_TIMEOUT,
                    identifier=f"pandaproxy-{self.serial_number}",
                ) as client:
                    self._upstream_client = client
                    await client.subscribe("#")
                    self._upstream_connected.set()
                    logger.info("Connected to printer MQTT broker")

                    async for message in client.messages:
                        packet = build_publish(
                            str(message.topic),
                            message.payload if isinstance(message.payload, bytes) else b"",
                            qos=message.qos,
                        )
                        await self._broadcast_to_clients(packet)

            except aiomqtt.MqttError as e:
                logger.warning("Upstream MQTT connection error: %s", e)
            except asyncio.CancelledError:
                logger.debug("Upstream connection loop cancelled")
                return
            except Exception as e:
                logger.error("Unexpected upstream error: %s", e)
            finally:
                self._upstream_connected.clear()
                self._upstream_client = None

            if self._running:
                logger.info("Reconnecting to printer in %d seconds...", RECONNECT_DELAY)
                await asyncio.sleep(RECONNECT_DELAY)

    async def _forward_to_upstream(self, topic: str, payload: bytes, qos: int) -> None:
        """Forward a client PUBLISH to the upstream printer connection."""
        if not self._running:
            return
        async with self._upstream_lock:
            client = self._upstream_client
            if client:
                try:
                    await client.publish(topic, payload, qos=qos)
                except aiomqtt.MqttError as e:
                    logger.warning("Failed to forward to upstream: %s", e)
            else:
                logger.debug("Upstream not connected, dropping client publish")

    # ------------------------------------------------------------------
    # Client broadcast
    # ------------------------------------------------------------------

    async def _broadcast_to_clients(self, packet: bytes) -> None:
        """Put a packet into every connected client's queue."""
        async with self._clients_lock:
            disconnected: list[str] = []
            for client_id, queue in self._clients.items():
                try:
                    queue.put_nowait(packet)
                except asyncio.QueueFull:
                    logger.warning("Client %s queue full, disconnecting", client_id)
                    with contextlib.suppress(asyncio.QueueFull):
                        queue.put_nowait(None)
                    disconnected.append(client_id)
            for client_id in disconnected:
                self._clients.pop(client_id, None)

    # ------------------------------------------------------------------
    # Client connection handling
    # ------------------------------------------------------------------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new MQTT client connection."""
        peer = writer.get_extra_info("peername")
        logger.info("New MQTT connection from %s", peer)
        client_id = str(peer)
        queue: asyncio.Queue[bytes | None] | None = None

        try:
            # --- MQTT CONNECT handshake ---
            try:
                pkt = await asyncio.wait_for(read_packet(reader), timeout=CLIENT_CONNECT_TIMEOUT)
            except TimeoutError:
                logger.warning("Client %s CONNECT timeout", peer)
                return
            except asyncio.IncompleteReadError:
                logger.debug("Client %s disconnected during CONNECT", peer)
                return

            if pkt.packet_type != PacketType.CONNECT:
                logger.warning("Expected CONNECT from %s, got type %d", peer, pkt.packet_type)
                return

            connect_info = parse_connect(pkt.payload)
            if connect_info.password != self.access_code:
                writer.write(build_connack(return_code=CONNACK_NOT_AUTHORIZED))
                await writer.drain()
                logger.warning("Auth failed for %s (client_id=%s)", peer, connect_info.client_id)
                return

            writer.write(build_connack(return_code=CONNACK_ACCEPTED))
            await writer.drain()
            logger.info("Client %s authenticated (client_id=%s)", peer, connect_info.client_id)

            # --- Wait for upstream to be ready ---
            if not self._upstream_connected.is_set():
                logger.info("Waiting for upstream connection for %s...", peer)
                try:
                    await asyncio.wait_for(
                        self._upstream_connected.wait(), timeout=UPSTREAM_WAIT_TIMEOUT
                    )
                except TimeoutError:
                    logger.warning("Upstream not available for %s, disconnecting", peer)
                    return

            # --- Register client queue ---
            queue = asyncio.Queue(maxsize=CLIENT_QUEUE_SIZE)
            async with self._clients_lock:
                self._clients[client_id] = queue

            # --- Run bidirectional forwarding ---
            keepalive = connect_info.keepalive
            send_task = asyncio.create_task(self._client_send_loop(client_id, queue, writer))
            recv_task = asyncio.create_task(
                self._client_recv_loop(client_id, reader, writer, keepalive)
            )

            done, pending = await asyncio.wait(
                [send_task, recv_task], return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        except ssl.SSLError as e:
            if "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in str(e):
                logger.debug("Client %s TLS close: %s", peer, e)
            else:
                logger.error("Client %s SSL error: %s", peer, e)
        except Exception as e:
            logger.error("Error handling client %s: %s", peer, e)
        finally:
            if queue is not None:
                async with self._clients_lock:
                    self._clients.pop(client_id, None)
            await close_writer(writer)
            logger.info("Connection from %s closed", peer)

    async def _client_send_loop(
        self, client_id: str, queue: asyncio.Queue[bytes | None], writer: asyncio.StreamWriter
    ) -> None:
        """Drain the client's queue and write packets to its socket."""
        try:
            while True:
                packet = await queue.get()
                if packet is None:
                    break
                writer.write(packet)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            logger.debug("Client %s connection reset during send", client_id)
        except ssl.SSLError as e:
            logger.debug("Client %s SSL error during send: %s", client_id, e)

    async def _client_recv_loop(
        self,
        client_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        keepalive: int,
    ) -> None:
        """Read MQTT packets from a client, handling them locally or forwarding."""
        # MQTT spec: disconnect if no packet within 1.5x keepalive
        timeout = keepalive * 1.5 if keepalive > 0 else 120.0

        try:
            while self._running:
                try:
                    pkt = await asyncio.wait_for(read_packet(reader), timeout=timeout)
                except TimeoutError:
                    logger.info("Client %s keepalive timeout", client_id)
                    return

                match pkt.packet_type:
                    case PacketType.PUBLISH:
                        info = parse_publish(pkt.flags, pkt.payload)
                        # ACK QoS 1 locally, then forward
                        if info.qos == 1 and info.packet_id is not None:
                            writer.write(build_puback(info.packet_id))
                            await writer.drain()
                        await self._forward_to_upstream(info.topic, info.payload, qos=0)

                    case PacketType.SUBSCRIBE:
                        pkt_id, topics = parse_subscribe(pkt.payload)
                        # Grant QoS 0 for everything (upstream handles subscriptions)
                        writer.write(build_suback(pkt_id, [0] * len(topics)))
                        await writer.drain()
                        logger.debug("Client %s subscribed to %s", client_id, topics)

                    case PacketType.UNSUBSCRIBE:
                        pkt_id, topics = parse_unsubscribe(pkt.payload)
                        writer.write(build_unsuback(pkt_id))
                        await writer.drain()
                        logger.debug("Client %s unsubscribed from %s", client_id, topics)

                    case PacketType.PINGREQ:
                        writer.write(build_pingresp())
                        await writer.drain()

                    case PacketType.PUBACK:
                        pass  # We ACK upstream ourselves; ignore client PUBACKs

                    case PacketType.DISCONNECT:
                        logger.debug("Client %s sent DISCONNECT", client_id)
                        return

                    case _:
                        logger.debug(
                            "Client %s sent unhandled packet type %d",
                            client_id,
                            pkt.packet_type,
                        )

        except asyncio.IncompleteReadError:
            logger.debug("Client %s disconnected", client_id)
        except ssl.SSLError as e:
            logger.debug("Client %s SSL error during recv: %s", client_id, e)
