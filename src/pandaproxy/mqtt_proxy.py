"""MQTT proxy for BambuLab printer control and status on port 8883.

BambuLab printers expose an MQTT interface via MQTTS (MQTT over TLS) on port 8883.
This proxy uses amqtt broker with bridge configuration to forward all MQTT messages
bidirectionally, acting as a transparent man-in-the-middle.

Protocol details:
- Connection: TLS socket (self-signed cert for clients, printer.cer for upstream)
- Authentication: MQTT CONNECT with username "bblp" and access code as password
- Messages: All MQTT messages forwarded transparently via broker bridge
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import ssl
import tempfile
from pathlib import Path

import aiomqtt
from amqtt.broker import Broker

from pandaproxy.protocol import MQTT_PORT

logger = logging.getLogger(__name__)

# Keepalive interval (seconds)
MQTT_KEEPALIVE = 60


class MQTTProxy:
    """MQTT proxy for BambuLab printer control and status.

    Uses amqtt broker to accept client connections and a bridge client
    to forward messages bidirectionally to the printer.
    """

    def __init__(
        self,
        printer_ip: str,
        access_code: str,
        serial_number: str,
        bind_address: str = "0.0.0.0",
    ) -> None:
        self.printer_ip = printer_ip
        self.access_code = access_code
        self.serial_number = serial_number
        self.bind_address = bind_address
        self.port = MQTT_PORT

        self._running = False
        self._broker: Broker | None = None
        self._bridge_task: asyncio.Task | None = None
        self._cert_path: Path | None = None
        self._key_path: Path | None = None
        self._password_file: Path | None = None

    async def start(self) -> None:
        """Start the MQTT proxy."""
        logger.info("Starting MQTT proxy on %s:%d", self.bind_address, self.port)
        self._running = True

        # Generate TLS certificates for the broker
        await self._generate_tls_certs()

        # Create password file for authentication
        await self._create_password_file()

        # Create broker configuration
        broker_config = {
            "listeners": {
                "default": {
                    "type": "tcp",
                    "bind": f"{self.bind_address}:{self.port}",
                    "ssl": True,
                    "certfile": str(self._cert_path),
                    "keyfile": str(self._key_path),
                },
            },
            "sys_interval": 0,  # Disable $SYS topics
            "auth": {
                "allow-anonymous": False,
                "password-file": str(self._password_file),
            },
            "topic-check": {
                "enabled": False,
            },
        }

        # Start the broker
        self._broker = Broker(broker_config)
        await self._broker.start()
        logger.info("MQTT broker started on %s:%d (TLS)", self.bind_address, self.port)

        # Start the bridge to printer
        self._bridge_task = asyncio.create_task(self._bridge_loop())

    async def stop(self) -> None:
        """Stop the MQTT proxy."""
        logger.info("Stopping MQTT proxy")
        self._running = False

        # Stop bridge
        if self._bridge_task:
            self._bridge_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._bridge_task

        # Stop broker
        if self._broker:
            await self._broker.shutdown()

        # Clean up temporary files
        for path in [self._cert_path, self._key_path, self._password_file]:
            if path and path.exists():
                path.unlink()

        logger.info("MQTT proxy stopped")

    async def _generate_tls_certs(self) -> None:
        """Generate self-signed TLS certificates for the broker."""
        import subprocess

        # Create temporary files for cert and key
        cert_fd, cert_path = tempfile.mkstemp(suffix=".pem", prefix="mqtt_cert_")
        key_fd, key_path = tempfile.mkstemp(suffix=".pem", prefix="mqtt_key_")
        os.close(cert_fd)
        os.close(key_fd)

        self._cert_path = Path(cert_path)
        self._key_path = Path(key_path)

        # Generate self-signed certificate with SANs for localhost connections
        # Include both IP and DNS names that clients might use to connect
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(self._key_path),
                "-out",
                str(self._cert_path),
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=PandaProxy-MQTT",
                "-addext",
                "subjectAltName=IP:127.0.0.1,IP:::1,DNS:localhost",
            ],
            check=True,
            capture_output=True,
        )

        logger.debug("Generated TLS certificates for MQTT broker")

    async def _create_password_file(self) -> None:
        """Create password file for broker authentication."""
        # amqtt uses passlib to verify passwords, so we need to hash them
        from passlib.hash import sha512_crypt

        pw_fd, pw_path = tempfile.mkstemp(suffix=".txt", prefix="mqtt_passwd_")
        os.close(pw_fd)

        self._password_file = Path(pw_path)
        hashed_password = sha512_crypt.hash(self.access_code)
        self._password_file.write_text(f"bblp:{hashed_password}\n")

        logger.debug("Created password file for MQTT broker")

    async def _bridge_loop(self) -> None:
        """Maintain bridge connection between local broker and printer."""
        while self._running:
            try:
                await self._run_bridge()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("Bridge error: %s", e)

            if self._running:
                logger.info("Reconnecting bridge in 5 seconds...")
                await asyncio.sleep(5)

    async def _run_bridge(self) -> None:
        """Run the bridge between local broker and printer."""
        ca_file = self._get_ca_file()

        # Create SSL context for printer connection
        # We use SSLContext directly instead of create_default_context() because
        # Python's create_default_context() has stricter verification that fails
        # on BambuLab printer certificates (missing key usage extension check).
        printer_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        printer_ssl_context.load_verify_locations(ca_file)
        printer_ssl_context.check_hostname = False
        printer_ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Connect to printer using aiomqtt (allows custom SSL context)
        logger.info("Connecting bridge to printer at %s:%d", self.printer_ip, self.port)

        async with aiomqtt.Client(
            hostname=self.printer_ip,
            port=self.port,
            username="bblp",
            password=self.access_code,
            tls_context=printer_ssl_context,
            identifier="pandaproxy-to-printer",
        ) as printer_client:
            logger.info("Bridge connected to printer")

            # Connect to local broker using aiomqtt with custom SSL context
            # We need custom SSL context because amqtt's create_default_context() is too strict
            host = "127.0.0.1" if self.bind_address in {"0.0.0.0", "::"} else self.bind_address
            local_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            local_ssl_context.load_verify_locations(str(self._cert_path))
            local_ssl_context.check_hostname = False
            local_ssl_context.verify_mode = ssl.CERT_REQUIRED

            async with aiomqtt.Client(
                hostname=host,
                port=self.port,
                username="bblp",
                password=self.access_code,
                tls_context=local_ssl_context,
                identifier="pandaproxy-to-local",
            ) as local_client:
                logger.debug("Bridge connected to local broker")

                # Subscribe to topics
                await printer_client.subscribe(f"device/{self.serial_number}/report")
                logger.debug("Bridge subscribed to device/%s/report", self.serial_number)

                await local_client.subscribe(f"device/{self.serial_number}/request")

                # Forward messages bidirectionally
                forward_printer_task = asyncio.create_task(
                    self._forward_from_printer(printer_client, local_client)
                )
                forward_local_task = asyncio.create_task(
                    self._forward_to_printer(local_client, printer_client)
                )

                try:
                    await asyncio.gather(forward_printer_task, forward_local_task)
                finally:
                    forward_printer_task.cancel()
                    forward_local_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await forward_printer_task
                    with contextlib.suppress(asyncio.CancelledError):
                        await forward_local_task

    async def _forward_from_printer(
        self,
        printer_client: aiomqtt.Client,
        local_client: aiomqtt.Client,
    ) -> None:
        """Forward messages from printer to local broker."""
        async for message in printer_client.messages:
            topic = str(message.topic)
            payload = message.payload
            if isinstance(payload, bytes):
                logger.debug("[printer->clients] %s (%d bytes)", topic, len(payload))
                await local_client.publish(topic, payload)

    async def _forward_to_printer(
        self,
        local_client: aiomqtt.Client,
        printer_client: aiomqtt.Client,
    ) -> None:
        """Forward messages from local broker to printer."""
        async for message in local_client.messages:
            topic = str(message.topic)
            payload = message.payload
            if isinstance(payload, bytes):
                logger.debug("[clients->printer] %s (%d bytes)", topic, len(payload))
                await printer_client.publish(topic, payload)

    @staticmethod
    def _get_ca_file() -> str:
        """Get the path to the printer CA certificate."""
        from importlib.resources import files

        cert_path = files("pandaproxy").joinpath("printer.cer")
        return str(cert_path)
