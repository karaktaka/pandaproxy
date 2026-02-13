"""Tests for MQTT multiplexing proxy."""

import asyncio
import ssl
import struct
import tempfile
from pathlib import Path

import pytest

from pandaproxy.helper import generate_self_signed_cert
from pandaproxy.mqtt_protocol import (
    PacketType,
    build_publish,
    read_packet,
)
from pandaproxy.mqtt_proxy import MQTTProxy


@pytest.fixture
def temp_certs():
    """Generate temporary TLS certificates for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "test.crt"
        key_path = Path(tmpdir) / "test.key"

        generate_self_signed_cert(
            common_name="TestProxy",
            san_dns=["localhost"],
            san_ips=["127.0.0.1", "::1"],
            output_cert=cert_path,
            output_key=key_path,
        )

        yield cert_path, key_path


def _build_connect_packet(
    client_id: str = "test-client",
    username: str = "bblp",
    password: str = "testcode",
    keepalive: int = 60,
) -> bytes:
    """Build a raw MQTT CONNECT packet for testing."""
    vh = bytearray()
    vh.extend(struct.pack(">H", 4))
    vh.extend(b"MQTT")
    vh.append(4)  # protocol level
    flags = 0x02 | 0x80 | 0x40  # clean session + username + password
    vh.append(flags)
    vh.extend(struct.pack(">H", keepalive))

    pl = bytearray()
    for val in [client_id, username, password]:
        encoded = val.encode("utf-8")
        pl.extend(struct.pack(">H", len(encoded)))
        pl.extend(encoded)

    payload = bytes(vh) + bytes(pl)
    # Fixed header: CONNECT (type=1) + remaining length
    remaining_len = len(payload)
    header = bytes([0x10]) + _encode_remaining_length(remaining_len)
    return header + payload


def _build_subscribe_packet(packet_id: int, topics: list[tuple[str, int]]) -> bytes:
    """Build a raw MQTT SUBSCRIBE packet for testing."""
    payload = bytearray()
    payload.extend(struct.pack(">H", packet_id))
    for topic, qos in topics:
        tb = topic.encode("utf-8")
        payload.extend(struct.pack(">H", len(tb)))
        payload.extend(tb)
        payload.append(qos)
    remaining = bytes(payload)
    # SUBSCRIBE: type=8, reserved flags=0x02 -> first byte = 0x82
    header = bytes([0x82]) + _encode_remaining_length(len(remaining))
    return header + remaining


def _build_pingreq_packet() -> bytes:
    """Build a raw MQTT PINGREQ packet."""
    return b"\xc0\x00"


def _build_disconnect_packet() -> bytes:
    """Build a raw MQTT DISCONNECT packet."""
    return b"\xe0\x00"


def _encode_remaining_length(length: int) -> bytes:
    result = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        result.append(byte)
        if length == 0:
            break
    return bytes(result)


class TestMQTTProxyInit:
    """Tests for MQTTProxy initialization."""

    def test_init_sets_properties(self, temp_certs):
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="0.0.0.0",
        )
        assert proxy.printer_ip == "192.168.1.100"
        assert proxy.access_code == "testcode"
        assert proxy.serial_number == "ABC123"
        assert proxy.cert_path == cert_path
        assert proxy.key_path == key_path
        assert proxy.bind_address == "0.0.0.0"
        assert proxy.port == 8883

    def test_init_defaults(self, temp_certs):
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
        )
        assert proxy.bind_address == "0.0.0.0"


class TestMQTTProxyLifecycle:
    """Tests for MQTTProxy start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_raises_if_certs_missing(self):
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=Path("/nonexistent/cert.crt"),
            key_path=Path("/nonexistent/key.key"),
        )
        with pytest.raises(FileNotFoundError):
            await proxy.start()

    @pytest.mark.asyncio
    async def test_start_creates_server(self, temp_certs):
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        try:
            await proxy.start()
            assert proxy._server is not None
            assert proxy._running is True
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_state(self, temp_certs):
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()
        await proxy.stop()
        assert proxy._running is False


class TestMQTTProxyClientHandling:
    """Tests for MQTT client connection handling."""

    @pytest.mark.asyncio
    async def test_accepts_tls_connection(self, temp_certs):
        """Should accept TLS connections."""
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()
        try:
            port = proxy._server.sockets[0].getsockname()[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                timeout=5.0,
            )
            writer.close()
            await writer.wait_closed()
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_connect_handshake_success(self, temp_certs):
        """Should respond with CONNACK on valid CONNECT."""
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()
        # Simulate upstream being connected so client doesn't wait
        proxy._upstream_connected.set()

        try:
            port = proxy._server.sockets[0].getsockname()[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                timeout=5.0,
            )
            try:
                # Send CONNECT
                writer.write(_build_connect_packet(password="testcode"))
                await writer.drain()

                # Read CONNACK
                pkt = await asyncio.wait_for(read_packet(reader), timeout=5.0)
                assert pkt.packet_type == PacketType.CONNACK
                assert pkt.payload[1] == 0  # accepted
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_connect_handshake_bad_password(self, temp_certs):
        """Should reject CONNECT with wrong password."""
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()

        try:
            port = proxy._server.sockets[0].getsockname()[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                timeout=5.0,
            )
            try:
                writer.write(_build_connect_packet(password="wrongcode"))
                await writer.drain()

                pkt = await asyncio.wait_for(read_packet(reader), timeout=5.0)
                assert pkt.packet_type == PacketType.CONNACK
                assert pkt.payload[1] == 5  # not authorized
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_pingreq_response(self, temp_certs):
        """Should respond to PINGREQ with PINGRESP."""
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()
        proxy._upstream_connected.set()

        try:
            port = proxy._server.sockets[0].getsockname()[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                timeout=5.0,
            )
            try:
                # CONNECT
                writer.write(_build_connect_packet())
                await writer.drain()
                await asyncio.wait_for(read_packet(reader), timeout=5.0)  # CONNACK

                # PINGREQ
                writer.write(_build_pingreq_packet())
                await writer.drain()

                pkt = await asyncio.wait_for(read_packet(reader), timeout=5.0)
                assert pkt.packet_type == PacketType.PINGRESP
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_subscribe_response(self, temp_certs):
        """Should respond to SUBSCRIBE with SUBACK."""
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()
        proxy._upstream_connected.set()

        try:
            port = proxy._server.sockets[0].getsockname()[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                timeout=5.0,
            )
            try:
                # CONNECT
                writer.write(_build_connect_packet())
                await writer.drain()
                await asyncio.wait_for(read_packet(reader), timeout=5.0)  # CONNACK

                # SUBSCRIBE
                writer.write(_build_subscribe_packet(1, [("device/#", 0)]))
                await writer.drain()

                pkt = await asyncio.wait_for(read_packet(reader), timeout=5.0)
                assert pkt.packet_type == PacketType.SUBACK
                # packet_id should be 1
                assert struct.unpack(">H", pkt.payload[:2])[0] == 1
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await proxy.stop()


class TestMQTTProxyBroadcast:
    """Tests for message broadcasting to clients."""

    @pytest.mark.asyncio
    async def test_broadcast_reaches_client(self, temp_certs):
        """Messages broadcast internally should reach connected clients."""
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()
        proxy._upstream_connected.set()

        try:
            port = proxy._server.sockets[0].getsockname()[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                timeout=5.0,
            )
            try:
                # CONNECT + CONNACK
                writer.write(_build_connect_packet())
                await writer.drain()
                await asyncio.wait_for(read_packet(reader), timeout=5.0)

                # Give the proxy a moment to register the client
                await asyncio.sleep(0.1)

                # Simulate upstream broadcasting a PUBLISH
                pub_packet = build_publish("device/report", b'{"status":"ok"}', qos=0)
                await proxy._broadcast_to_clients(pub_packet)

                # Client should receive the PUBLISH
                pkt = await asyncio.wait_for(read_packet(reader), timeout=5.0)
                assert pkt.packet_type == PacketType.PUBLISH
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_broadcast_reaches_multiple_clients(self, temp_certs):
        """Broadcast should fan out to all connected clients."""
        cert_path, key_path = temp_certs
        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )
        await proxy.start()
        proxy._upstream_connected.set()

        try:
            port = proxy._server.sockets[0].getsockname()[1]
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            connections = []
            for i in range(3):
                r, w = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                    timeout=5.0,
                )
                w.write(_build_connect_packet(client_id=f"client-{i}"))
                await w.drain()
                await asyncio.wait_for(read_packet(r), timeout=5.0)  # CONNACK
                connections.append((r, w))

            await asyncio.sleep(0.1)

            # Broadcast
            pub_packet = build_publish("device/report", b"test", qos=0)
            await proxy._broadcast_to_clients(pub_packet)

            # All clients should receive it
            for r, _ in connections:
                pkt = await asyncio.wait_for(read_packet(r), timeout=5.0)
                assert pkt.packet_type == PacketType.PUBLISH

            # Clean up
            for _, w in connections:
                w.close()
                await w.wait_closed()
        finally:
            await proxy.stop()
