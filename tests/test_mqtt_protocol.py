"""Tests for MQTT wire protocol utilities."""

import asyncio
import struct

import pytest

from pandaproxy.mqtt_protocol import (
    CONNACK_ACCEPTED,
    CONNACK_NOT_AUTHORIZED,
    MQTTPacket,
    PacketType,
    _encode_remaining_length,
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


class TestEncodeRemainingLength:
    """Tests for MQTT variable-length encoding."""

    def test_zero(self):
        assert _encode_remaining_length(0) == b"\x00"

    def test_small_value(self):
        assert _encode_remaining_length(127) == b"\x7f"

    def test_two_byte_value(self):
        # 128 = 0x00 0x01 in MQTT encoding
        assert _encode_remaining_length(128) == b"\x80\x01"

    def test_large_value(self):
        # 16384 = 0x80 0x80 0x01
        assert _encode_remaining_length(16384) == b"\x80\x80\x01"


class TestReadPacket:
    """Tests for reading MQTT packets from streams."""

    async def _feed_and_read(self, data: bytes) -> MQTTPacket:
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        return await read_packet(reader)

    @pytest.mark.asyncio
    async def test_read_pingreq(self):
        """PINGREQ is a zero-length packet: type=12, flags=0, no payload."""
        pkt = await self._feed_and_read(b"\xc0\x00")
        assert pkt.packet_type == PacketType.PINGREQ
        assert pkt.flags == 0
        assert pkt.payload == b""

    @pytest.mark.asyncio
    async def test_read_disconnect(self):
        """DISCONNECT is a zero-length packet: type=14, flags=0."""
        pkt = await self._feed_and_read(b"\xe0\x00")
        assert pkt.packet_type == PacketType.DISCONNECT
        assert pkt.payload == b""

    @pytest.mark.asyncio
    async def test_read_connack(self):
        """CONNACK has 2-byte payload."""
        pkt = await self._feed_and_read(b"\x20\x02\x00\x00")
        assert pkt.packet_type == PacketType.CONNACK
        assert pkt.payload == b"\x00\x00"

    @pytest.mark.asyncio
    async def test_read_incomplete_raises(self):
        """Should raise IncompleteReadError on truncated data."""
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x30\x05\x00")  # Says 5 bytes but only 1 follows
        reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await read_packet(reader)


class TestBuildPackets:
    """Tests for packet builder functions."""

    def test_build_connack_accepted(self):
        data = build_connack(return_code=CONNACK_ACCEPTED)
        assert data == b"\x20\x02\x00\x00"

    def test_build_connack_not_authorized(self):
        data = build_connack(return_code=CONNACK_NOT_AUTHORIZED)
        assert data == b"\x20\x02\x00\x05"

    def test_build_connack_session_present(self):
        data = build_connack(return_code=CONNACK_ACCEPTED, session_present=True)
        assert data == b"\x20\x02\x01\x00"

    def test_build_pingresp(self):
        assert build_pingresp() == b"\xd0\x00"

    def test_build_puback(self):
        data = build_puback(packet_id=42)
        assert data[0] == 0x40  # PUBACK type
        assert data[1] == 2  # remaining length
        assert struct.unpack(">H", data[2:4])[0] == 42

    def test_build_suback(self):
        data = build_suback(packet_id=1, return_codes=[0, 0])
        assert data[0] == 0x90  # SUBACK type
        assert data[1] == 4  # remaining length: 2 (pkt_id) + 2 (codes)
        assert struct.unpack(">H", data[2:4])[0] == 1  # packet_id
        assert data[4:6] == b"\x00\x00"  # return codes

    def test_build_unsuback(self):
        data = build_unsuback(packet_id=7)
        assert data[0] == 0xB0  # UNSUBACK type
        assert data[1] == 2
        assert struct.unpack(">H", data[2:4])[0] == 7

    def test_build_publish_qos0(self):
        data = build_publish("test/topic", b"hello", qos=0)
        # Type=3, flags=0x00 (QoS 0) -> first byte = 0x30
        assert data[0] == 0x30
        # After remaining length: topic length (2) + topic (10) + payload (5) = 17
        assert data[1] == 17

    def test_build_publish_qos1(self):
        data = build_publish("t", b"p", qos=1, packet_id=99)
        # Type=3, flags=0x02 (QoS 1) -> first byte = 0x32
        assert data[0] == 0x32
        # Verify packet_id is present
        # remaining: topic_len(2) + topic(1) + pkt_id(2) + payload(1) = 6
        assert data[1] == 6


class TestParseConnect:
    """Tests for CONNECT packet parsing."""

    def _build_connect_payload(
        self,
        client_id: str = "test",
        username: str | None = "bblp",
        password: str | None = "secret",
        keepalive: int = 60,
        will_topic: str | None = None,
        will_message: bytes | None = None,
    ) -> bytes:
        """Build a raw CONNECT variable header + payload for testing."""
        vh = bytearray()
        vh.extend(struct.pack(">H", 4))
        vh.extend(b"MQTT")
        vh.append(4)  # protocol level

        flags = 0x02  # clean session
        if username:
            flags |= 0x80
        if password:
            flags |= 0x40
        if will_topic is not None:
            flags |= 0x04  # Will Flag
        vh.append(flags)
        vh.extend(struct.pack(">H", keepalive))

        pl = bytearray()
        cid = client_id.encode()
        pl.extend(struct.pack(">H", len(cid)))
        pl.extend(cid)

        # Will Topic + Will Message come BEFORE username/password per MQTT 3.1.1
        if will_topic is not None:
            wt = will_topic.encode()
            pl.extend(struct.pack(">H", len(wt)))
            pl.extend(wt)
            wm = will_message or b""
            pl.extend(struct.pack(">H", len(wm)))
            pl.extend(wm)

        if username:
            ub = username.encode()
            pl.extend(struct.pack(">H", len(ub)))
            pl.extend(ub)
        if password:
            pb = password.encode()
            pl.extend(struct.pack(">H", len(pb)))
            pl.extend(pb)

        return bytes(vh) + bytes(pl)

    def test_parse_with_credentials(self):
        data = self._build_connect_payload(
            client_id="myclient", username="bblp", password="12345678"
        )
        info = parse_connect(data)
        assert info.client_id == "myclient"
        assert info.username == "bblp"
        assert info.password == "12345678"
        assert info.keepalive == 60
        assert info.clean_session is True

    def test_parse_without_credentials(self):
        data = self._build_connect_payload(client_id="anon", username=None, password=None)
        info = parse_connect(data)
        assert info.client_id == "anon"
        assert info.username is None
        assert info.password is None

    def test_parse_with_will_message(self):
        """CONNECT with Will flag set should still parse username/password correctly.

        MQTT 3.1.1 payload order: Client ID → Will Topic → Will Message → Username → Password.
        BambuLab clients (e.g. Bambuddy) set a Will message, which was previously causing
        the parser to misread Will Topic as Username, breaking authentication.
        """
        data = self._build_connect_payload(
            client_id="bambuddy",
            username="bblp",
            password="12345678",
            will_topic="device/status",
            will_message=b'{"online": false}',
        )
        info = parse_connect(data)
        assert info.client_id == "bambuddy"
        assert info.username == "bblp"
        assert info.password == "12345678"
        assert info.clean_session is True

    def test_parse_with_will_no_credentials(self):
        """CONNECT with Will flag but no username/password."""
        data = self._build_connect_payload(
            client_id="willclient",
            username=None,
            password=None,
            will_topic="lwt/offline",
            will_message=b"bye",
        )
        info = parse_connect(data)
        assert info.client_id == "willclient"
        assert info.username is None
        assert info.password is None

    def test_parse_custom_keepalive(self):
        data = self._build_connect_payload(keepalive=120)
        info = parse_connect(data)
        assert info.keepalive == 120


class TestParseSubscribe:
    """Tests for SUBSCRIBE packet parsing."""

    def test_single_topic(self):
        # packet_id=1, topic="test/topic", qos=0
        topic = b"test/topic"
        data = struct.pack(">H", 1) + struct.pack(">H", len(topic)) + topic + b"\x00"
        pkt_id, topics = parse_subscribe(data)
        assert pkt_id == 1
        assert topics == [("test/topic", 0)]

    def test_multiple_topics(self):
        data = bytearray()
        data.extend(struct.pack(">H", 5))  # packet_id
        for topic_str, qos in [("a/b", 0), ("c/d", 1)]:
            tb = topic_str.encode()
            data.extend(struct.pack(">H", len(tb)))
            data.extend(tb)
            data.append(qos)
        pkt_id, topics = parse_subscribe(bytes(data))
        assert pkt_id == 5
        assert topics == [("a/b", 0), ("c/d", 1)]


class TestParseUnsubscribe:
    """Tests for UNSUBSCRIBE packet parsing."""

    def test_single_topic(self):
        topic = b"test/topic"
        data = struct.pack(">H", 2) + struct.pack(">H", len(topic)) + topic
        pkt_id, topics = parse_unsubscribe(data)
        assert pkt_id == 2
        assert topics == ["test/topic"]


class TestParsePublish:
    """Tests for PUBLISH packet parsing."""

    def test_qos0(self):
        topic = b"t/1"
        payload = b"hello"
        data = struct.pack(">H", len(topic)) + topic + payload
        info = parse_publish(flags=0x00, data=data)
        assert info.topic == "t/1"
        assert info.payload == b"hello"
        assert info.qos == 0
        assert info.packet_id is None

    def test_qos1(self):
        topic = b"t/2"
        payload = b"world"
        data = struct.pack(">H", len(topic)) + topic + struct.pack(">H", 42) + payload
        info = parse_publish(flags=0x02, data=data)  # QoS 1 = flags bit 1
        assert info.topic == "t/2"
        assert info.payload == b"world"
        assert info.qos == 1
        assert info.packet_id == 42


class TestRoundtrip:
    """Test that building and then reading back packets produces correct results."""

    @pytest.mark.asyncio
    async def test_connack_roundtrip(self):
        raw = build_connack(return_code=CONNACK_ACCEPTED)
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        pkt = await read_packet(reader)
        assert pkt.packet_type == PacketType.CONNACK
        assert pkt.payload == b"\x00\x00"

    @pytest.mark.asyncio
    async def test_publish_roundtrip(self):
        raw = build_publish("sensor/temp", b"22.5", qos=0)
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        pkt = await read_packet(reader)
        assert pkt.packet_type == PacketType.PUBLISH
        info = parse_publish(pkt.flags, pkt.payload)
        assert info.topic == "sensor/temp"
        assert info.payload == b"22.5"
        assert info.qos == 0

    @pytest.mark.asyncio
    async def test_publish_qos1_roundtrip(self):
        raw = build_publish("cmd/go", b"data", qos=1, packet_id=100)
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        pkt = await read_packet(reader)
        info = parse_publish(pkt.flags, pkt.payload)
        assert info.topic == "cmd/go"
        assert info.payload == b"data"
        assert info.qos == 1
        assert info.packet_id == 100
