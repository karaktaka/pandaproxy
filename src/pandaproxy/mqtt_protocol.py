"""Minimal MQTT wire protocol utilities for client-facing packet handling.

Only implements the subset needed for accepting and responding to MQTT clients.
The upstream (printer) connection uses aiomqtt which handles protocol internally.

Client-facing needs:
- Reading packets from client streams
- Parsing CONNECT, SUBSCRIBE, UNSUBSCRIBE, PUBLISH from clients
- Building CONNACK, SUBACK, UNSUBACK, PUBACK, PINGRESP, PUBLISH for clients
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from enum import IntEnum


class PacketType(IntEnum):
    """MQTT control packet types (upper 4 bits of fixed header byte 1)."""

    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14


# CONNACK return codes (MQTT 3.1.1)
CONNACK_ACCEPTED = 0
CONNACK_BAD_CREDENTIALS = 4
CONNACK_NOT_AUTHORIZED = 5


@dataclass(frozen=True, slots=True)
class MQTTPacket:
    """A parsed MQTT packet."""

    packet_type: int
    flags: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class ConnectInfo:
    """Parsed fields from an MQTT CONNECT packet."""

    client_id: str
    username: str | None
    password: str | None
    keepalive: int
    clean_session: bool


@dataclass(frozen=True, slots=True)
class PublishInfo:
    """Parsed fields from an MQTT PUBLISH packet."""

    topic: str
    payload: bytes
    qos: int
    packet_id: int | None


# ---------------------------------------------------------------------------
# Variable-length encoding
# ---------------------------------------------------------------------------


def _encode_remaining_length(length: int) -> bytes:
    """Encode an integer using MQTT variable-length encoding (1-4 bytes)."""
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


# ---------------------------------------------------------------------------
# Packet reading
# ---------------------------------------------------------------------------


async def read_packet(reader: asyncio.StreamReader) -> MQTTPacket:
    """Read a complete MQTT packet from an asyncio stream.

    Raises asyncio.IncompleteReadError if the connection closes mid-packet.
    """
    first_byte = await reader.readexactly(1)
    packet_type = (first_byte[0] >> 4) & 0x0F
    flags = first_byte[0] & 0x0F

    # Decode remaining length (variable-length, 1-4 bytes)
    remaining_length = 0
    multiplier = 1
    while True:
        byte = await reader.readexactly(1)
        remaining_length += (byte[0] & 0x7F) * multiplier
        if (byte[0] & 0x80) == 0:
            break
        multiplier *= 128
        if multiplier > 128**3:
            raise ValueError("Malformed remaining length in MQTT packet")

    payload = await reader.readexactly(remaining_length) if remaining_length > 0 else b""

    return MQTTPacket(packet_type=packet_type, flags=flags, payload=payload)


# ---------------------------------------------------------------------------
# Packet builders (proxy -> client)
# ---------------------------------------------------------------------------


def _build_packet(packet_type: int, flags: int, payload: bytes) -> bytes:
    """Assemble a complete MQTT packet from type, flags, and payload."""
    first_byte = ((packet_type & 0x0F) << 4) | (flags & 0x0F)
    return bytes([first_byte]) + _encode_remaining_length(len(payload)) + payload


def build_connack(return_code: int = CONNACK_ACCEPTED, session_present: bool = False) -> bytes:
    """Build a CONNACK packet."""
    flags = 0x01 if session_present else 0x00
    return _build_packet(PacketType.CONNACK, 0, bytes([flags, return_code]))


def build_suback(packet_id: int, return_codes: list[int]) -> bytes:
    """Build a SUBACK packet."""
    return _build_packet(PacketType.SUBACK, 0, struct.pack(">H", packet_id) + bytes(return_codes))


def build_unsuback(packet_id: int) -> bytes:
    """Build an UNSUBACK packet."""
    return _build_packet(PacketType.UNSUBACK, 0, struct.pack(">H", packet_id))


def build_puback(packet_id: int) -> bytes:
    """Build a PUBACK packet."""
    return _build_packet(PacketType.PUBACK, 0, struct.pack(">H", packet_id))


def build_pingresp() -> bytes:
    """Build a PINGRESP packet."""
    return _build_packet(PacketType.PINGRESP, 0, b"")


def build_publish(topic: str, payload: bytes, qos: int = 0, packet_id: int = 0) -> bytes:
    """Build a PUBLISH packet for fan-out to clients."""
    flags = (qos & 0x03) << 1
    data = bytearray()
    topic_bytes = topic.encode("utf-8")
    data.extend(struct.pack(">H", len(topic_bytes)))
    data.extend(topic_bytes)
    if qos > 0:
        data.extend(struct.pack(">H", packet_id))
    data.extend(payload)
    return _build_packet(PacketType.PUBLISH, flags, bytes(data))


# ---------------------------------------------------------------------------
# Packet parsers (client -> proxy)
# ---------------------------------------------------------------------------


def parse_connect(data: bytes) -> ConnectInfo:
    """Parse a CONNECT packet's variable header + payload.

    Handles MQTT 3.1.1 (and 3.1) CONNECT packets including optional
    Will Topic/Message fields that precede Username/Password.

    Payload order per MQTT 3.1.1 spec (section 3.1.3):
      Client ID → [Will Topic → Will Message] → [Username] → [Password]
    """
    offset = 0

    # Protocol name (length-prefixed)
    proto_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2 + proto_len

    # Protocol level
    offset += 1  # skip protocol level byte

    # Connect flags
    connect_flags = data[offset]
    offset += 1
    has_username = bool(connect_flags & 0x80)
    has_password = bool(connect_flags & 0x40)
    has_will = bool(connect_flags & 0x04)
    clean_session = bool(connect_flags & 0x02)

    # Keepalive
    keepalive = struct.unpack_from(">H", data, offset)[0]
    offset += 2

    # Client ID
    cid_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    client_id = data[offset : offset + cid_len].decode("utf-8")
    offset += cid_len

    # Will Topic + Will Message (skip if present, comes before username/password)
    if has_will:
        will_topic_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2 + will_topic_len
        will_msg_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2 + will_msg_len

    # Username (optional)
    username = None
    if has_username:
        ulen = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        username = data[offset : offset + ulen].decode("utf-8")
        offset += ulen

    # Password (optional)
    password = None
    if has_password:
        plen = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        password = data[offset : offset + plen].decode("utf-8")
        offset += plen

    return ConnectInfo(
        client_id=client_id,
        username=username,
        password=password,
        keepalive=keepalive,
        clean_session=clean_session,
    )


def parse_subscribe(data: bytes) -> tuple[int, list[tuple[str, int]]]:
    """Parse SUBSCRIBE payload. Returns (packet_id, [(topic, qos), ...])."""
    offset = 0
    packet_id = struct.unpack_from(">H", data, offset)[0]
    offset += 2

    topics: list[tuple[str, int]] = []
    while offset < len(data):
        tlen = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        topic = data[offset : offset + tlen].decode("utf-8")
        offset += tlen
        qos = data[offset]
        offset += 1
        topics.append((topic, qos))

    return packet_id, topics


def parse_unsubscribe(data: bytes) -> tuple[int, list[str]]:
    """Parse UNSUBSCRIBE payload. Returns (packet_id, [topic, ...])."""
    offset = 0
    packet_id = struct.unpack_from(">H", data, offset)[0]
    offset += 2

    topics: list[str] = []
    while offset < len(data):
        tlen = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        topic = data[offset : offset + tlen].decode("utf-8")
        offset += tlen
        topics.append(topic)

    return packet_id, topics


def parse_publish(flags: int, data: bytes) -> PublishInfo:
    """Parse PUBLISH variable header + payload."""
    offset = 0
    qos = (flags >> 1) & 0x03

    topic_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    topic = data[offset : offset + topic_len].decode("utf-8")
    offset += topic_len

    packet_id = None
    if qos > 0:
        packet_id = struct.unpack_from(">H", data, offset)[0]
        offset += 2

    return PublishInfo(topic=topic, payload=data[offset:], qos=qos, packet_id=packet_id)
