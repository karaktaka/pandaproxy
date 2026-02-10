"""Camera stream type detection for BambuLab printers.

Detects whether a printer uses RTSP (port 322) or Chamber Image (port 6000)
protocol by probing both endpoints.
"""

import asyncio
import logging
import struct

from pandaproxy.helper import (
    close_writer,
    create_auth_payload,
    create_ssl_context,
)
from pandaproxy.protocol import CHAMBER_PORT, MAX_PAYLOAD_SIZE, RTSP_PORT

logger = logging.getLogger(__name__)

# Connection timeout for detection
DETECT_TIMEOUT = 5.0


async def _probe_chamber_port(ip: str, access_code: str) -> bool:
    """Probe the chamber image port (6000) to see if it responds.

    Returns True if the printer responds to the chamber image protocol.
    """
    ssl_context = create_ssl_context()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, CHAMBER_PORT, ssl=ssl_context),
            timeout=DETECT_TIMEOUT,
        )

        try:
            # Send authentication payload
            auth_payload = create_auth_payload(access_code)
            writer.write(auth_payload)
            await writer.drain()

            # Try to read the 16-byte header response
            header = await asyncio.wait_for(reader.read(16), timeout=DETECT_TIMEOUT)

            if len(header) >= 4:
                # Check if we got a valid payload size
                payload_size = struct.unpack("<I", header[0:4])[0]
                if 0 < payload_size < MAX_PAYLOAD_SIZE:
                    logger.debug("Chamber image protocol detected (payload size: %d)", payload_size)
                    return True

        finally:
            await close_writer(writer)

    except TimeoutError:
        logger.debug("Chamber port %d timeout", CHAMBER_PORT)
    except ConnectionRefusedError:
        logger.debug("Chamber port %d connection refused", CHAMBER_PORT)
    except OSError as e:
        logger.debug("Chamber port %d error: %s", CHAMBER_PORT, e)

    return False


async def _probe_rtsp_port(ip: str) -> bool:
    """Probe the RTSP port (322) to see if it responds.

    Returns True if the printer has an open RTSPS port.
    """
    ssl_context = create_ssl_context()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, RTSP_PORT, ssl=ssl_context),
            timeout=DETECT_TIMEOUT,
        )

        try:
            # Send RTSP OPTIONS request
            request = f"OPTIONS rtsp://{ip}:{RTSP_PORT}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            # Try to read response
            response = await asyncio.wait_for(reader.read(1024), timeout=DETECT_TIMEOUT)

            if response and (b"RTSP/1.0" in response or b"RTSP/2.0" in response):
                logger.debug("RTSP protocol detected")
                return True

            # Even if we don't get a proper RTSP response, the port being open
            # with TLS suggests it's an RTSP printer
            if response:
                logger.debug("RTSP port open but unexpected response, assuming RTSP")
                return True

        finally:
            await close_writer(writer)

    except TimeoutError:
        logger.debug("RTSP port %d timeout", RTSP_PORT)
    except ConnectionRefusedError:
        logger.debug("RTSP port %d connection refused", RTSP_PORT)
    except OSError as e:
        logger.debug("RTSP port %d error: %s", RTSP_PORT, e)

    return False


async def detect_camera_type(ip: str, access_code: str) -> str:
    """Detect the camera stream type for a BambuLab printer.

    Args:
        ip: IP address of the printer
        access_code: Access code for authentication

    Returns:
        "chamber" for A1/P1 printers (port 6000)
        "rtsp" for X1/H2/P2 printers (port 322)

    Raises:
        RuntimeError: If neither protocol is detected
    """
    logger.info("Detecting camera type for printer at %s...", ip)

    # Probe both ports concurrently
    chamber_result, rtsp_result = await asyncio.gather(
        _probe_chamber_port(ip, access_code),
        _probe_rtsp_port(ip),
    )

    if chamber_result and not rtsp_result:
        logger.info("Detected camera type: Chamber Image (A1/P1 series)")
        return "chamber"
    elif rtsp_result and not chamber_result:
        logger.info("Detected camera type: RTSP (X1/H2/P2 series)")
        return "rtsp"
    elif chamber_result and rtsp_result:
        # Both responded - prefer chamber as it's more specific
        logger.info("Both protocols responded, using Chamber Image")
        return "chamber"
    else:
        raise RuntimeError(
            f"Could not detect camera type for printer at {ip}. "
            "Please ensure:\n"
            "  - The printer is powered on and connected to the network\n"
            "  - LAN Mode is enabled\n"
            "  - Development Mode is enabled\n"
            "  - The access code is correct"
        )
