"""CLI entry point for PandaProxy."""

import asyncio
import logging
import os
import shutil
import signal
from typing import Annotated

import typer

from pandaproxy.chamber_proxy import ChamberImageProxy
from pandaproxy.detection import detect_camera_type
from pandaproxy.mqtt_proxy import MQTTProxy
from pandaproxy.rtsp_proxy import RTSPProxy

app = typer.Typer(
    name="PandaProxy",
    help="BambuLab Multi-Service Proxy - Proxy camera and MQTT from BambuLab printers to multiple clients.",
    add_completion=False,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def check_dependencies(services: set[str], camera_type: str | None) -> tuple[bool, list[str]]:
    """Check for required external dependencies based on enabled services."""
    missing = []

    # Camera service dependencies
    if "camera" in services:
        if camera_type == "rtsp":
            if not shutil.which("ffmpeg"):
                missing.append("ffmpeg")
            if not shutil.which("mediamtx"):
                missing.append("mediamtx")
        elif camera_type == "chamber" and not shutil.which("openssl"):
            missing.append("openssl")

    # MQTT proxy needs openssl for TLS cert generation
    if "mqtt" in services and not shutil.which("openssl") and "openssl" not in missing:
        missing.append("openssl")

    return len(missing) == 0, missing


def parse_services(services_str: str | None, enable_all: bool) -> set[str]:
    """Parse services string into a set of service names."""
    all_services = {"camera", "mqtt"}

    if enable_all:
        return all_services

    if not services_str:
        return {"camera"}  # Default to camera only

    services = {s.strip().lower() for s in services_str.split(",")}

    # Validate service names
    invalid = services - all_services
    if invalid:
        raise typer.BadParameter(
            f"Invalid service(s): {', '.join(invalid)}. Valid services: {', '.join(all_services)}"
        )

    return services


async def run_proxy(
    printer_ip: str,
    access_code: str,
    serial_number: str,
    bind: str,
    services: set[str],
    camera_type: str | None,
) -> None:
    """Run the proxy servers based on enabled services."""
    chamber_proxy: ChamberImageProxy | None = None
    rtsp_proxy: RTSPProxy | None = None
    mqtt_proxy: MQTTProxy | None = None

    # Setup signal handlers for graceful shutdown
    stop_event = asyncio.Event()

    def signal_handler() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # noinspection PyTypeChecker
        loop.add_signal_handler(sig, signal_handler)

    try:
        # Start camera proxy if enabled
        if "camera" in services and camera_type:
            if camera_type == "chamber":
                chamber_proxy = ChamberImageProxy(
                    printer_ip=printer_ip,
                    access_code=access_code,
                    bind_address=bind,
                )
                await chamber_proxy.start()
            elif camera_type == "rtsp":
                rtsp_proxy = RTSPProxy(
                    printer_ip=printer_ip,
                    access_code=access_code,
                    bind_address=bind,
                )
                await rtsp_proxy.start()

        # Start MQTT proxy if enabled
        if "mqtt" in services:
            mqtt_proxy = MQTTProxy(
                printer_ip=printer_ip,
                access_code=access_code,
                serial_number=serial_number,
                bind_address=bind,
            )
            await mqtt_proxy.start()

        # Print startup banner
        typer.echo("\n" + "=" * 60)
        typer.echo("PandaProxy is running!")
        typer.echo("=" * 60)
        typer.echo(f"Printer: {printer_ip}")
        typer.echo(f"Serial Number: {serial_number}")
        typer.echo("-" * 60)
        typer.echo("Active Services:")

        if "camera" in services and camera_type:
            if camera_type == "chamber":
                typer.echo(f"  Camera: {bind}:6000 (TLS) - Chamber Image")
            elif camera_type == "rtsp":
                typer.echo(f"  Camera: rtsp://bblp:<access_code>@{bind}:322/stream")

        if "mqtt" in services:
            typer.echo(f"  MQTT: mqtts://{bind}:8883 (TLS)")

        typer.echo("=" * 60)
        if not (os.path.exists("/.dockerenv") or os.environ.get("RUNNING_IN_DOCKER")):
            typer.echo("Press Ctrl+C to stop\n")

        # Wait for shutdown signal
        await stop_event.wait()

    finally:
        logger.info("Shutting down...")

        if chamber_proxy:
            await chamber_proxy.stop()

        if rtsp_proxy:
            await rtsp_proxy.stop()

        if mqtt_proxy:
            await mqtt_proxy.stop()

        logger.info("Shutdown complete")


@app.command()
def main(
    printer_ip: Annotated[
        str,
        typer.Option(
            "--printer-ip",
            "-p",
            help="IP address of the BambuLab printer",
            envvar="PRINTER_IP",
        ),
    ],
    access_code: Annotated[
        str,
        typer.Option(
            "--access-code",
            "-a",
            help="Access code for the printer (found in printer settings)",
            envvar="ACCESS_CODE",
        ),
    ],
    serial_number: Annotated[
        str,
        typer.Option(
            "--serial-number",
            "-s",
            help="Serial number of the printer (required for MQTT)",
            envvar="SERIAL_NUMBER",
        ),
    ],
    bind: Annotated[
        str,
        typer.Option(
            "--bind",
            "-b",
            help="Address to bind the proxy servers to",
            envvar="BIND_ADDRESS",
        ),
    ] = "0.0.0.0",
    services: Annotated[
        str | None,
        typer.Option(
            "--services",
            help="Comma-separated list of services to enable: camera,mqtt",
            envvar="SERVICES",
        ),
    ] = None,
    enable_all: Annotated[
        bool,
        typer.Option(
            "--enable-all",
            help="Enable all services (camera, mqtt)",
            envvar="ENABLE_ALL",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose/debug logging",
        ),
    ] = False,
) -> None:
    """Start the BambuLab multiservice proxy.

    This proxy connects to your BambuLab printer and serves multiple clients,
    preventing connection limit issues. It can proxy camera streams, and MQTT
    (for printer control/status).

    Services:
    - camera: Auto-detected (Chamber Image for A1/P1, RTSP for X1/H2/P2)
    - mqtt: MQTTS on port 8883 for printer control and status

    Examples:
        # Camera only (default)
        pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001

        # All services
        pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001 --enable-all

        # Specific services
        pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001 --services camera,mqtt
    """
    # Set log level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Parse services
    try:
        enabled_services = parse_services(services, enable_all)
    except typer.BadParameter as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1) from None

    typer.echo(f"Connecting to printer at {printer_ip}...")
    typer.echo(f"Enabled services: {', '.join(sorted(enabled_services))}")

    # Detect camera type if camera service is enabled
    camera_type: str | None = None
    if "camera" in enabled_services:
        try:
            camera_type = asyncio.run(detect_camera_type(printer_ip, access_code))
            typer.echo(f"Detected camera type: {camera_type.upper()}")
        except RuntimeError as e:
            typer.echo(f"Warning: Could not detect camera type: {e}", err=True)
            typer.echo("Camera service will be disabled.", err=True)
            enabled_services.discard("camera")

    # Check dependencies for enabled services
    dependencies_satisfied, dependencies_missing = check_dependencies(enabled_services, camera_type)
    if not dependencies_satisfied:
        typer.echo("Error: Missing required dependencies:", err=True)
        for dep in dependencies_missing:
            if dep == "ffmpeg":
                typer.echo("  - ffmpeg: Install via your package manager", err=True)
                typer.echo("      Linux: apt install ffmpeg / pacman -S ffmpeg", err=True)
                typer.echo("      macOS: brew install ffmpeg", err=True)
            elif dep == "mediamtx":
                typer.echo(
                    "  - mediamtx: Download from https://github.com/bluenviron/mediamtx/releases",
                    err=True,
                )
            elif dep == "openssl":
                typer.echo("  - openssl: Install via your package manager", err=True)
                typer.echo("      Linux: apt install openssl / pacman -S openssl", err=True)
                typer.echo("      macOS: brew install openssl", err=True)
        raise typer.Exit(1)

    if not enabled_services:
        typer.echo("Error: No services enabled.", err=True)
        raise typer.Exit(1)

    typer.echo("Starting PandaProxy...")

    # Run the async proxy
    asyncio.run(
        run_proxy(
            printer_ip=printer_ip,
            access_code=access_code,
            serial_number=serial_number,
            bind=bind,
            services=enabled_services,
            camera_type=camera_type,
        )
    )


if __name__ == "__main__":
    app()
