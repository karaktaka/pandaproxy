"""CLI entry point for PandaProxy."""

import asyncio
import logging
import os
import shutil
import signal
from importlib.metadata import version
from pathlib import Path
from typing import Annotated

import typer

from pandaproxy.chamber_proxy import ChamberImageProxy
from pandaproxy.detection import detect_camera_type
from pandaproxy.ftp_proxy import FTPProxy
from pandaproxy.helper import generate_self_signed_cert
from pandaproxy.mqtt_proxy import MQTTProxy
from pandaproxy.protocol import CERT_FILENAME, KEY_FILENAME
from pandaproxy.rtsp_proxy import RTSPProxy


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"PandaProxy v{version('PandaProxy')}")
        raise typer.Exit()


app = typer.Typer(
    name="PandaProxy",
    help="BambuLab Multi-Service Proxy - Proxy camera, MQTT, and FTP from BambuLab printers to multiple clients.",
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
    if "camera" in services and camera_type == "rtsp":
        if not shutil.which("ffmpeg"):
            missing.append("ffmpeg")
        if not shutil.which("mediamtx"):
            missing.append("mediamtx")

    return len(missing) == 0, missing


def parse_services(services_str: str | None, enable_all: bool) -> set[str]:
    """Parse services string into a set of service names."""
    all_services = {"camera", "mqtt", "ftp"}

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


def is_running_in_docker() -> bool:
    """Check if the application is running inside a Docker container."""
    # Check for the existence of .dockerenv file
    if os.path.exists("/.dockerenv"):
        return True

    # Check for RUNNING_IN_DOCKER environment variable (used in our Dockerfile)
    if os.environ.get("RUNNING_IN_DOCKER"):
        return True

    # Check cgroup for "docker" string on Linux
    try:
        with open("/proc/1/cgroup") as f:
            return "docker" in f.read()
    except FileNotFoundError:
        pass  # File doesn't exist, not a Linux-based container

    return False


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
    ftp_proxy: FTPProxy | None = None
    background_tasks = []

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
        # Generate shared TLS certificate
        certs_dir = Path("certs")
        certs_dir.mkdir(exist_ok=True)
        cert_path = certs_dir / CERT_FILENAME
        key_path = certs_dir / KEY_FILENAME

        if not cert_path.exists() or not key_path.exists():
            logger.info("Generating shared TLS certificate...")
            san_ips = ["127.0.0.1", "::1"]
            if bind != "0.0.0.0":
                san_ips.append(bind)

            generate_self_signed_cert(
                common_name="PandaProxy",
                san_dns=["localhost"],
                san_ips=san_ips,
                output_cert=cert_path,
                output_key=key_path,
            )

        # Instantiate camera proxy if enabled
        if "camera" in services and camera_type:
            if camera_type == "chamber":
                chamber_proxy = ChamberImageProxy(
                    printer_ip=printer_ip,
                    access_code=access_code,
                    cert_path=cert_path,
                    key_path=key_path,
                    bind_address=bind,
                )
            elif camera_type == "rtsp":
                rtsp_proxy = RTSPProxy(
                    printer_ip=printer_ip,
                    access_code=access_code,
                    cert_path=cert_path,
                    key_path=key_path,
                    bind_address=bind,
                )

        # Instantiate MQTT proxy if enabled
        if "mqtt" in services:
            mqtt_proxy = MQTTProxy(
                printer_ip=printer_ip,
                access_code=access_code,
                serial_number=serial_number,
                cert_path=cert_path,
                key_path=key_path,
                bind_address=bind,
            )

        # Instantiate FTP proxy if enabled
        if "ftp" in services:
            ftp_proxy = FTPProxy(
                printer_ip=printer_ip,
                bind_address=bind,
            )

        # Start all services concurrently
        # Collect start coroutines from instantiated proxies
        start_tasks = []
        if chamber_proxy:
            start_tasks.append(chamber_proxy.start())
        if rtsp_proxy:
            start_tasks.append(rtsp_proxy.start())
        if mqtt_proxy:
            start_tasks.append(mqtt_proxy.start())
        if ftp_proxy:
            start_tasks.append(ftp_proxy.start())

        if start_tasks:
            await asyncio.gather(*start_tasks)

        # IMPORTANT: Background tasks must be created AFTER start() completes
        # because they depend on _running being True (set in start())
        if chamber_proxy:
            background_tasks.append(asyncio.create_task(chamber_proxy.run_upstream_loop()))
        if rtsp_proxy:
            background_tasks.append(asyncio.create_task(rtsp_proxy.run_monitor_loop()))
        if mqtt_proxy:
            background_tasks.append(asyncio.create_task(mqtt_proxy.run_upstream_loop()))

        # Print startup banner
        typer.echo("\n" + "=" * 60)
        typer.echo(f"PandaProxy v{version('PandaProxy')} is running!")
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

        if "ftp" in services:
            typer.echo(f"  FTP: ftps://{bind}:990 (implicit TLS, active mode only)")

        typer.echo("=" * 60)
        if not is_running_in_docker():
            typer.echo("Press Ctrl+C to stop\n")

        # Wait for shutdown signal
        await stop_event.wait()

    finally:
        logger.info("Shutting down...")

        # Cancel background tasks
        for task in background_tasks:
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

        # Create a list of stop coroutines from the proxies that were started
        stop_tasks = []
        if chamber_proxy:
            stop_tasks.append(chamber_proxy.stop())
        if rtsp_proxy:
            stop_tasks.append(rtsp_proxy.stop())
        if mqtt_proxy:
            stop_tasks.append(mqtt_proxy.stop())
        if ftp_proxy:
            stop_tasks.append(ftp_proxy.stop())

        # Stop all services concurrently
        if stop_tasks:
            await asyncio.gather(*stop_tasks)

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
            help="Comma-separated list of services to enable: camera,mqtt,ftp",
            envvar="SERVICES",
        ),
    ] = None,
    enable_all: Annotated[
        bool,
        typer.Option(
            "--enable-all",
            help="Enable all services (camera, mqtt, ftp)",
            envvar="ENABLE_ALL",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose/debug logging",
            envvar="DEBUG",
        ),
    ] = False,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """Start the BambuLab multiservice proxy.

    This proxy connects to your BambuLab printer and serves multiple clients,
    preventing connection limit issues. It can proxy camera streams, MQTT
    (for printer control/status), and FTP (for file uploads).

    Services:
    - camera: Auto-detected (Chamber Image for A1/P1, RTSP for X1/H2/P2)
    - mqtt: MQTTS on port 8883 for printer control and status
    - ftp: Implicit FTPS on port 990 for file uploads

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
