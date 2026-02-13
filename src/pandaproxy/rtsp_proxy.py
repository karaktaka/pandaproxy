"""RTSP proxy using FFmpeg and MediaMTX for BambuLab camera stream on port 322.

BambuLab printers expose a camera stream via RTSPS (RTSP over TLS) on port 322.
This proxy uses FFmpeg to pull the stream and push it to MediaMTX, which serves
multiple clients with authentication.
"""

import asyncio
import contextlib
import logging
import os
import shutil
import tempfile
from pathlib import Path

import ffmpeg

logger = logging.getLogger(__name__)

# MediaMTX configuration template
MEDIAMTX_CONFIG_TEMPLATE = """
###############################################
# MediaMTX configuration for PandaProxy
###############################################

# Logging
logLevel: info
logDestinations: [stdout]

# API (disabled for security)
api: no

# RTSP server settings
rtsp: yes
protocols: [tcp]
rtspAddress: :{rtsp_port}
rtspEncryption: "yes"
rtspServerKey: "{server_key}"
rtspServerCert: "{server_cert}"

# Authentication for RTSP
authMethod: internal
authInternalUsers:
  - user: bblp
    pass: {access_code}
    permissions:
      - action: read
        path: ""
      - action: publish
        path: ""

# Paths configuration
paths:
  stream:
    # FFmpeg will publish to this path
    source: publisher
    # Allow reading without republishing
    sourceOnDemand: no
"""


def check_dependencies() -> tuple[bool, list[str]]:
    """Check if required dependencies (ffmpeg, mediamtx) are installed.

    Returns:
        Tuple of (all_ok, list_of_missing_dependencies)
    """
    missing = []

    if not shutil.which("ffmpeg"):
        missing.append("ffmpeg")

    if not shutil.which("mediamtx"):
        missing.append("mediamtx")

    return len(missing) == 0, missing


class RTSPProxy:
    """RTSP proxy using FFmpeg and MediaMTX for BambuLab camera stream.

    Uses FFmpeg to pull the RTSPS stream from the printer and push it to
    a local MediaMTX instance, which handles multiple client connections
    with authentication.
    """

    def __init__(
        self,
        printer_ip: str,
        access_code: str,
        cert_path: Path,
        key_path: Path,
        bind_address: str = "0.0.0.0",
        mediamtx_internal_port: int = 8554,
    ) -> None:
        self.printer_ip = printer_ip
        self.access_code = access_code
        self.cert_path = cert_path
        self.key_path = key_path
        self.bind_address = bind_address
        self.port = 322
        self.mediamtx_internal_port = mediamtx_internal_port

        self._ffmpeg_process: asyncio.subprocess.Process | None = None
        self._mediamtx_process: asyncio.subprocess.Process | None = None
        self._running = False
        self._config_path: Path | None = None
        self._monitor_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the RTSP proxy (MediaMTX + FFmpeg)."""
        logger.info("Starting RTSP proxy on %s:%d", self.bind_address, self.port)

        # Check dependencies
        ok, missing = check_dependencies()
        if not ok:
            raise RuntimeError(
                f"Missing required dependencies: {', '.join(missing)}. "
                "Please install them before running the RTSP proxy.\n"
                "  - ffmpeg: Install via your package manager (e.g., apt install ffmpeg, brew install ffmpeg)\n"
                "  - mediamtx: Download from https://github.com/bluenviron/mediamtx/releases"
            )

        self._running = True

        # Create MediaMTX config
        self._config_path = await self._create_mediamtx_config()

        # Start MediaMTX
        await self._start_mediamtx()

        # Wait for MediaMTX to be ready
        await asyncio.sleep(2)

        # Start FFmpeg to pull from printer and push to MediaMTX
        await self._start_ffmpeg()

        logger.info("RTSP proxy running on rtsp://%s:%d/stream", self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the RTSP proxy."""
        logger.info("Stopping RTSP proxy")
        self._running = False

        # Cancel monitor task
        if self._monitor_task:
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task

        # Stop FFmpeg
        if self._ffmpeg_process:
            logger.debug("Terminating FFmpeg process")
            self._ffmpeg_process.terminate()
            try:
                await asyncio.wait_for(self._ffmpeg_process.wait(), timeout=5.0)
            except TimeoutError:
                self._ffmpeg_process.kill()
            self._ffmpeg_process = None

        # Stop MediaMTX
        if self._mediamtx_process:
            logger.debug("Terminating MediaMTX process")
            self._mediamtx_process.terminate()
            try:
                await asyncio.wait_for(self._mediamtx_process.wait(), timeout=5.0)
            except TimeoutError:
                self._mediamtx_process.kill()
            self._mediamtx_process = None

        # Clean up config file
        if self._config_path and self._config_path.exists():
            self._config_path.unlink()
            self._config_path = None

        logger.info("RTSP proxy stopped")

    async def run_monitor_loop(self) -> None:
        """Run the process monitoring loop as a standalone coroutine.

        This is the entry point called from cli.py as a background task.
        It must never exit silently — any unexpected crash is logged.
        """
        self._monitor_task = asyncio.current_task()
        try:
            await self._monitor_processes()
            logger.info("Monitor loop exited normally")
        except asyncio.CancelledError:
            logger.debug("Monitor loop cancelled")
        except Exception:
            logger.exception("Monitor loop crashed unexpectedly")

    async def _create_mediamtx_config(self) -> Path:
        """Create MediaMTX configuration file."""
        if not self.cert_path.exists() or not self.key_path.exists():
            raise FileNotFoundError(
                f"TLS certificates not found at {self.cert_path} or {self.key_path}. "
                "Please ensure the CLI entry point has generated them."
            )

        config_content = MEDIAMTX_CONFIG_TEMPLATE.format(
            rtsp_port=self.port,
            access_code=self.access_code,
            server_cert=str(self.cert_path.absolute()),
            server_key=str(self.key_path.absolute()),
        )

        # Create temp config file
        fd, path = tempfile.mkstemp(prefix="pandaproxy_mediamtx_", suffix=".yml")
        os.close(fd)
        config_path = Path(path)

        config_path.write_text(config_content)
        logger.debug("Created MediaMTX config at %s", config_path)

        return config_path

    async def _start_mediamtx(self) -> None:
        """Start MediaMTX process."""
        cmd = ["mediamtx", str(self._config_path)]

        logger.info("Starting MediaMTX: %s", " ".join(cmd))

        self._mediamtx_process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Start log readers
        asyncio.create_task(self._read_process_output(self._mediamtx_process, "mediamtx"))

    async def _start_ffmpeg(self) -> None:
        """Start FFmpeg process to pull RTSPS from printer and push to MediaMTX."""
        # Build RTSPS URL with authentication
        # BambuLab uses: rtsps://bblp:<access_code>@<ip>:322/streaming/live/1
        source_url = f"rtsps://bblp:{self.access_code}@{self.printer_ip}:322/streaming/live/1"

        # MediaMTX publish URL (internal, no auth needed for publisher)
        publish_url = f"rtsps://bblp:{self.access_code}@127.0.0.1:{self.port}/stream"

        # Use ffmpeg-python to construct the command
        # Note: ffmpeg-python is a wrapper that constructs the command line arguments
        # We still execute it via asyncio.create_subprocess_exec to have async control
        # and output capturing consistent with the rest of the application.

        stream = ffmpeg.input(
            source_url,
            rtsp_transport="tcp",
            allowed_media_types="video",
            fflags="+genpts",
            # Ignore cert verification for source
            tls_verify=0,
        )

        stream = ffmpeg.output(
            stream,
            publish_url,
            c="copy",
            f="rtsp",
            rtsp_transport="tcp",
            # Ignore cert verification for destination (our self-signed cert)
            tls_verify=0,
        )

        # Get the command arguments
        # ffmpeg-python's compile() returns the full command list including 'ffmpeg'
        cmd = ffmpeg.compile(stream)

        # Mask access code in log
        safe_cmd = " ".join(cmd).replace(self.access_code, "****")
        logger.info("Starting FFmpeg: %s", safe_cmd)

        # Set FFMPEG to accept self-signed certs
        env = os.environ.copy()

        self._ffmpeg_process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        # Start log readers
        asyncio.create_task(self._read_process_output(self._ffmpeg_process, "ffmpeg"))

    async def _read_process_output(self, process: asyncio.subprocess.Process, name: str) -> None:
        """Read and log process stdout/stderr."""

        async def read_stream(stream: asyncio.StreamReader | None, level: int) -> None:
            if stream is None:
                return
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                # Mask access code in output
                text = text.replace(self.access_code, "****")
                logger.log(level, "[%s] %s", name, text)

        await asyncio.gather(
            read_stream(process.stdout, logging.DEBUG),
            read_stream(process.stderr, logging.WARNING),
        )

    async def _monitor_processes(self) -> None:
        """Monitor FFmpeg and MediaMTX processes, restart if needed."""
        while self._running:
            await asyncio.sleep(5)

            try:
                # Check MediaMTX
                if self._mediamtx_process and self._mediamtx_process.returncode is not None:
                    logger.warning(
                        "MediaMTX process exited with code %d", self._mediamtx_process.returncode
                    )
                    if self._running:
                        logger.info("Restarting MediaMTX...")
                        await self._start_mediamtx()
                        await asyncio.sleep(2)

                # Check FFmpeg
                if self._ffmpeg_process and self._ffmpeg_process.returncode is not None:
                    logger.warning(
                        "FFmpeg process exited with code %d", self._ffmpeg_process.returncode
                    )
                    if self._running:
                        logger.info("Restarting FFmpeg in 5 seconds...")
                        await asyncio.sleep(5)
                        await self._start_ffmpeg()
            except asyncio.CancelledError:
                raise  # Let cancellation propagate for clean shutdown
            except Exception as e:
                logger.error("Error during process restart: %s", e)
