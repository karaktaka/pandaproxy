"""FTPS proxy for BambuLab printer file uploads on port 990.

BambuLab printers accept file uploads (gcode, 3mf) via implicit FTPS on port 990.
This proxy accepts client connections with TLS and forwards all FTP commands
directly to the printer (pass-through mode).

Protocol details:
- Connection: Implicit TLS (TLS immediately on connect, port 990)
- Authentication: Handled by printer (proxy just forwards)
- Data transfer: Negotiated between client and printer directly
"""

import asyncio
import contextlib
import contextvars
import logging
import re
import ssl
from importlib.resources import files
from pathlib import Path

from pandaproxy.helper import (
    close_writer,
)
from pandaproxy.protocol import FTP_PORT

logger = logging.getLogger(__name__)

# FTP response timeout (seconds)
FTP_TIMEOUT = 60.0

ssl_session_context: contextvars.ContextVar[ssl.SSLSession | None] = contextvars.ContextVar(
    "ssl_session", default=None
)


class SessionReusingSSLContext(ssl.SSLContext):
    """SSLContext that forces session reuse from a provided session.

    Overrides both wrap_socket() and wrap_bio() to inject the session
    from the context variable. This is needed because asyncio uses
    wrap_socket() internally, not wrap_bio().
    """

    def wrap_socket(
        self,
        sock,
        server_side=False,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        server_hostname=None,
        session=None,
    ):
        ctx_session = ssl_session_context.get()
        if ctx_session and session is None:
            session = ctx_session
            logger.debug("Injecting SSL session for reuse in wrap_socket")
        return super().wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            session=session,
        )

    def wrap_bio(self, incoming, outgoing, server_side=False, server_hostname=None, session=None):
        ctx_session = ssl_session_context.get()
        if ctx_session and session is None:
            session = ctx_session
            logger.debug("Injecting SSL session for reuse in wrap_bio")
        return super().wrap_bio(
            incoming,
            outgoing,
            server_side=server_side,
            server_hostname=server_hostname,
            session=session,
        )


class FTPProxy:
    """
    FTPS proxy for BambuLab printer file uploads (pass-through mode) with
    FTP-specific ALG (Application Layer Gateway) logic to handle PASV mode.
    """

    def __init__(
        self,
        printer_ip: str,
        access_code: str,
        cert_path: Path,
        key_path: Path,
        bind_address: str = "0.0.0.0",
    ) -> None:
        self.printer_ip = printer_ip
        self.access_code = access_code
        self.cert_path = cert_path
        self.key_path = key_path
        self.bind_address = bind_address
        self.port = FTP_PORT

        self._server: asyncio.Server | None = None
        self._running = False
        self._active_connections: dict[str, tuple[asyncio.Task, asyncio.Task]] = {}

        # We'll initialize these in start()
        self._ssl_context: ssl.SSLContext | None = None
        self._server_ssl_context: ssl.SSLContext | None = None
        self._client_count = 0

    async def start(self) -> None:
        """Start the FTP proxy server."""
        if self._running:
            return

        logger.info("Starting FTP proxy on %s:%d", self.bind_address, self.port)
        self._running = True

        # Initialize SSL contexts
        self._ssl_context = SessionReusingSSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_REQUIRED
        cert_path = files("pandaproxy").joinpath("printer.cer")
        self._ssl_context.load_verify_locations(str(cert_path))

        if not self.cert_path.exists() or not self.key_path.exists():
            raise FileNotFoundError(
                f"TLS certificates not found at {self.cert_path} or {self.key_path}. "
                "Please ensure the CLI entry point has generated them."
            )

        self._server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._server_ssl_context.load_cert_chain(self.cert_path, self.key_path)

        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
            ssl=self._server_ssl_context,
        )
        logger.info("FTP proxy listening on %s:%d (implicit TLS)", self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the FTP proxy server."""
        logger.info("Stopping FTP proxy")
        self._running = False

        # Cancel all active connection tasks
        for _client_id, (task1, task2) in list(self._active_connections.items()):
            task1.cancel()
            task2.cancel()

        self._active_connections.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        logger.info("FTP proxy stopped")

    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        """Handle an incoming client connection."""
        self._client_count += 1
        client_id = f"client_{self._client_count}"
        peername = client_writer.get_extra_info("peername")
        logger.info("FTP client #%d connected from %s", self._client_count, peername)

        upstream_writer: asyncio.StreamWriter | None = None
        upstream_reader: asyncio.StreamReader | None = None
        data_servers: list[asyncio.Server] = []
        active_data_transfers = 0
        data_transfer_done = asyncio.Event()
        data_transfer_done.set()  # Initially no transfers, so "done"

        try:
            logger.debug("Connecting to printer FTP at %s:%d", self.printer_ip, self.port)
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.printer_ip, self.port, ssl=self._ssl_context),
                timeout=10.0,
            )
            logger.debug("Connected to printer FTP")

            # Extract SSL session for reuse (required by BambuLab printers)
            control_ssl_obj = upstream_writer.get_extra_info("ssl_object")
            control_session = control_ssl_obj.session if control_ssl_obj else None
            if control_session:
                logger.debug("SSL session extracted for data channel reuse")
            else:
                logger.warning("No SSL session available - data connections may fail")

            # --- Data Connection Helper ---
            async def handle_data_connection(
                target_ip: str,
                target_port: int,
                r: asyncio.StreamReader,
                w: asyncio.StreamWriter,
            ) -> None:
                """Handle a data connection for a specific PASV request."""
                nonlocal active_data_transfers
                peer = w.get_extra_info("peername")
                logger.debug("Data connection from %s -> %s:%d", peer, target_ip, target_port)

                # Track active transfers for QUIT handling
                active_data_transfers += 1
                data_transfer_done.clear()

                target_w: asyncio.StreamWriter | None = None
                try:
                    # Prepare SSL context for data connection
                    # BambuLab printers require TLS session reuse from control channel
                    ctx = self._ssl_context
                    token = None
                    if control_session:
                        token = ssl_session_context.set(control_session)
                        logger.debug("Attempting TLS session reuse for data connection")
                    else:
                        logger.warning("No session to reuse - printer may reject connection")

                    try:
                        target_r, target_w = await asyncio.open_connection(
                            target_ip, target_port, ssl=ctx
                        )
                        # Verify session was actually reused
                        data_ssl_obj = target_w.get_extra_info("ssl_object")
                        if data_ssl_obj and data_ssl_obj.session_reused:
                            logger.debug("TLS session reuse successful")
                        else:
                            logger.warning("TLS session was NOT reused - transfer may fail")
                        logger.debug("Connected to printer data port %s:%d", target_ip, target_port)
                    finally:
                        if token:
                            ssl_session_context.reset(token)

                    async def fwd(src, dst, direction: str):
                        """Forward data from src to dst with proper error handling."""
                        bytes_transferred = 0
                        try:
                            while True:
                                try:
                                    data = await src.read(65536)
                                except Exception as read_err:
                                    logger.error(
                                        "Read error on %s after %d bytes: %s",
                                        direction,
                                        bytes_transferred,
                                        read_err,
                                    )
                                    raise
                                if not data:
                                    logger.debug(
                                        "EOF detected on %s after %d bytes",
                                        direction,
                                        bytes_transferred,
                                    )
                                    break
                                try:
                                    dst.write(data)
                                    await dst.drain()
                                except Exception as write_err:
                                    logger.error(
                                        "Write error on %s after %d bytes: %s",
                                        direction,
                                        bytes_transferred,
                                        write_err,
                                    )
                                    raise
                                bytes_transferred += len(data)
                        except asyncio.CancelledError:
                            logger.debug(
                                "Forwarding %s cancelled after %d bytes",
                                direction,
                                bytes_transferred,
                            )
                            raise
                        except Exception as e:
                            logger.error(
                                "Forwarding %s failed after %d bytes: %s",
                                direction,
                                bytes_transferred,
                                e,
                            )
                            raise
                        finally:
                            logger.debug(
                                "Forwarding %s complete: %d bytes", direction, bytes_transferred
                            )

                    t1 = asyncio.create_task(fwd(r, target_w, "client->printer"))
                    t2 = asyncio.create_task(fwd(target_r, w, "printer->client"))

                    # Wait for either direction to complete (FTP data is unidirectional)
                    done, pending = await asyncio.wait(
                        [t1, t2], return_when=asyncio.FIRST_COMPLETED
                    )

                    # Check for exceptions in completed task
                    for task in done:
                        exc = task.exception()
                        if exc:
                            logger.error("Data transfer failed: %s", exc)

                    # Signal end-of-stream by closing the write side
                    # For SSL sockets, write_eof() doesn't work - we must close
                    # For uploads: client finished -> close upstream to signal printer
                    # For downloads: printer finished -> close downstream to signal client
                    if t1 in done and not t1.exception():
                        # Client finished sending (upload) - close upstream connection
                        logger.debug("Upload complete, flushing and closing upstream connection")
                        try:
                            # Ensure all buffered data is sent before close
                            await target_w.drain()
                            logger.debug("Drain complete, closing connection")
                            target_w.close()
                            # Use timeout to avoid blocking if SSL shutdown hangs
                            try:
                                await asyncio.wait_for(target_w.wait_closed(), timeout=2.0)
                                logger.debug("Upstream connection closed successfully")
                            except TimeoutError:
                                # SSL shutdown is hanging - abort the transport to force EOF
                                logger.debug("wait_closed timed out, aborting transport")
                                transport = target_w.transport
                                if transport:
                                    transport.abort()
                        except Exception as e:
                            logger.debug("Error closing upstream: %s", e)
                        target_w = None  # Prevent double-close in finally
                    if t2 in done and not t2.exception():
                        # Printer finished sending (download) - close downstream connection
                        logger.debug("Download complete, closing downstream connection")
                        await close_writer(w)

                    # Cancel the other direction (it was idle for this transfer type)
                    for task in pending:
                        task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await task

                except Exception as exc:
                    logger.error("Data proxy error: %s", exc)
                finally:
                    await close_writer(w)
                    if target_w:
                        await close_writer(target_w)
                    logger.debug("Data connection closed")
                    # Signal that this transfer is done
                    active_data_transfers -= 1
                    if active_data_transfers == 0:
                        data_transfer_done.set()

            # --- Forwarding Logic ---

            async def forward_client_to_printer():
                """Forward commands from client to printer."""
                try:
                    while self._running:
                        # FTP is line-based for commands. Reading line-by-line is safer regarding boundaries.
                        # However, raw bridging like TLSProxy is usually better unless we need to inspect.
                        # We do logging, so we prefer line-based or peeking.
                        # Let's stick to line-based for control channel as it's cleaner for logging.
                        line = await client_reader.readline()
                        if not line:
                            break

                        # Logging
                        with contextlib.suppress(Exception):
                            cmd_str = line.decode("utf-8", "replace").strip()
                            if cmd_str:
                                logger.debug("C->P: %s", self._mask_password(cmd_str))

                            # Block EPSV command to force PASV
                            if cmd_str.upper().startswith("EPSV"):
                                logger.info("Blocking EPSV command from client")
                                client_writer.write(b"502 Command not implemented\r\n")
                                await client_writer.drain()
                                continue

                            # Delay QUIT until data transfers complete
                            # Some clients (Bambuddy) send QUIT during active transfers
                            if cmd_str.upper() == "QUIT" and active_data_transfers > 0:
                                logger.debug(
                                    "Delaying QUIT until %d data transfer(s) complete",
                                    active_data_transfers,
                                )
                                await data_transfer_done.wait()
                                logger.debug("Data transfers complete, forwarding QUIT")

                        upstream_writer.write(line)
                        await upstream_writer.drain()
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    logger.error("Error forwarding C->P: %s", exc)

            async def forward_printer_to_client():
                """Forward responses from printer to client, rewriting PASV."""
                try:
                    while self._running:
                        line = await upstream_reader.readline()
                        if not line:
                            break

                        # Parse and log
                        try:
                            resp_str = line.decode("utf-8", "replace").strip()
                            if resp_str:
                                logger.debug("P->C: %s", resp_str)

                            # PASV Rewrite Logic
                            pasv_match = re.search(
                                r"227 .*\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", resp_str
                            )
                            if pasv_match:
                                # Only extract port from PASV - we always use printer_ip
                                # for upstream data connections (PASV IP may be 0.0.0.0)
                                _, _, _, _, p1, p2 = map(int, pasv_match.groups())
                                target_port = p1 * 256 + p2

                                # Create temp server
                                def make_handler(tip, tport):
                                    async def handler(r, w):
                                        await handle_data_connection(tip, tport, r, w)

                                    return handler

                                ds = await asyncio.start_server(
                                    make_handler(self.printer_ip, target_port),
                                    self.bind_address,
                                    0,
                                    ssl=self._server_ssl_context,
                                )
                                data_servers.append(ds)

                                # Get ephemeral port
                                if ds.sockets:
                                    _, port = ds.sockets[0].getsockname()[:2]

                                    # Formulate new PASV response
                                    proxy_sock = client_writer.get_extra_info("sockname")
                                    proxy_ip = proxy_sock[0]
                                    ip_parts = proxy_ip.split(".")
                                    if len(ip_parts) == 4:
                                        p1_new = port // 256
                                        p2_new = port % 256
                                        new_args = f"{ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{p1_new},{p2_new}"

                                        prefix = resp_str[: resp_str.find("(") + 1]
                                        suffix = resp_str[resp_str.find(")") :]
                                        new_resp = f"{prefix}{new_args}{suffix}"
                                        logger.info("Rewrote PASV: %s -> %s", resp_str, new_resp)
                                        line = (new_resp + "\r\n").encode("utf-8")
                        except Exception as exc:
                            logger.error("Error parsing PASV: %s", exc)

                        client_writer.write(line)
                        await client_writer.drain()
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    logger.error("Error forwarding P->C: %s", exc)

            # Start tasks
            task1 = asyncio.create_task(forward_client_to_printer(), name=f"ftp_c2p_{client_id}")
            task2 = asyncio.create_task(forward_printer_to_client(), name=f"ftp_p2c_{client_id}")

            self._active_connections[client_id] = (task1, task2)

            # Wait for completion
            done, pending = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)

            for t in pending:
                t.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(*done, return_exceptions=True)

        except TimeoutError:
            logger.warning("Client #%d connection timeout", self._client_count)
        except Exception as e:
            logger.error("Client #%d error: %s", self._client_count, e)
        finally:
            self._active_connections.pop(client_id, None)

            logger.info("Client #%d disconnected", self._client_count)
            await close_writer(client_writer)
            if upstream_writer:
                await close_writer(upstream_writer)

            # Clean up data servers
            for s in data_servers:
                s.close()
                await s.wait_closed()

    @staticmethod
    def _mask_password(command: str) -> str:
        """Mask password in FTP command for logging."""
        if command.upper().startswith("PASS "):
            return "PASS ****"
        return command
