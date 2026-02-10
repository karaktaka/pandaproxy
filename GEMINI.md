# PandaProxy

## Project Overview

**PandaProxy** is a Python-based multi-service proxy designed for BambuLab 3D printers. It acts as a "man-in-the-middle" to multiplex connections to the printer's services, overcoming the limited simultaneous connection support of the hardware.

**Key Features:**
- **Camera Proxy:**
    - **Chamber Image (A1/P1):** Proxies the TLS-based custom binary protocol on port 6000.
    - **RTSP (X1/H2/P2):** Proxies the RTSP stream on port 322 using FFmpeg and MediaMTX.
    - **Auto-Detection:** Automatically determines the camera protocol used by the printer.
- **MQTT Proxy:** Proxies TLS-encrypted MQTT control/status traffic on port 8883.
- **FTP Proxy:** Proxies implicit FTPS for file uploads on port 990.
- **Fan-out Architecture:** Allows multiple clients to connect to a single printer service simultaneously.

**Tech Stack:**
- **Language:** Python 3.14+
- **Concurrency:** `asyncio`
- **CLI Framework:** `typer`
- **Dependency Management:** `uv`
- **Containerization:** Docker (Alpine Linux base)
- **External Dependencies:** `ffmpeg`, `mediamtx` (for RTSP support)

## Project Structure

```text
/
├── .env.example                # Example environment variables
├── docker-compose.yml          # Docker Compose configuration
├── Dockerfile                  # Multi-stage Docker build definition
├── pyproject.toml              # Project dependencies and configuration
├── README.md                   # User documentation
├── uv.lock                     # Locked dependencies
└── src/
    └── pandaproxy/
        ├── __init__.py
        ├── __main__.py
        ├── chamber_proxy.py    # Chamber camera (port 6000) proxy logic
        ├── cli.py              # CLI entry point using Typer
        ├── detection.py        # Camera type detection logic
        ├── fanout.py           # Stream fan-out logic
        ├── ftp_proxy.py        # FTP (port 990) proxy logic
        ├── mqtt_proxy.py       # MQTT (port 8883) proxy logic
        ├── protocol.py         # Shared protocol utilities (SSL, auth)
        └── rtsp_proxy.py       # RTSP (port 322) proxy logic
```

## Building and Running

### Local Development

This project uses `uv` for dependency management.

1.  **Install Dependencies:**
    ```bash
    uv sync
    ```

2.  **Run CLI:**
    ```bash
    # Basic usage (Camera only)
    uv run pandaproxy -p <PRINTER_IP> -a <ACCESS_CODE> -s <SERIAL_NUMBER>

    # Enable all services (Camera, MQTT, FTP)
    uv run pandaproxy -p <PRINTER_IP> -a <ACCESS_CODE> -s <SERIAL_NUMBER> --enable-all
    ```

3.  **Linting and formatting:**
    ```bash
    # Run ruff linter
    uv run ruff check .
    # Run ruff formatter
    uv run ruff format .
    ```

### Docker Deployment

1.  **Configuration:**
    Copy `.env.example` to `.env` and configure your printer details.

2.  **Run with Docker Compose:**
    ```bash
    docker compose up -d
    ```

## Development Conventions

- **Code Style:** Adhere to `ruff` defaults. The configuration is in `pyproject.toml`.
- **AsyncIO:** The core logic is built on `asyncio`. Ensure non-blocking I/O for all network operations.
- **Type Hinting:** Use strict type hints for all function signatures and class attributes.
- **Logging:** Use the standard `logging` module.
- **Privileged Ports:** Note that ports 322, 990, and 6000 are privileged (<1024). In Docker, this is handled via `CAP_NET_BIND_SERVICE`. For local dev, you might need `sudo` or port mapping if binding to these specific ports is required.
