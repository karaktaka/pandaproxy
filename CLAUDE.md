# PandaProxy - Claude Code Instructions

## Project Overview

**PandaProxy** is a Python-based multi-service proxy for BambuLab 3D printers. It acts as a "man-in-the-middle" to multiplex connections, allowing multiple clients to connect to a single printer service simultaneously.

### Services Proxied

| Service        | Port | Protocol                 | Printers   |
| -------------- | ---- | ------------------------ | ---------- |
| Chamber Camera | 6000 | TLS + custom binary      | A1, P1     |
| RTSP Camera    | 322  | RTSP via FFmpeg/MediaMTX | X1, H2, P2 |
| MQTT           | 8883 | TLS-encrypted MQTT       | All        |
| FTP            | 990  | Implicit FTPS            | All        |

## Tech Stack

- **Python:** 3.13+ with `asyncio`
- **CLI:** `typer`
- **Dependencies:** Managed with `uv`
- **Linting/Formatting:** `ruff`
- **Testing:** `pytest` + `pytest-asyncio`
- **Versioning:** `hatch-vcs` (git tags)
- **Container:** Docker (Alpine Linux)

## Development Commands

```bash
# Install dependencies
uv sync

# Run the CLI
uv run pandaproxy -p <PRINTER_IP> -a <ACCESS_CODE> -s <SERIAL_NUMBER>

# Run tests
uv run pytest tests/ -v

# Lint
uv run ruff check .

# Format
uv run ruff format .
```

## Project Structure

```
src/pandaproxy/
├── cli.py              # CLI entry point (Typer)
├── chamber_proxy.py    # Chamber camera proxy (port 6000)
├── rtsp_proxy.py       # RTSP proxy (port 322)
├── mqtt_proxy.py       # MQTT proxy (port 8883)
├── mqtt_protocol.py    # Minimal MQTT wire protocol (client-facing packet parsing/building)
├── ftp_proxy.py        # FTP proxy (port 990)
├── detection.py        # Camera type auto-detection
├── fanout.py           # Stream fan-out logic
├── protocol.py         # Shared SSL/auth utilities
├── helper.py           # Common helper functions
└── printer.cer         # TLS certificate for printer connections
```

## Coding Conventions

- **AsyncIO:** All network I/O must be non-blocking
- **Type Hints:** Required for all function signatures
- **Logging:** Use standard `logging` module
- **Line Length:** 100 characters (configured in `pyproject.toml`)

## Git Workflow

### Commits

This is a **GitHub repository**. All commits should include the co-author line:

```
Co-Authored-By: Claude <noreply@anthropic.com>
```

Use conventional commit format: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`

### Versioning

Versions are derived from git tags via `hatch-vcs`:

- Tags: `v0.0.1` → version `0.0.1`
- Dev builds: `0.0.1-10-g766210a` → `0.0.1.dev10+g766210a`

## CI/CD

GitHub Actions workflows:

- **`docker.yml`**: Build & push multi-arch images on push to `main` or tags
- **`docker-pr.yml`**: Validate Docker builds on PRs
- **`docker-pr-build.yml`**: Build & push PR images on `/build-pr` comment (maintainer-only)
- **`lint.yml`**: Run ruff checks

### Testing GitHub Actions Locally

Use these tools to validate workflows before pushing:

```bash
# Syntax validation (fast, catches most errors)
actionlint .github/workflows/<workflow>.yml

# Dry-run workflow execution with mock event
act <event> -e <event.json> -n -W .github/workflows/<workflow>.yml

# List jobs that would run
act <event> -e <event.json> -l -W .github/workflows/<workflow>.yml
```

**Tools:**
- **`actionlint`**: Validates YAML syntax, action references, expressions, and shellcheck integration
- **`act`**: Simulates workflow execution using Docker; useful for testing job dependencies and `if` conditions

**Tips:**
- Empty output from `act -n` means the job's `if` condition filtered it out
- For Apple Silicon: add `--container-architecture linux/amd64` to `act` commands
- Create mock event payloads in `/tmp/` for testing different trigger scenarios

## Docker

```bash
# Local build (use podman locally)
podman build -t pandaproxy .

# Run with docker-compose
docker compose up -d
```

### Privileged Ports

Ports 322, 990 are privileged (<1024). The Docker image uses `CAP_NET_BIND_SERVICE` to allow binding as non-root.
