# PandaProxy

BambuLab Multi-Service Proxy - Proxy camera, MQTT, and FTP from BambuLab printers to multiple clients.

[![Release](https://img.shields.io/badge/Version-0.0.0-green?style=for-the-badge)](https://github.com/karaktaka/pandaproxy/releases)
![AI-Powered](https://img.shields.io/badge/Developed%20with-AI-blue?style=for-the-badge&logo=google-gemini&logoColor=white)

## Overview

BambuLab printers in LAN Mode with Development Mode enabled expose several services:
- **Camera (RTSPS)** on port 322 - X1, X1C, X1E, H2C, H2D, H2D Pro, H2S, P2S
- **Camera (Chamber Image)** on port 6000 - A1, A1 Mini, P1P, P1S
- **MQTT** on port 8883 (MQTTS) - Printer control and status for all models
- **FTP** on port 990 (implicit FTPS) - File uploads (gcode, 3mf) for all models

These services have limited simultaneous connection support. PandaProxy acts as a transparent man-in-the-middle proxy that:
1. **Automatically detects** the camera protocol used by your printer
2. Maintains connections to the printer's services
3. Serves **multiple clients** using the same protocols
4. Clients connect to PandaProxy as if they were connecting directly to the printer

## Features

- **Multiservice proxy**: Camera, MQTT, and FTP in one application
- **Automatic camera type detection** - no manual configuration needed
- **Chamber image proxy** (port 6000) for A1/P1 printers with TLS
- **RTSP proxy** (port 322) for X1/H2/P2 printers using FFmpeg + MediaMTX
- **MQTT proxy** (port 8883) for printer control and status with TLS
- **FTP proxy** (port 990) for file uploads with implicit TLS
- Same authentication (access code) as the printer
- Automatic reconnection on connection loss
- Docker support with Alpine-based image

## Requirements

### For Local CLI Usage

- Python 3.13+
- OpenSSL (for TLS certificate generation)
- FFmpeg (for RTSP camera proxy only)
- MediaMTX (for RTSP camera proxy only) - [Download from GitHub](https://github.com/bluenviron/mediamtx/releases)

### For Docker

- Docker & Docker Compose
- All dependencies are included in the image

## Installation

### Using uv (recommended)

```bash
# Clone the repository
git clone https://github.com/karaktaka/pandaproxy.git
cd pandaproxy

# Install with uv
uv sync

# Run
uv run pandaproxy --help
```

### Using pip

```bash
pip install .
pandaproxy --help
```

## Usage

### CLI

```bash
# Camera only (default) - camera type is automatically detected
pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001

# Enable all services (camera, mqtt, ftp)
pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001 --enable-all

# Enable specific services
pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001 --services camera,mqtt


# Verbose logging
pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001 -v
```

### CLI Options

| Option             | Short | Environment Variable | Description                                      |
|--------------------|-------|----------------------|--------------------------------------------------|
| `--printer-ip`     | `-p`  | `PRINTER_IP`         | IP address of the BambuLab printer               |
| `--access-code`    | `-a`  | `ACCESS_CODE`        | Access code (found in printer settings)          |
| `--serial-number`  | `-s`  | `SERIAL_NUMBER`      | Printer serial number                            |
| `--bind`           | `-b`  | `BIND_ADDRESS`       | Address to bind proxy servers (default: 0.0.0.0) |
| `--services`       |       | `SERVICES`           | Comma-separated services: camera,mqtt,ftp        |
| `--enable-all`     |       | `ENABLE_ALL`         | Enable all services                              |
| `--verbose`        | `-v`  |                      | Enable debug logging                             |

### Environment Variables

All options can be set via environment variables:

```bash
export PRINTER_IP=192.168.1.100
export ACCESS_CODE=12345678
export SERIAL_NUMBER=01P00A000000001
export BIND_ADDRESS=0.0.0.0
export SERVICES=camera,mqtt,ftp
# Or use ENABLE_ALL=1 to enable all services

pandaproxy
```

### Docker

```bash
# Copy example env file
cp .env.example .env

# Edit with your printer details
nano .env

# Run with Docker Compose
docker compose up -d

# View logs
docker compose logs -f
```

Or run directly:

```bash
docker run -d \
  -e PRINTER_IP=192.168.1.100 \
  -e ACCESS_CODE=12345678 \
  -e SERIAL_NUMBER=01P00A000000001 \
  -e ENABLE_ALL=1 \
  -p 322:322 \
  -p 6000:6000 \
  -p 8883:8883 \
  -p 990:990 \
  pandaproxy:latest
```

## Connecting Clients

Once PandaProxy is running, connect your clients to the proxy instead of the printer:

### Camera - Chamber Image (A1/P1 printers)

Clients connect to `<proxy-ip>:6000` using TLS with the same binary authentication protocol.
This is typically used by BambuLab apps and compatible third-party software.

### Camera - RTSPS (X1/H2/P2 printers)

```
rtsps://bblp:<access_code>@<proxy-ip>:322/stream
```

Example with VLC:
```bash
vlc rtsps://bblp:12345678@192.168.1.50:322/stream
```

### MQTT (All printers)

Connect to `<proxy-ip>:8883` using MQTTS (MQTT over TLS):
- Username: `bblp`
- Password: Your access code

Example with mosquitto_sub:
```bash
mosquitto_sub -h 192.168.1.50 -p 8883 \
  --cafile /path/to/ca.crt --insecure \
  -u bblp -P 12345678 \
  -t "device/01P00A000000001/report"
```

### FTP (All printers)

Connect to `<proxy-ip>:990` using implicit FTPS:
- Username: `bblp`
- Password: Your access code

Example with lftp:
```bash
lftp -u bblp,12345678 ftps://192.168.1.50:990
```

## Architecture

```
┌─────────────┐                 ┌──────────────┐                  ┌─────────┐
│  BambuLab   │◄───Connection───│  PandaProxy  │◄───Connections───│ Clients │
│   Printer   │                 │              │                  │         │
└─────────────┘                 └──────────────┘                  └─────────┘
    :322 RTSPS                      :322 RTSPS     (X1/H2/P2 Camera)
    :6000 TLS                       :6000 TLS      (A1/P1 Camera)
    :8883 MQTTS                     :8883 MQTTS    (Control/Status)
    :990 FTPS                       :990 FTPS      (File Uploads)
```

### How It Works

1. **Camera Proxy**: Auto-detects camera type and starts appropriate proxy
   - Chamber Image: Pure Python asyncio TLS proxy with fan-out
   - RTSP: FFmpeg pulls from printer, MediaMTX serves clients

2. **MQTT Proxy**: Uses TCP proxy with TLS termination
   - Accepts client connections with TLS
   - Forwards traffic bidirectionally to printer's MQTT broker
   - Transparently handles MQTT traffic

3. **FTP Proxy**: Pure Python asyncio FTPS proxy
   - Accepts implicit TLS connections
   - Supports active mode transfers (client-to-printer uploads)
   - Passive mode is not supported

## Service Ports

| Service           | Printer Port | Proxy Port  | Protocol      |
|-------------------|--------------|-------------|---------------|
| Camera (X1/H2/P2) | 322          | 322         | RTSPS         |
| Camera (A1/P1)    | 6000         | 6000        | TLS Binary    |
| MQTT              | 8883         | 8883        | MQTTS         |
| FTP Control       | 990          | 990         | Implicit FTPS |

## Printer Model Support

| Model                  | Camera          | MQTT | FTP |
|------------------------|-----------------|------|-----|
| X1, X1C, X1E           | RTSPS (:322)    | ✓    | ✓   |
| H2C, H2D, H2D Pro, H2S | RTSPS (:322)    | ✓    | ✓   |
| P2S                    | RTSPS (:322)    | ✓    | ✓   |
| A1, A1 Mini            | Chamber (:6000) | ✓    | ✓   |
| P1P, P1S               | Chamber (:6000) | ✓    | ✓   |

## Troubleshooting

### Camera connection fails

- Verify the printer IP and access code
- Ensure the printer has LAN Mode and Development Mode enabled
- Check if the camera port is accessible on the printer
- For RTSP: Verify FFmpeg and MediaMTX are installed
- Try running with `-v` for verbose logs

### MQTT connection fails

- Verify the printer IP and access code
- Ensure the printer has LAN Mode enabled
- Check if port 8883 is accessible on the printer
- Verify OpenSSL is installed for TLS cert generation

### FTP connection fails

- Verify the printer IP and access code
- Ensure the printer has LAN Mode enabled
- Check if port 990 is accessible on the printer
- Use implicit FTPS mode (not explicit FTPS)
- Use active mode (PORT) for data transfers - passive mode is not supported

### Privileged ports (322, 990, 6000)

On Linux, binding to ports below 1024 requires root or capabilities:

```bash
# Option 1: Run as root (not recommended)
sudo pandaproxy ...

# Option 2: Use setcap (recommended for production)
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Option 3: Use Docker (handles this automatically)
docker compose up -d
```

## License

MIT License
