# PandaProxy - BambuLab Camera Fan-Out Proxy
# Multi-stage build for minimal image size

FROM python:3.13-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev

# Install uv for faster package installation
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY src/ src/

# Install the package
RUN uv pip install --system --no-cache .


# Final stage
FROM python:3.13-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    ffmpeg \
    openssl \
    curl \
    ca-certificates

# Install MediaMTX
ARG MEDIAMTX_VERSION=1.9.3
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
        amd64) ARCH="amd64" ;; \
        arm64) ARCH="arm64v8" ;; \
        arm) ARCH="armv7" ;; \
        *) ARCH="amd64" ;; \
    esac && \
    curl -fsSL "https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VERSION}/mediamtx_v${MEDIAMTX_VERSION}_linux_${ARCH}.tar.gz" | \
    tar -xz -C /usr/local/bin mediamtx && \
    chmod +x /usr/local/bin/mediamtx

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/pandaproxy /usr/local/bin/pandaproxy

# Create non-root user
RUN adduser -D -u 1000 pandaproxy
USER pandaproxy

# Set working directory
WORKDIR /home/pandaproxy

# Environment variables (can be overridden)
ENV PRINTER_IP=""
ENV ACCESS_CODE=""
ENV SERIAL_NUMBER=""
ENV BIND_ADDRESS="0.0.0.0"
ENV SERVICES=""
ENV ENABLE_ALL=""

# Expose ports
# 322: RTSP camera (X1/H2/P2)
# 6000: Chamber image (A1/P1)
# 8883: MQTT (printer control/status)
# 990: FTP (file uploads)
EXPOSE 322 6000 8883 990

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f pandaproxy || exit 1

# Run the proxy
ENTRYPOINT ["pandaproxy"]
CMD []
