# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for dependency caching
COPY go.mod go.sum ./

# Copy the prompt-classifier Go client (referenced by replace directive in go.mod)
COPY --from=classifier-client . /prompt-classifier/client/go

# Download dependencies (cached unless go.mod/go.sum change)
RUN go mod download

# Copy source code
COPY . .

# Build the application with BuildKit cache mounts.
# The go-build cache persists compiled packages across Docker builds,
# so only changed packages are recompiled (~10s vs ~10min).
# All storage drivers are pure Go (no CGO required).
ARG BUILD_HASH=""
ARG BUILD_NUMBER=""
ARG BUILD_DATE=""
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s \
    -X 'github.com/soapbucket/proxy/internal/version.BuildHash=${BUILD_HASH}' \
    -X 'github.com/soapbucket/proxy/internal/version.BuildNumber=${BUILD_NUMBER}' \
    -X 'github.com/soapbucket/proxy/internal/version.BuildDate=${BUILD_DATE}'" \
    -o proxy ./cmd/sbproxy/

# Final stage
FROM alpine:latest
# Using alpine:latest for minimal production image

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Create a non-root user
RUN addgroup -g 1000 proxy && \
    adduser -D -u 1000 -G proxy proxy

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/proxy /app/proxy

# Copy entrypoint script
COPY deploy/scripts/docker-entrypoint.sh /app/docker-entrypoint.sh

# Create directories for config, logs, and data
RUN mkdir -p /app/config /app/logs /app/data && \
    chmod +x /app/docker-entrypoint.sh && \
    chown -R proxy:proxy /app

# Switch to non-root user
USER proxy

# Expose common proxy ports
# 8080: HTTP
# 8443: HTTPS (TCP) and HTTP/3 (UDP)
# 8888: Telemetry/Metrics
EXPOSE 8080/tcp
EXPOSE 8443/tcp
EXPOSE 8443/udp
EXPOSE 8888/tcp

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Default command
CMD ["serve"]

