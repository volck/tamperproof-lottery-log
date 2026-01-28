# Dockerfile for lottery-tlog server
FROM harbor.norsk-tipping.no/dockerhub/golang:alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o lottery-tlog .

# Final stage
FROM harbor.norsk-tipping.no/dockerhub/alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk --no-cache add ca-certificates curl

# Copy binary from builder
COPY --from=builder /build/lottery-tlog .

# Copy default config (will be overridden by volume mount)
COPY config.yaml ./config.yaml.example

# Create data directory
RUN mkdir -p .lottery-data

# Expose HTTPS port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f -k https://localhost:8443/api/status || exit 1

# Run the server
CMD ["./lottery-tlog", "server"]
