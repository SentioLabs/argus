# Build stage - runs on native platform for fast cross-compilation
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

WORKDIR /app

# Install certs and tzdata to copy to scratch image
RUN apk add --no-cache ca-certificates tzdata

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Cross-compile natively (no QEMU emulation needed)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build \
    -ldflags="-w -s \
        -X github.com/sentiolabs/argus/cmd.Version=$VERSION \
        -X github.com/sentiolabs/argus/cmd.Commit=$COMMIT \
        -X github.com/sentiolabs/argus/cmd.BuildDate=$BUILD_DATE" \
    -o argus .

# Runtime stage - minimal scratch image
FROM scratch

# Copy certs for HTTPS requests to GitHub/Snyk/Jira APIs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary
COPY --from=builder /app/argus /argus

# Run as non-root (numeric UID since scratch has no /etc/passwd)
USER 1000

ENTRYPOINT ["/argus"]
CMD ["--help"]
