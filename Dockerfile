# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o patrol .

# Runtime stage
FROM alpine:3.21

WORKDIR /app

# Install ca-certificates for HTTPS requests to GitHub/Snyk/Jira APIs
RUN apk add --no-cache ca-certificates tzdata

# Copy binary from builder
COPY --from=builder /app/patrol /usr/local/bin/patrol

# Create non-root user
RUN adduser -D -u 1000 patrol
USER patrol

# Default command
ENTRYPOINT ["patrol"]
CMD ["--help"]
