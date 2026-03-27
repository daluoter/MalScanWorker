# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Cache dependency download (separate go.mod copy from source copy)
COPY go.mod go.sum ./
RUN go mod download

# Build static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ingest ./cmd/ingest

# Runtime stage
FROM alpine:3.19

# Non-root user with uid 1000 (matches K8s runAsNonRoot: true, runAsUser: 1000)
RUN adduser -D -u 1000 ingest

# ca-certificates needed for TLS connections (MinIO with MINIO_SECURE=true)
RUN apk add --no-cache ca-certificates

COPY --from=builder /ingest /ingest

USER ingest

EXPOSE 8080

ENTRYPOINT ["/ingest"]
