# syntax=docker/dockerfile:1.7

# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Cache dependency download (separate go.mod copy from source copy)
COPY go.mod go.sum ./

# Optional extra CA for environments with HTTPS inspection.
# The secret is only mounted for this RUN step and is not stored in the image.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        SSL_CERT_FILE=/tmp/build-ca.crt go mod download; \
    else \
        go mod download; \
    fi

# Build static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ingest ./cmd/ingest

# Runtime stage
FROM alpine:3.19

# Non-root user with uid 1000 (matches K8s runAsNonRoot: true, runAsUser: 1000)
RUN adduser -D -u 1000 ingest

# ca-certificates needed for TLS connections (MinIO with MINIO_SECURE=true).
# company_ca is optional and only used during the package installation step.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        SSL_CERT_FILE=/tmp/build-ca.crt apk add --no-cache ca-certificates; \
    else \
        apk add --no-cache ca-certificates; \
    fi

COPY --from=builder /ingest /ingest

USER ingest

EXPOSE 8080

ENTRYPOINT ["/ingest"]
