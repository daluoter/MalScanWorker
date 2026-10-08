# syntax=docker/dockerfile:1.7

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies.
# company_ca is optional and is only used during this build step.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        apt-get -o Acquire::https::CaInfo=/tmp/build-ca.crt update; \
        apt-get -o Acquire::https::CaInfo=/tmp/build-ca.crt install -y --no-install-recommends \
            libmagic1 \
            unar; \
        rm -rf /var/lib/apt/lists/*; \
    else \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            libmagic1 \
            unar; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Install Poetry.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        PIP_CERT=/tmp/build-ca.crt \
        SSL_CERT_FILE=/tmp/build-ca.crt \
        REQUESTS_CA_BUNDLE=/tmp/build-ca.crt \
            pip install poetry; \
    else \
        pip install poetry; \
    fi

# Copy backend package first (worker has a path dependency on malscan-api)
COPY backend/ /backend

# Copy worker dependency files
COPY worker/pyproject.toml worker/poetry.lock* ./

# Install dependencies.
RUN --mount=type=secret,id=company_ca,required=false \
    set -eu; \
    trap 'rm -f /tmp/build-ca.crt' EXIT; \
    if [ -f /run/secrets/company_ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt \
            /run/secrets/company_ca \
            > /tmp/build-ca.crt; \
        SSL_CERT_FILE=/tmp/build-ca.crt \
        REQUESTS_CA_BUNDLE=/tmp/build-ca.crt \
            poetry config virtualenvs.create false; \
        SSL_CERT_FILE=/tmp/build-ca.crt \
        REQUESTS_CA_BUNDLE=/tmp/build-ca.crt \
            poetry install --only main --no-root --no-interaction --no-ansi; \
    else \
        poetry config virtualenvs.create false; \
        poetry install --only main --no-root --no-interaction --no-ansi; \
    fi

# Copy worker source code
COPY worker/src/ ./src/

# Copy YARA rules
COPY worker/rules/ /etc/yara/rules/

ENV PYTHONPATH=/app/src

EXPOSE 9090

CMD ["python", "-m", "malscan_worker.main"]
