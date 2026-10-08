# syntax=docker/dockerfile:1.7

FROM python:3.11-slim

WORKDIR /app

# Install Poetry.
# company_ca is optional and is only used during this build step.
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

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

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

# Copy source code
COPY src/ ./src/

# Ensure /tmp is writable for multipart file uploads
RUN mkdir -p /tmp && chmod 1777 /tmp

# Set PYTHONPATH so Python can find the malscan module
ENV PYTHONPATH=/app/src
ENV TMPDIR=/tmp

EXPOSE 8000

CMD ["uvicorn", "malscan.main:app", "--host", "0.0.0.0", "--port", "8000"]
