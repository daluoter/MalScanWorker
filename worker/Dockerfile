FROM python:3.11-slim

WORKDIR /app

# Install system dependencies: ClamAV, YARA, libmagic
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-freshclam \
    yara \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV virus database (best effort at build time)
RUN freshclam || true

# Install poetry
RUN pip install poetry

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-root --no-interaction --no-ansi

# Copy source code
COPY src/ ./src/

# Copy YARA rules (if any)
COPY rules/ /etc/yara/rules/

# Set PYTHONPATH so Python can find the malscan_worker module
ENV PYTHONPATH=/app/src

# Expose metrics port
EXPOSE 9090

# Run the worker
CMD ["python", "-m", "malscan_worker.main"]
