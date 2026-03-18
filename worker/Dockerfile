FROM python:3.11-slim

WORKDIR /app

# Install system dependencies: libmagic, unar (for RAR archive extraction)
# ClamAV and YARA are now handled differently
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    unar \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install poetry

# Copy backend package first (worker has a path dependency on malscan-api)
COPY backend/ /backend

# Copy worker dependency files
COPY worker/pyproject.toml worker/poetry.lock* ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-root --no-interaction --no-ansi

# Copy worker source code
COPY worker/src/ ./src/

# Copy YARA rules (if any)
COPY worker/rules/ /etc/yara/rules/

# Set PYTHONPATH so Python can find the malscan_worker module
ENV PYTHONPATH=/app/src

# Expose metrics port
EXPOSE 9090

# Run the worker
CMD ["python", "-m", "malscan_worker.main"]
