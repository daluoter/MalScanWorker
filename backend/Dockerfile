FROM python:3.11-slim

WORKDIR /app

# Install poetry
RUN pip install poetry

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Update lock file if needed and install dependencies
RUN poetry config virtualenvs.create false \
    && poetry lock --no-update || true \
    && poetry install --only main --no-root --no-interaction --no-ansi

# Copy source code
COPY src/ ./src/

# Set PYTHONPATH so Python can find the malscan module
ENV PYTHONPATH=/app/src

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "malscan.main:app", "--host", "0.0.0.0", "--port", "8000"]
