# Use official Python slim image for reduced size
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements.txt and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY config/ ./config/
COPY monitoring/ ./monitoring/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY .env.example ./

# Create directories for certs, logs, and backups
RUN mkdir -p certs logs backups

# Set permissions
RUN chmod -R 600 certs && chmod -R 700 logs backups

# Expose ports
EXPOSE 8443 9090

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TZ=Europe/Zurich

# Run setup script (generates certs if needed)
RUN ./scripts/setup-bridge.sh

# Default command (overridden in docker-compose.yml)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "/app/certs/server.key", "--ssl-certfile", "/app/certs/server.crt", "--workers", "2"]