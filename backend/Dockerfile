FROM python:3.11-slim

LABEL maintainer="ThreatSenseAI"
LABEL description="THREAT-SENSE AI — FastAPI backend"

WORKDIR /app

# System dependencies (libpq for asyncpg, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached until pyproject.toml changes)
COPY pyproject.toml .
# Create a minimal package structure so hatchling can install deps
RUN mkdir -p app && touch app/__init__.py
RUN pip install --no-cache-dir -e .

# Copy the full source
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .

# Create upload directory (must be outside web root)
RUN mkdir -p /app/uploads && chmod 750 /app/uploads

EXPOSE 8000

# Run migrations then start the server
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
