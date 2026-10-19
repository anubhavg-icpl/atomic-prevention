FROM node:22-alpine AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build


FROM python:3.11-slim AS runtime

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY schemas/ ./schemas/
COPY agent/ ./agent/
COPY --from=frontend-builder /build/frontend/out ./frontend-static/

RUN useradd --create-home --uid 10001 atomicprevention \
    && mkdir -p /app/data /app/data/mitre_cache \
    && chown -R atomicprevention:atomicprevention /app

USER atomicprevention

ENV MA_DATABASE_URL="sqlite+aiosqlite:///./data/atomic_prevention.db" \
    MA_DATA_DIR="/app/data" \
    MA_MITRE_CACHE_DIR="/app/data/mitre_cache" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=6 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"]

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
