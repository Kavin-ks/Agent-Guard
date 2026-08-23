# Agent Guard backend — FastAPI + engine (production image).
FROM python:3.13-slim

# Faster, quieter Python; no .pyc, unbuffered logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTGUARD_DB_PATH=/data/agentguard.db

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Only the application code (no tests, venv, or data).
COPY agentguard ./agentguard
COPY api ./api

# Non-root user; own the persistent data dir so the named volume inherits it.
RUN useradd -r -u 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app
VOLUME ["/data"]
USER appuser

EXPOSE 8000

# Container health: the open /health endpoint. Port follows $PORT (a PaaS like
# Render assigns it); defaults to 8000 for local docker compose.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://localhost:{p}/health').status==200 else 1)"

# Bind the port the platform assigns ($PORT); fall back to 8000 locally. Shell
# form so ${PORT:-8000} expands at runtime — no render.yaml command override needed.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
