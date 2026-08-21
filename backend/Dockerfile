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

# Container health: the open /health endpoint.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
