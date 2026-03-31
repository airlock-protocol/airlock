# Airlock gateway — inject secrets at runtime (never bake AIRLOCK_* secrets into layers).
# Installs the [redis] extra so AIRLOCK_REDIS_URL works for multi-replica internal deploys.
FROM python:3.12-slim-bookworm

WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip

COPY pyproject.toml README.md LICENSE ./
COPY airlock ./airlock

RUN pip install --no-cache-dir ".[redis]"

ENV AIRLOCK_HOST=0.0.0.0
ENV AIRLOCK_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/live', timeout=4)"

CMD ["python", "-m", "uvicorn", "airlock.gateway.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "60"]
