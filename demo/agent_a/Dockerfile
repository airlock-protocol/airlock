FROM python:3.12-slim-bookworm
WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY airlock ./airlock
RUN pip install --no-cache-dir .
RUN pip install --no-cache-dir fastapi uvicorn httpx

WORKDIR /app
COPY demo/agent_a/app.py .

EXPOSE 5001
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001"]
