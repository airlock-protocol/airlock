FROM python:3.12-slim-bookworm
WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx pynacl base58

COPY demo/agent_b/app.py .

EXPOSE 5002
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5002"]
