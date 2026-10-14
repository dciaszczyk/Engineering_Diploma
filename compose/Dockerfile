FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx

COPY relay/server.py relay/final_dest.py ./

# PORT is set per-service in docker-compose.yml
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]