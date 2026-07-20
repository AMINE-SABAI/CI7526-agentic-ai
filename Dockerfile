# ─────────────────────────────────────────────
#  CySyMo — Dockerfile
#  Base: python:3.11-slim
#  Runs: uvicorn backend:app on port 8000
# ─────────────────────────────────────────────

FROM python:3.11-slim

# system deps (none needed beyond pip)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy project files
COPY . .

# make sure the static folder exists
RUN mkdir -p static

# data folder for SQLite db (will be overridden by volume mount)
RUN mkdir -p /data
ENV CYSYMO_DB_PATH=/data/cysymo_data.db

EXPOSE 8000

CMD ["uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "8000"]
