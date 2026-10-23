FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash build-essential ca-certificates curl gzip skopeo tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir "fastapi>=0.115,<1" "uvicorn>=0.30,<1" \
    && python -m pip install --no-cache-dir . \
    && useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /app/.oci2bin-jobs \
    && chown -R appuser:appuser /app

USER 10001:10001
EXPOSE 10000
CMD ["sh", "-c", "exec uvicorn webapp:app --host 0.0.0.0 --port ${PORT:-10000}"]
