FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip \
    && pip install \
        "cryptography>=42.0.0" \
        "fastapi>=0.115.0" \
        "itsdangerous>=2.2.0" \
        "jinja2>=3.1.0" \
        "python-multipart>=0.0.9" \
        "pyyaml>=6.0" \
        "sse-starlette>=2.0.0" \
        "uvicorn>=0.30.0"

COPY . /app

EXPOSE 8443 8080
