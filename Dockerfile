FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python3-cryptography \
        python3-fastapi \
        python3-itsdangerous \
        python3-jinja2 \
        python3-python-multipart \
        python3-sse-starlette \
        python3-uvicorn \
        python3-yaml \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir --break-system-packages .

EXPOSE 6708 6707
