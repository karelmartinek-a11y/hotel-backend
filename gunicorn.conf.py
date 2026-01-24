"""Gunicorn configuration for HOTEL backend.

This file is intended to be used inside the Docker container.
Nginx runs on the host and proxies to the container published on 127.0.0.1:8201.

Run (in container):
  gunicorn -c gunicorn.conf.py app.main:app
"""

import multiprocessing
import os

# Bind inside container. The docker-compose publishes to host loopback 127.0.0.1:8201.
bind = os.getenv("GUNICORN_BIND", "0.0.0.0:8000")

# Use Uvicorn worker for FastAPI.
worker_class = "uvicorn.workers.UvicornWorker"

# Conservative defaults for a small hotel server.
# You can override via env if needed.
workers = int(os.getenv("GUNICORN_WORKERS", str(max(2, multiprocessing.cpu_count() * 2))))
threads = int(os.getenv("GUNICORN_THREADS", "1"))

# Timeouts: allow photo uploads and thumbnail generation.
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))

# Logging: write to stdout/stderr (Docker captures logs).
accesslog = os.getenv("GUNICORN_ACCESSLOG", "-")
errorlog = os.getenv("GUNICORN_ERRORLOG", "-")
loglevel = os.getenv("GUNICORN_LOGLEVEL", "info")

# Avoid leaking server implementation details.
server_header = False

# Worker recycling to mitigate memory growth.
max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", "2000"))
max_requests_jitter = int(os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "200"))

# Security-related: do not trust forwarded headers unless behind our Nginx.
# Nginx is on the host; docker-compose network is private.
forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")

# Preload app to reduce memory usage (copy-on-write) when possible.
preload_app = os.getenv("GUNICORN_PRELOAD", "true").lower() in ("1", "true", "yes")
