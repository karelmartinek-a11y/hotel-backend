FROM python:3.11-slim

# Systémové závislosti pro psycopg (binary), Pillow a tini
RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential libpq-dev curl tini \
  && rm -rf /var/lib/apt/lists/*

# Uživatel sladěný s existujícími bind mounty (uid/gid 998)
RUN groupadd -g 998 appuser && useradd -m -u 998 -g 998 appuser

WORKDIR /app

# Přeneseme zdrojáky backendu (bez .git – v produkční kopii stejně není)
COPY . /app/backend
COPY deploy/entrypoint.sh /app/deploy/entrypoint.sh
RUN chmod +x /app/deploy/entrypoint.sh
# Odstraníme případný zbloudilý .git ve statických šablonách
RUN rm -rf /app/backend/app/web/.git

# Instalace Python závislostí
WORKDIR /app/backend
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1

USER appuser
WORKDIR /app/backend
ENTRYPOINT ["/usr/bin/tini", "--", "/app/deploy/entrypoint.sh"]
