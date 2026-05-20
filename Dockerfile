FROM python:3.12-slim

LABEL maintainer="Plinio Lima"
LABEL description="Munin — Cyber Risk Intelligence Platform"

# ── System deps ───────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python deps ───────────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Source ────────────────────────────────────────────────────────────────────
COPY . .

# ── Data directories ─────────────────────────────────────────────────────────
RUN mkdir -p /data/history /data/reports /data/baselines /data/scans

# ── Expose dashboard port ─────────────────────────────────────────────────────
EXPOSE 5000

ENV MUNIN_DASHBOARD_PORT=5000
ENV OLLAMA_HOST=http://ollama:11434
ENV ENABLE_NLP=true

CMD ["python3", "dashboard.py", "--host", "0.0.0.0"]
