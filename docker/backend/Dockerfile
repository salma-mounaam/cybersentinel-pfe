FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

# ── Dépendances système ────────────────────────────────────
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    build-essential \
    libpq-dev \
    libpcap-dev \
    tcpdump \
    curl \
    wget \
    git \
    gnupg \
    ca-certificates \
    tar \
    docker.io \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── Docker Compose plugin ──────────────────────────────────
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -SL https://github.com/docker/compose/releases/download/v2.40.1/docker-compose-linux-x86_64 \
    -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# ── Trivy (SCA dépendances — M4) ──────────────────────────
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" \
    > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

# ── Gitleaks (secrets — M4) ───────────────────────────────
RUN wget -O /tmp/gitleaks.tar.gz \
    https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp && \
    mv /tmp/gitleaks /usr/local/bin/gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -f /tmp/gitleaks.tar.gz

# ── Dépendances Python ────────────────────────────────────
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# ── Semgrep dans venv isolé (M4) ──────────────────────────
RUN python -m venv /opt/semgrep-venv && \
    /opt/semgrep-venv/bin/pip install --upgrade pip && \
    /opt/semgrep-venv/bin/pip install semgrep

# ── Répertoires de données ────────────────────────────────
RUN mkdir -p \
    /app/data/raw \
    /app/data/models \
    /app/data/models/backups \
    /app/data/dast_captures \
    /app/data/processed \
    /shared/dast_captures

# ── Code source ────────────────────────────────────────────
COPY . .

# ── Vérification des outils au build ──────────────────────
RUN git --version && \
    docker --version && \
    docker compose version && \
    trivy --version && \
    gitleaks version && \
    /opt/semgrep-venv/bin/semgrep --version

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app/app"]