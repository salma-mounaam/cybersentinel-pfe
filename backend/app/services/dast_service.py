# ============================================================
# M5 — Service DAST Sandbox Isolée — v14 FINAL
# Fix v14.3 : _wait_for_uploaded_app TCP + HTTP + ZAP notify
#             socket fermé dans finally (fix leak)
#             timeout 300s dans run_git_project ET run_uploaded_project
#             sleep(30) + timeout(240) dans _llm_retry
# Fix v14 : Retry intelligent LLM (Ollama llama3.1:8b)
#           Après échec healthcheck → LLM analyse logs + fichiers
#           → génère start.sh corrigé → rebuild → relaunch
#           Universel : fonctionne pour toutes les stacks
#           Intégré dans run_git_project ET run_uploaded_project
# Fix v13 : DVPWA/aiohttp — patch config/dev.yaml au démarrage
#           PostgreSQL : création user 'postgres' + db 'sqli'
#           sed patch tous les YAMLs host: postgres → 127.0.0.1
# Fix v13.2 : migrations SQL automatiques (find migrations/*.sql)
# Fix v12 : support DVPWA/aiohttp + installation Python robuste
# Fix v11 : ZAP 500 non accessible, abort si container crashé
# Fix v10 : Dockerfile natif du repo si présent
# Fix v9  : ascan 400 — forceAddToSiteMap + spider complet
# Fix v8  : IP container via docker inspect (anti-ZAP 400 DNS)
# ============================================================

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.core.database import AsyncSessionLocal
from app.models.sast_finding import SASTFinding, SASTSeverity
from app.services.mitre_service import MitreEnrichmentEngine
from app.services.scoring_service import RiskScoringEngine

logger = logging.getLogger(__name__)

ZAP_HOST             = "http://cybersentinel_zap:8090"
ZAP_API_KEY          = ""
COMPOSE_PROJECT_NAME = "cybersentinel"

ALLOWED_TARGETS = {
    "webgoat": "http://cybersentinel_webgoat:8080/WebGoat",
    "dvwa":    "http://cybersentinel_dvwa:80/login.php",
}
TARGET_SERVICES = {"webgoat": "webgoat", "dvwa": "dvwa"}

HOST_PCAP_STORAGE      = Path("data/dast_captures")
CONTAINER_PCAP_STORAGE = "/shared/dast_captures"

_IGNORE_DIRS = {
    "venv", ".venv", "env", "node_modules", ".git", "__pycache__",
    "dist", "build", "target", ".idea", ".vscode", "vendor",
    "coverage", "logs", "tmp", ".tox", "htmlcov", ".pytest_cache",
    "Lib", "lib", "bin", "Scripts", "Include", "site-packages",
}


# ─────────────────────────────────────────────────────────────
# Helpers globaux
# ─────────────────────────────────────────────────────────────

def _is_valid_target_url(url: str) -> bool:
    if not url:
        return False
    v = url.strip().lower()
    if not (v.startswith("http://") or v.startswith("https://")):
        return False
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname in ("localhost", "0.0.0.0", "::1", "ip6-localhost"):
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            if any([ip.is_private, ip.is_loopback, ip.is_link_local,
                    ip.is_reserved, ip.is_multicast, ip.is_unspecified]):
                logger.warning(f"URL bloquée (IP privée/réservée) : {hostname}")
                return False
        except ValueError:
            pass
    except Exception as e:
        logger.warning(f"Validation URL échouée : {e}")
        return False
    return True


def _is_custom_target_inside_sandbox(url: str) -> bool:
    v = url.strip().lower()
    return any(f in v for f in [
        "cybersentinel_", "webgoat", "dvwa", ".internal", "sandbox", "target",
    ])


def _safe_name(value: str) -> str:
    cleaned = "".join(c.lower() if c.isalnum() else "-" for c in value)
    cleaned = "-".join(filter(None, cleaned.split("-")))
    return cleaned[:40] or "app"


def _safe_extract_zip(zip_path: str, dest_dir: Path) -> None:
    dest_str = str(dest_dir.resolve())
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = dest_dir / member.filename
            if not str(member_path.resolve()).startswith(dest_str):
                raise ValueError(f"Archive ZIP dangereuse : {member.filename}")
        zf.extractall(dest_dir)


def _find_entrypoint(base: Path, depth: int = 0) -> Optional[Path]:
    if depth > 4:
        return None
    if (base / "pom.xml").exists():
        return base
    if (base / "package.json").exists():
        try:
            pkg = json.loads((base / "package.json").read_text(encoding="utf-8"))
            if "start" in pkg.get("scripts", {}):
                return base
        except Exception:
            pass
    if (base / "requirements.txt").exists():
        return base
    if (base / "composer.json").exists() or any(base.glob("*.php")):
        return base
    for child in sorted(base.iterdir()):
        if child.is_dir() and child.name not in _IGNORE_DIRS and not child.name.startswith("."):
            result = _find_entrypoint(child, depth + 1)
            if result:
                return result
    return None


# ─────────────────────────────────────────────────────────────
# Analyse intelligente du projet
# ─────────────────────────────────────────────────────────────

def _analyze_project(project_dir: Path) -> dict:
    analysis = {
        "stack": None, "port": 3000, "entry": None,
        "needs_mongo": False, "needs_redis": False,
        "needs_postgres": False, "needs_mysql": False,
        "env_example": {}, "project_dir": str(project_dir),
    }

    for env_file in [".env.example", ".env.sample", ".env.template"]:
        env_path = project_dir / env_file
        if env_path.exists():
            try:
                for line in env_path.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, val = line.partition("=")
                        analysis["env_example"][key.strip()] = val.strip()
            except Exception:
                pass
            break

    if (project_dir / "package.json").exists():
        analysis["stack"] = "node"; analysis["port"] = 3000
        try:
            pkg  = json.loads((project_dir / "package.json").read_text(encoding="utf-8"))
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            analysis["needs_mongo"]    = any(d in deps for d in ["mongoose", "mongodb", "monk", "connect-mongo"])
            analysis["needs_redis"]    = any(d in deps for d in ["redis", "ioredis", "connect-redis"])
            analysis["needs_postgres"] = any(d in deps for d in ["pg", "sequelize", "typeorm", "knex"])
            analysis["needs_mysql"]    = any(d in deps for d in ["mysql", "mysql2", "mariadb"])
            for js_file in ["app.js", "server.js", "index.js", "src/app.js", "src/server.js"]:
                js_path = project_dir / js_file
                if js_path.exists():
                    content = js_path.read_text(errors="ignore")
                    m = re.search(r"listen\s*\(\s*(\d{4,5})", content)
                    if m:
                        analysis["port"] = int(m.group(1))
                    break
        except Exception as e:
            logger.warning(f"Analyse package.json failed: {e}")

    elif (project_dir / "requirements.txt").exists():
        reqs = (project_dir / "requirements.txt").read_text(errors="ignore").lower()
        py_content_parts = []
        for py_file in project_dir.glob("*.py"):
            try:
                py_content_parts.append(py_file.read_text(errors="ignore").lower())
            except Exception:
                pass
        combined = reqs + "\n" + "\n".join(py_content_parts)

        analysis["needs_mongo"]    = any(x in combined for x in ["pymongo", "mongoengine", "motor"])
        analysis["needs_redis"]    = any(x in combined for x in ["redis", "aioredis", "celery"])
        analysis["needs_postgres"] = any(x in combined for x in ["psycopg2", "asyncpg", "sqlalchemy", "postgres"])
        analysis["needs_mysql"]    = any(x in combined for x in ["pymysql", "mysqlclient", "aiomysql"])

        if "fastapi" in combined or "uvicorn" in combined:
            analysis["stack"] = "fastapi"; analysis["port"] = 8000
        elif "aiohttp" in combined:
            analysis["stack"] = "aiohttp"; analysis["port"] = 8080
        else:
            analysis["stack"] = "flask"; analysis["port"] = 5000

        for entry in ["app.py", "main.py", "run.py", "server.py", "wsgi.py", "manage.py"]:
            if (project_dir / entry).exists():
                analysis["entry"] = entry; break
        if not analysis["entry"]:
            for f in project_dir.glob("*.py"):
                try:
                    content = f.read_text(errors="ignore")
                    if (
                        "app.run" in content or "Flask(" in content
                        or "FastAPI(" in content or "run_app" in content
                        or "aiohttp" in content
                    ):
                        analysis["entry"] = f.name; break
                except Exception:
                    pass

    elif (project_dir / "composer.json").exists() or any(project_dir.glob("*.php")):
        analysis["stack"] = "php"; analysis["port"] = 80
        if (project_dir / "composer.json").exists():
            try:
                composer = json.loads((project_dir / "composer.json").read_text())
                deps = {**composer.get("require", {}), **composer.get("require-dev", {})}
                analysis["needs_mysql"]    = any("mysql" in d.lower() for d in deps)
                analysis["needs_mongo"]    = any("mongo" in d.lower() for d in deps)
                analysis["needs_postgres"] = any("pgsql" in d.lower() or "postgres" in d.lower() for d in deps)
            except Exception:
                pass

    elif (project_dir / "pom.xml").exists():
        analysis["stack"] = "springboot"; analysis["port"] = 8080
        try:
            pom = (project_dir / "pom.xml").read_text(errors="ignore").lower()
            analysis["needs_mongo"]    = "mongodb" in pom
            analysis["needs_redis"]    = "redis" in pom
            analysis["needs_postgres"] = "postgresql" in pom
            analysis["needs_mysql"]    = "mysql" in pom
        except Exception:
            pass

    logger.info(
        f"Analyse projet : stack={analysis['stack']} port={analysis['port']} "
        f"mongo={analysis['needs_mongo']} redis={analysis['needs_redis']} "
        f"postgres={analysis['needs_postgres']} mysql={analysis['needs_mysql']}"
    )
    return analysis


def _write_start_script(project_dir: Path, analysis: dict, app_cmd: str) -> str:
    lines = ["#!/bin/bash", "set -e", ""]
    if analysis["needs_mongo"]:
        lines += [
            "mkdir -p /data/db /var/log/mongodb",
            "mongod --fork --logpath /var/log/mongodb/mongod.log --dbpath /data/db --bind_ip 127.0.0.1 --quiet",
            "echo 'Attente MongoDB...'", "sleep 4",
        ]
    if analysis["needs_redis"]:
        lines += ["redis-server --daemonize yes --loglevel warning", "sleep 1"]
    if analysis["needs_postgres"]:
        lines += [
            "service postgresql start",
            "echo 'Attente PostgreSQL...'",
            "for i in $(seq 1 15); do pg_isready -q && break || sleep 2; done",
            "su postgres -c \"psql -c \\\"CREATE USER mock WITH PASSWORD 'mock';\\\" 2>/dev/null\" || true",
            "su postgres -c \"createdb -O mock mockdb 2>/dev/null\" || true",
            "su postgres -c \"psql -c \\\"ALTER USER postgres WITH PASSWORD 'postgres';\\\" 2>/dev/null\" || true",
            "su postgres -c \"createdb sqli 2>/dev/null\" || true",
            # Migrations SQL automatiques
            "for sql_file in $(find /app/migrations /app/db /app/sql /app/database -name '*.sql' 2>/dev/null | sort); do",
            "  echo \"[CyberSentinel] Migration: $sql_file\"",
            "  su postgres -c \"psql -d sqli -f $sql_file 2>/dev/null\" || true",
            "  su postgres -c \"psql -d mockdb -f $sql_file 2>/dev/null\" || true",
            "done",
            # Patch YAML configs
            "echo '[CyberSentinel] Patch YAML configs...'",
            "find /app -maxdepth 5 \\( -name '*.yaml' -o -name '*.yml' \\) 2>/dev/null | while read f; do",
            "  if grep -q 'host: postgres' \"$f\" 2>/dev/null; then",
            "    echo \"[CyberSentinel] Patching: $f\"",
            "    sed -i 's/host: postgres/host: 127.0.0.1/g' \"$f\"",
            "    sed -i 's/host: redis/host: 127.0.0.1/g' \"$f\"",
            "  fi",
            "done",
        ]
    if analysis["needs_mysql"]:
        lines += [
            "service mariadb start || service mysql start", "sleep 3",
            "mysql -u root -e \"CREATE DATABASE IF NOT EXISTS mockdb;\" 2>/dev/null || true",
            "mysql -u root -e \"CREATE USER IF NOT EXISTS 'mock'@'localhost' IDENTIFIED BY 'mock';\" 2>/dev/null || true",
            "mysql -u root -e \"GRANT ALL ON mockdb.* TO 'mock'@'localhost'; FLUSH PRIVILEGES;\" 2>/dev/null || true",
        ]
    lines += ["", "echo 'Démarrage application...'", f"exec {app_cmd}"]
    script_path = project_dir / "start.cybersentinel.sh"
    script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script_path.chmod(0o755)
    logger.info(f"Script démarrage généré : {script_path}")
    return "start.cybersentinel.sh"


def _generate_dockerfile(analysis: dict) -> str:
    stack = analysis["stack"]
    needs_mongo = analysis["needs_mongo"]
    needs_redis = analysis["needs_redis"]
    needs_postgres = analysis["needs_postgres"]
    needs_mysql = analysis["needs_mysql"]
    entry = analysis.get("entry")
    port = analysis["port"]
    project_dir = Path(analysis["project_dir"])
    services_needed = needs_mongo or needs_redis or needs_postgres or needs_mysql
    python_version = "python:3.8-slim" if stack == "aiohttp" else "python:3.11-slim"

    build_deps = """RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc g++ make python3-dev libffi-dev libssl-dev libpq-dev \\
    && rm -rf /var/lib/apt/lists/*

"""
    replace_psycopg2 = """RUN sed -i -E 's/^psycopg2([=><!~].*)?$/psycopg2-binary/g' requirements.txt && \\
    sed -i -E 's/^psycopg2-binary-binary/psycopg2-binary/g' requirements.txt && \\
    echo "requirements.txt après correction:" && cat requirements.txt

"""

    if stack == "node":
        if services_needed:
            _write_start_script(project_dir, analysis, "npm start")
            mongo_repo = ""
            if needs_mongo:
                mongo_repo = """RUN curl -fsSL https://www.mongodb.org/static/pgp/server-6.0.asc | \\
    gpg --dearmor -o /usr/share/keyrings/mongodb.gpg && \\
    echo "deb [ arch=amd64 signed-by=/usr/share/keyrings/mongodb.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \\
    > /etc/apt/sources.list.d/mongodb.list && \\
    apt-get update && apt-get install -y mongodb-org"""
            extra_pkgs = []
            if needs_redis: extra_pkgs.append("redis-server")
            if needs_postgres: extra_pkgs += ["postgresql", "postgresql-client"]
            if needs_mysql: extra_pkgs.append("mariadb-server")
            extra_install = f"RUN apt-get install -y {' '.join(extra_pkgs)}" if extra_pkgs else ""

            return f"""FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl gnupg2 ca-certificates && apt-get clean
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && apt-get install -y nodejs
{mongo_repo}
{extra_install}
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm install --legacy-peer-deps || npm install --force
COPY . .
RUN chmod +x /app/start.cybersentinel.sh
EXPOSE {port}
CMD ["/bin/bash", "/app/start.cybersentinel.sh"]
"""
        return f"""FROM node:16-bullseye
WORKDIR /app
COPY package*.json ./
RUN npm install --legacy-peer-deps || npm install --force
COPY . .
EXPOSE {port}
CMD ["npm", "start"]
"""

    elif stack in ("flask", "fastapi", "aiohttp"):
        extra_pip = ""
        if needs_mongo: extra_pip += "\nRUN pip install --no-cache-dir mongomock"
        if needs_redis: extra_pip += "\nRUN pip install --no-cache-dir fakeredis"

        if stack == "fastapi":
            module = f"{entry.replace('.py', '')}:app" if entry else "main:app"
            app_cmd = f"uvicorn {module} --host 0.0.0.0 --port {port}"
            cmd_line = f'CMD ["uvicorn", "{module}", "--host", "0.0.0.0", "--port", "{port}"]'
        else:
            if not entry:
                entry = "run.py" if stack == "aiohttp" else "app.py"
            app_cmd = f"python {entry}"
            cmd_line = f'CMD ["python", "{entry}"]'

        runtime_pip = "RUN pip install --no-cache-dir aiohttp asyncpg redis"

        if services_needed:
            _write_start_script(project_dir, analysis, app_cmd)
            extra_system_pkgs = ""
            if needs_postgres:
                extra_system_pkgs += "\nRUN apt-get update && apt-get install -y postgresql postgresql-client && apt-get clean && rm -rf /var/lib/apt/lists/*\n"
            if needs_redis:
                extra_system_pkgs += "\nRUN apt-get update && apt-get install -y redis-server && apt-get clean && rm -rf /var/lib/apt/lists/*\n"
            if needs_mysql:
                extra_system_pkgs += "\nRUN apt-get update && apt-get install -y mariadb-server mariadb-client && apt-get clean && rm -rf /var/lib/apt/lists/*\n"

            return f"""FROM {python_version}
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
{build_deps}
{extra_system_pkgs}
WORKDIR /app
COPY requirements.txt .
{replace_psycopg2}
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt
{runtime_pip}
{extra_pip}
COPY . .
RUN chmod +x /app/start.cybersentinel.sh
EXPOSE {port}
CMD ["/bin/bash", "/app/start.cybersentinel.sh"]
"""
        return f"""FROM {python_version}
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
{build_deps}
WORKDIR /app
COPY requirements.txt .
{replace_psycopg2}
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt
{runtime_pip}
{extra_pip}
COPY . .
EXPOSE {port}
{cmd_line}
"""

    elif stack == "php":
        has_composer = (project_dir / "composer.json").exists()
        composer_setup = "RUN curl -sS https://getcomposer.org/installer | php && mv composer.phar /usr/local/bin/composer" if has_composer else ""
        composer_install = "RUN composer install --no-dev --optimize-autoloader || true" if has_composer else ""
        return f"""FROM php:8.2-apache
RUN apt-get update && apt-get install -y unzip curl sqlite3 libsqlite3-dev && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN docker-php-ext-install pdo pdo_sqlite || true
{composer_setup}
WORKDIR /var/www/html
COPY . /var/www/html
{composer_install}
RUN chmod -R 755 /var/www/html
EXPOSE 80
"""

    elif stack == "springboot":
        return """FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
"""

    raise ValueError(f"Stack non supportée : {stack}")


def _generate_env(analysis: dict) -> list:
    env = []
    needs_mongo = analysis["needs_mongo"]; needs_redis = analysis["needs_redis"]
    needs_postgres = analysis["needs_postgres"]; needs_mysql = analysis["needs_mysql"]
    port = analysis["port"]; env_example = analysis.get("env_example", {})

    env += [
        f"PORT={port}", "HOST=0.0.0.0", "NODE_ENV=development",
        "FLASK_ENV=development", "ENVIRONMENT=development", "DEBUG=false", "TESTING=true",
        "SECRET_KEY=cybersentinel-mock-secret-key-32chars",
        "JWT_SECRET=cybersentinel-mock-jwt-secret",
        "JWT_SECRET_KEY=cybersentinel-mock-jwt-secret",
        "SESSION_SECRET=cybersentinel-mock-session-secret",
        "APP_SECRET=cybersentinel-mock-app-secret",
        "APP_KEY=base64:Y3liZXJzZW50aW5lbC1tb2NrLWtleS0zMmNoYXJz",
        "API_KEY=cybersentinel-mock-api-key",
    ]
    if needs_mongo:
        env += [
            "MONGODB_URI=mongodb://127.0.0.1:27017/mockdb",
            "MONGO_URL=mongodb://127.0.0.1:27017/mockdb",
            "MONGO_URI=mongodb://127.0.0.1:27017/mockdb",
            "MONGOLAB_URI=mongodb://127.0.0.1:27017/mockdb",
            "MONGODB_URL=mongodb://127.0.0.1:27017/mockdb",
        ]
    if needs_redis:
        env += [
            "REDIS_URL=redis://127.0.0.1:6379/0", "REDIS_HOST=127.0.0.1", "REDIS_PORT=6379",
            "CELERY_BROKER_URL=redis://127.0.0.1:6379/0",
            "CELERY_RESULT_BACKEND=redis://127.0.0.1:6379/0",
        ]
    else:
        env += ["CELERY_BROKER_URL=memory://", "CELERY_RESULT_BACKEND=cache+memory://"]
    if needs_postgres:
        env += [
            "DATABASE_URL=postgresql://mock:mock@127.0.0.1:5432/mockdb",
            "SQLALCHEMY_DATABASE_URI=postgresql://mock:mock@127.0.0.1:5432/mockdb",
            "POSTGRES_URL=postgresql://mock:mock@127.0.0.1:5432/mockdb",
            "DB_HOST=127.0.0.1", "DB_PORT=5432", "DB_NAME=mockdb", "DB_USER=mock", "DB_PASSWORD=mock",
            "APP_DB_HOST=127.0.0.1", "APP_DB_PORT=5432",
            "APP_DB_DATABASE=mockdb", "APP_DB_USER=mock", "APP_DB_PASSWORD=mock",
        ]
    else:
        env += [
            "DATABASE_URL=sqlite:///./mock.db",
            "SQLALCHEMY_DATABASE_URI=sqlite:///./mock.db",
            "DB_URL=sqlite:///./mock.db",
        ]
    if needs_mysql:
        env += [
            "DATABASE_URL=mysql://mock:mock@127.0.0.1:3306/mockdb",
            "MYSQL_HOST=127.0.0.1", "MYSQL_PORT=3306", "MYSQL_DATABASE=mockdb",
            "MYSQL_USER=mock", "MYSQL_PASSWORD=mock",
            "DB_HOST=127.0.0.1", "DB_PORT=3306", "DB_NAME=mockdb",
            "DB_USERNAME=mock", "DB_PASSWORD=mock",
        ]
    env += [
        "SPRING_DATASOURCE_URL=jdbc:h2:mem:mockdb;DB_CLOSE_DELAY=-1",
        "SPRING_DATASOURCE_DRIVER_CLASS_NAME=org.h2.Driver",
        "SPRING_DATASOURCE_USERNAME=sa", "SPRING_DATASOURCE_PASSWORD=",
        "SPRING_JPA_DATABASE_PLATFORM=org.hibernate.dialect.H2Dialect",
        "SPRING_JPA_HIBERNATE_DDL_AUTO=create-drop", "SPRING_PROFILES_ACTIVE=dev",
    ]
    already_set = {e.split("=")[0] for e in env}
    for key, val in env_example.items():
        if key not in already_set and val and not any(
            skip in key.upper() for skip in ["PASSWORD", "SECRET", "TOKEN", "KEY", "SALT", "PRIVATE"]
        ):
            env.append(f"{key}={val}")
    return env


def _detect_stack(project_dir: Path) -> dict:
    project_dir = Path(project_dir)
    real_dir = _find_entrypoint(project_dir)
    if real_dir and real_dir != project_dir:
        logger.info(f"Point d'entrée : {real_dir}")
        project_dir = real_dir
    elif not real_dir:
        raise ValueError(
            "Stack non reconnue. Support : Spring Boot, Node.js, Python (Flask/FastAPI), PHP.\n"
            "Vérifiez que votre projet contient pom.xml, package.json, requirements.txt ou *.php."
        )
    analysis = _analyze_project(project_dir)
    if not analysis["stack"]:
        raise ValueError("Stack non reconnue après analyse du projet.")
    return {
        "type": analysis["stack"], "port": analysis["port"],
        "project_dir": str(project_dir),
        "dockerfile": _generate_dockerfile(analysis),
        "env": _generate_env(analysis),
    }


def _resolve_compose_file() -> Path:
    env_file = os.getenv("CYBERSENTINEL_COMPOSE_FILE")
    candidates = []
    if env_file:
        candidates.append(Path(env_file))
    candidates += [
        Path("/workspace/docker-compose.yml"), Path("/app/docker-compose.yml"),
        Path("./docker-compose.yml"), Path("./compose.yml"),
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    raise FileNotFoundError("Aucun docker-compose.yml trouvé.")


# ─────────────────────────────────────────────────────────────
# FIX v14 : LLM retry universel — toutes stacks
# ─────────────────────────────────────────────────────────────

async def _llm_retry(
    orchestrator,
    project_dir: Path,
    container_name: str,
    image_name: str,
    target_url: str,
    stack_type: str,
    project_name: str,
) -> Tuple[bool, str, str]:
    """
    Retry intelligent LLM après échec healthcheck.
    Retourne (success, new_target_url, final_logs).
    Universel : fonctionne pour toutes les stacks auto (pas Dockerfile natif).
    """
    try:
        from app.services.dast_llm_helper import generate_start_script

        logger.warning(f"[LLM RETRY] App '{project_name}' non accessible — tentative réparation LLM")

        # Récupérer les logs du container
        _, logs_out, logs_err = await orchestrator._run_command(
            "docker", "logs", "--tail", "120", container_name, timeout=10,
        )
        final_logs = (logs_out + "\n" + logs_err).strip()

        # Analyser le projet pour le contexte LLM
        try:
            stack_info = _detect_stack(project_dir)
            real_project_dir = Path(stack_info.get("project_dir", str(project_dir)))
        except Exception:
            real_project_dir = project_dir

        analysis = _analyze_project(real_project_dir)

        # Lire le script actuel
        current_script = ""
        script_path = real_project_dir / "start.cybersentinel.sh"
        if script_path.exists():
            current_script = script_path.read_text(errors="ignore")

        # Appel LLM
        new_script = await generate_start_script(
            project_dir=real_project_dir,
            current_script=current_script,
            container_logs=final_logs,
            analysis=analysis,
        )

        if not new_script:
            logger.warning("[LLM RETRY] LLM n'a pas généré de script valide")
            return False, target_url, final_logs

        # Écrire le nouveau script
        script_path.write_text(new_script, encoding="utf-8")
        script_path.chmod(0o755)
        logger.info(f"[LLM RETRY] Nouveau script écrit ({len(new_script)} chars)")

        # Cleanup ancien container + image
        await orchestrator._cleanup_uploaded_target(container_name, image_name)

        # Rebuild avec le nouveau script
        code, new_target_url, error_msg, _ = await orchestrator._build_and_run(
            real_project_dir, image_name, container_name,
        )

        if code != 0:
            logger.error(f"[LLM RETRY] Rebuild échoué: {error_msg[:300]}")
            return False, target_url, error_msg

        # FIX v14.3 : délai plus long avant healthcheck (PostgreSQL + migrations)
        await asyncio.sleep(30)
        running, crash_logs = await orchestrator._check_container_running(container_name)
        if not running:
            logger.error(f"[LLM RETRY] Container crashé après LLM: {crash_logs[:300]}")
            return False, new_target_url, crash_logs

        # FIX v14.3 : timeout augmenté à 240s pour stacks lourdes
        ready = await orchestrator._wait_for_uploaded_app(new_target_url, timeout=240)
        if ready:
            logger.info(f"✅ [LLM RETRY] Succès ! App accessible sur {new_target_url}")
            return True, new_target_url, ""
        else:
            _, retry_out, retry_err = await orchestrator._run_command(
                "docker", "logs", "--tail", "50", container_name, timeout=10,
            )
            return False, new_target_url, (retry_out + "\n" + retry_err).strip()

    except Exception as e:
        logger.exception(f"[LLM RETRY] Erreur inattendue: {e}")
        return False, target_url, str(e)


# ─────────────────────────────────────────────────────────────
# DASTOrchestrator
# ─────────────────────────────────────────────────────────────

class DASTOrchestrator:

    def __init__(self):
        self.mitre_engine   = MitreEnrichmentEngine()
        self.scoring_engine = RiskScoringEngine()
        self._session_active          = False
        self._current_session_id: Optional[str] = None
        self._compose_file: Optional[Path] = None

    def _get_compose_file(self) -> Path:
        if self._compose_file is None:
            self._compose_file = _resolve_compose_file()
        return self._compose_file

    async def _run_command(
        self,
        *cmd: str,
        timeout: int = 60,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> Tuple[int, str, str]:
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd, env=full_env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

    async def _run_compose(self, *args: str, timeout: int = 60) -> Tuple[int, str, str]:
        cf  = self._get_compose_file()
        cmd = ["docker", "compose", "-p", COMPOSE_PROJECT_NAME, "-f", str(cf), *args]
        return await self._run_command(*cmd, timeout=timeout, cwd=str(cf.parent))

    async def _resolve_container_ip(self, container_name: str) -> str:
        code, out, err = await self._run_command(
            "docker", "inspect",
            "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_name, timeout=10,
        )
        if code != 0:
            raise RuntimeError(f"Impossible de résoudre IP container {container_name}: {err or out}")
        ip = out.strip()
        if not ip:
            raise RuntimeError(f"IP vide pour le container {container_name}")
        logger.info(f"IP container {container_name} → {ip}")
        return ip

    async def _target_url_from_container(self, container_name: str, port: int) -> str:
        ip = await self._resolve_container_ip(container_name)
        return f"http://{ip}:{port}"

    def _detect_port_from_dockerfile(self, dockerfile_path: Path) -> int:
        try:
            content = dockerfile_path.read_text(errors="ignore")

            # 1. EXPOSE explicite — source de vérité, flag IGNORECASE pour robustesse
            match = re.search(r"EXPOSE\s+(\d+)", content, re.MULTILINE | re.IGNORECASE)
            if match:
                logger.info(f"Port détecté via EXPOSE : {match.group(1)}")
                return int(match.group(1))

            # 2. Détection par stack si pas d'EXPOSE
            lower = content.lower()

            if any(kw in lower for kw in ["spring", "java", "maven", "gradle", ".jar"]):
                logger.info("Port détecté par stack : Java/Spring → 8080")
                return 8080

            if any(kw in lower for kw in ["node", "npm", "yarn"]):
                logger.info("Port détecté par stack : Node.js → 3000")
                return 3000

            if any(kw in lower for kw in ["uvicorn", "fastapi"]):
                logger.info("Port détecté par stack : FastAPI → 8000")
                return 8000

            if any(kw in lower for kw in ["aiohttp", "flask", "gunicorn", "python"]):
                logger.info("Port détecté par stack : Python → 5000")
                return 5000

            if any(kw in lower for kw in ["php", "apache", "nginx"]):
                logger.info("Port détecté par stack : PHP/Web → 80")
                return 80

        except Exception as e:
            logger.warning(f"_detect_port_from_dockerfile erreur: {e}")

        # Fallback 8080 (plus courant que 3000 pour les repos avec Dockerfile natif)
        logger.info("Port non détecté → fallback 8080")
        return 8080

    async def _verify_isolation(self) -> bool:
        try:
            code, stdout, _ = await self._run_command(
                "docker", "network", "inspect", "cybersentinel_sandbox-net",
                "--format", "{{.Internal}}", timeout=20,
            )
            if code != 0:
                return False
            is_internal = stdout.strip().lower() == "true"
            logger.info("✅ Isolation OK" if is_internal else "❌ sandbox-net NON isolé")
            return is_internal
        except Exception as e:
            logger.error(f"Vérification isolation échouée: {e}")
            return False

    async def _wait_for_zap(self, timeout: int = 240) -> bool:
        deadline = time.time() + timeout
        async with httpx.AsyncClient() as client:
            while time.time() < deadline:
                try:
                    resp = await client.get(f"{ZAP_HOST}/JSON/core/view/version/", timeout=5)
                    if resp.status_code == 200:
                        logger.info("✅ ZAP prêt")
                        return True
                except Exception as e:
                    logger.info(f"Attente ZAP... {e}")
                await asyncio.sleep(5)
        logger.error("ZAP non disponible")
        return False

    async def _ensure_zap_only(self) -> dict:
        logger.info("Vérification/Démarrage ZAP seul")
        try:
            # 1) Si ZAP existe déjà et répond, ne pas lancer docker compose up
            code, out, _ = await self._run_command(
                "docker", "inspect",
                "--format", "{{.State.Running}}",
                "cybersentinel_zap",
                timeout=10,
            )

            if code == 0 and out.strip().lower() == "true":
                logger.info("ZAP existe déjà — vérification API")
                isolation_ok = await self._verify_isolation()
                zap_ready    = await self._wait_for_zap(timeout=60)

                if isolation_ok and zap_ready:
                    logger.info("✅ ZAP déjà prêt, pas de recréation")
                    return {
                        "success": True,
                        "isolation_ok": isolation_ok,
                        "zap_ready": zap_ready,
                        "details": "ZAP déjà existant et opérationnel",
                    }

                logger.warning("ZAP existe mais ne répond pas — recréation")
                await self._run_command(
                    "docker", "rm", "-f", "cybersentinel_zap", timeout=60,
                )

            # 2) Sinon démarrage normal via docker compose
            logger.info("Démarrage ZAP via docker compose")
            code, stdout, stderr = await self._run_compose(
                "--profile", "dast", "up", "-d", "--no-recreate", "zap", timeout=180,
            )

            if code != 0:
                return {"success": False, "error": (stderr or stdout)[:1200]}

            await asyncio.sleep(5)
            isolation_ok = await self._verify_isolation()
            zap_ready    = await self._wait_for_zap(timeout=240)

            return {
                "success": bool(isolation_ok and zap_ready),
                "isolation_ok": isolation_ok,
                "zap_ready": zap_ready,
            }

        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout ZAP (>180s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _wait_for_uploaded_app(self, target_url: str, timeout: int = 120) -> bool:
        """
        FIX v15 : healthcheck depuis ZAP TCP.
        Le backend n'est pas sur sandbox-net, mais ZAP l'est.
        On exécute le test TCP depuis le container ZAP via docker exec.
        TCP OK = la cible est joignable depuis ZAP, même si HTTP retourne empty reply.
        """
        from urllib.parse import urlparse as _urlparse

        parsed = _urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or 80

        deadline = time.time() + timeout
        consecutive_ok = 0

        logger.info(f"Attente démarrage app via ZAP TCP : {host}:{port}")

        while time.time() < deadline:
            try:
                code, out, err = await self._run_command(
                    "docker", "exec", "-u", "root", "cybersentinel_zap",
                    "python3", "-c",
                    (
                        "import socket,sys;"
                        "s=socket.socket();"
                        "s.settimeout(5);"
                        f"r=s.connect_ex(('{host}', {port}));"
                        "s.close();"
                        "print(r);"
                        "sys.exit(0 if r == 0 else 1)"
                    ),
                    timeout=10,
                )

                if code == 0:
                    consecutive_ok += 1
                    logger.info(f"✅ Port {port} ouvert depuis ZAP TCP ({consecutive_ok}/2)")

                    if consecutive_ok >= 2:
                        logger.info(f"✅ App prête pour ZAP : {target_url}")
                        try:
                            async with httpx.AsyncClient() as client:
                                await client.get(
                                    f"{ZAP_HOST}/JSON/core/action/accessUrl/",
                                    params={
                                        "url": target_url,
                                        "followRedirects": "true",
                                    },
                                    timeout=10,
                                )
                        except Exception as e:
                            logger.warning(f"ZAP accessUrl non bloquant : {e}")
                        return True
                else:
                    consecutive_ok = 0
                    logger.info(f"Port {port} pas encore ouvert depuis ZAP TCP")

            except Exception as e:
                consecutive_ok = 0
                logger.info(f"Attente app via ZAP TCP... {e}")

            await asyncio.sleep(5)

        logger.error(f"❌ App non accessible depuis ZAP après {timeout}s")
        return False

    async def _check_container_running(self, container_name: str) -> Tuple[bool, str]:
        try:
            code, out, _ = await self._run_command(
                "docker", "inspect", "--format", "{{.State.Running}}", container_name, timeout=10,
            )
            is_running = out.strip().lower() == "true"
            if not is_running:
                _, logs_out, logs_err = await self._run_command(
                    "docker", "logs", "--tail", "80", container_name, timeout=10,
                )
                combined_logs = (logs_out + "\n" + logs_err).strip()
                return False, combined_logs[:2000]
            return True, ""
        except Exception as e:
            return False, str(e)

    async def _cleanup_uploaded_target(
        self, container_name: Optional[str], image_name: Optional[str]
    ) -> None:
        if container_name:
            try:
                await self._run_command("docker", "rm", "-f", container_name, timeout=60)
                logger.info(f"Container supprimé : {container_name}")
            except Exception as e:
                logger.warning(f"Erreur rm {container_name}: {e}")
        if image_name:
            try:
                await self._run_command("docker", "rmi", "-f", image_name, timeout=60)
                logger.info(f"Image supprimée : {image_name}")
            except Exception as e:
                logger.warning(f"Erreur rmi {image_name}: {e}")

    async def _build_and_run(
        self,
        project_dir: Path,
        image_name: str,
        container_name: str,
    ) -> Tuple[int, str, str, str]:
        try:
            stack = _detect_stack(project_dir)
        except ValueError as e:
            return 1, "", str(e), ""

        real_project_dir = Path(stack.get("project_dir", str(project_dir)))
        dockerfile_path = real_project_dir / "Dockerfile.cybersentinel"
        dockerfile_path.write_text(stack["dockerfile"], encoding="utf-8")

        logger.info(f"Build auto {stack['type']} → {image_name}")
        logger.info(f"Dockerfile généré : {dockerfile_path}")

        build_code, build_out, build_err = await self._run_command(
            "docker", "build", "--no-cache",
            "-f", str(dockerfile_path), "-t", image_name, str(real_project_dir),
            timeout=900, env={"DOCKER_BUILDKIT": "0"},
        )

        if build_code != 0:
            dockerfile_content = ""
            try:
                dockerfile_content = dockerfile_path.read_text(errors="ignore")
            except Exception:
                dockerfile_content = "Impossible de lire Dockerfile.cybersentinel"
            logger.error(
                f"Build échoué:\nDOCKERFILE:\n{dockerfile_content[:5000]}"
                f"\nSTDOUT:\n{build_out[-12000:]}\nSTDERR:\n{build_err[-12000:]}"
            )
            return (
                build_code, "",
                f"Build échoué ({stack['type']}):\n\nDOCKERFILE:\n{dockerfile_content[:5000]}"
                f"\n\nSTDOUT:\n{build_out[-12000:]}\n\nSTDERR:\n{build_err[-12000:]}",
                stack["type"],
            )

        env_args = []
        for e in stack.get("env", []):
            env_args += ["--env", e]

        run_code, run_out, run_err = await self._run_command(
            "docker", "run", "-d",
            "--name", container_name,
            "--network", "cybersentinel_sandbox-net",
            "--restart", "no",
            *env_args, image_name,
            timeout=120,
        )

        if run_code != 0:
            return run_code, "", f"Lancement échoué : {(run_err or run_out)[:2000]}", stack["type"]

        try:
            target_url = await self._target_url_from_container(container_name, stack["port"])
        except Exception as e:
            target_url = f"http://{container_name}:{stack['port']}"
            logger.warning(f"Fallback DNS: {e}")

        logger.info(f"Container lancé → {target_url}")
        return 0, target_url, "", stack["type"]

    # ─────────────────────────────────────────────────────────
    # Mode 1 — cible prédéfinie ou URL custom
    # ─────────────────────────────────────────────────────────

    async def run_session(
        self,
        target: str = "webgoat",
        target_url: Optional[str] = None,
        deploy_target: bool = True,
        internal_target: bool = False,
    ) -> dict:
        if self._session_active:
            return {"error": "Session DAST déjà active", "session_id": self._current_session_id}

        if target_url:
            if not internal_target:
                if not _is_valid_target_url(target_url):
                    return {"error": "URL invalide ou IP privée bloquée (anti-SSRF)", "constraint": "C-05"}
                if not _is_custom_target_inside_sandbox(target_url):
                    return {"error": "Cible hors sandbox refusée", "constraint": "C-05"}
            resolved_name = "custom"
            resolved_url  = target_url.strip()
        else:
            if target not in ALLOWED_TARGETS:
                return {"error": f"Cible non autorisée: {list(ALLOWED_TARGETS.keys())}", "constraint": "C-05"}
            resolved_name = target
            resolved_url  = ALLOWED_TARGETS[target]

        session_id = f"dast_{int(time.time())}"
        self._session_active     = True
        self._current_session_id = session_id

        results = {
            "session_id": session_id, "target": resolved_name, "target_url": resolved_url,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "phases": {}, "findings": [], "pcap_path": None, "total_vulns": 0,
        }

        try:
            results["phases"]["1_deploy"] = await self._phase_deploy(
                target=target, deploy_target=deploy_target and not bool(target_url),
            )
            if not results["phases"]["1_deploy"]["success"]:
                return results

            results["phases"]["2_spider"] = await self._phase_spider(resolved_url)
            capture_task = asyncio.create_task(self._start_pcap_capture(session_id))
            results["phases"]["3_inject"] = await self._phase_inject(resolved_url)

            pcap_path = await capture_task
            results["phases"]["4_capture"] = {
                "success": bool(pcap_path), "pcap_path": str(pcap_path) if pcap_path else None,
            }
            results["pcap_path"] = str(pcap_path) if pcap_path else None

            findings = await self._phase_collect_proofs(resolved_url, session_id)
            results["phases"]["5_proofs"] = {"success": True, "vuln_count": len(findings)}
            results["findings"]    = findings
            results["total_vulns"] = len(findings)
            await self._process_findings(findings, session_id)

        except Exception as e:
            logger.exception("DAST session erreur")
            results["error"] = str(e)
        finally:
            results["phases"]["6_teardown"] = await self._phase_teardown()
            results["finished_at"]           = datetime.now(timezone.utc).isoformat()
            self._session_active             = False
            self._current_session_id         = None

        logger.info(f"DAST terminé | {results['total_vulns']} vulns | PCAP: {results['pcap_path']}")
        return results

    # ─────────────────────────────────────────────────────────
    # Mode 2 — upload ZIP
    # ─────────────────────────────────────────────────────────

    async def run_uploaded_project(self, zip_path: str, original_name: str) -> dict:
        container_name: Optional[str] = None
        image_name: Optional[str]     = None
        extract_dir: Optional[Path]   = None
        project_dir: Optional[Path]   = None
        try:
            if self._session_active:
                return {"error": "Session DAST déjà active", "session_id": self._current_session_id}
            isolation_ok = await self._verify_isolation()
            if not isolation_ok:
                return {"error": "sandbox-net non isolé", "constraint": "C-05"}
            deploy_info = await self._ensure_zap_only()
            if not deploy_info.get("success"):
                return {"error": "ZAP non disponible", "details": deploy_info}

            container_name, image_name, target_url, extract_dir, project_dir = \
                await self._deploy_uploaded_project(zip_path, original_name)

            await asyncio.sleep(5)
            running, crash_logs = await self._check_container_running(container_name)
            if not running:
                logger.error(f"Container crashé — logs:\n{crash_logs}")
                return {"error": f"Application '{original_name}' crashée au démarrage.", "container_logs": crash_logs}

            # FIX v14.3 : timeout augmenté à 300s pour ZIP avec stack lourde
            ready = await self._wait_for_uploaded_app(target_url, timeout=300)

            # FIX v14 : LLM retry universel
            if not ready and project_dir:
                llm_ok, target_url, final_logs = await _llm_retry(
                    self, project_dir, container_name, image_name,
                    target_url, "auto", original_name,
                )
                ready = llm_ok
                if not ready:
                    return {
                        "error": f"Application '{original_name}' non accessible après retry LLM.",
                        "container_logs": final_logs[:3000],
                        "llm_retry": True,
                    }

            if not ready:
                _, flo, fle = await self._run_command(
                    "docker", "logs", "--tail", "50", container_name, timeout=10,
                )
                return {
                    "error": f"Application '{original_name}' non accessible après 300s.",
                    "container_logs": (flo + "\n" + fle).strip()[:1000],
                }

            result = await self.run_session(
                target="custom", target_url=target_url, deploy_target=False, internal_target=True,
            )
            result["uploaded_project"] = {
                "filename": original_name, "container_name": container_name,
                "image_name": image_name, "target_url": target_url,
            }
            return result
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            logger.exception(f"run_uploaded_project erreur: {e}")
            return {"error": str(e)}
        finally:
            await self._cleanup_uploaded_target(container_name, image_name)
            if extract_dir:
                shutil.rmtree(extract_dir, ignore_errors=True)
            try:
                Path(zip_path).unlink(missing_ok=True)
            except Exception:
                pass

    async def _deploy_uploaded_project(
        self, zip_path: str, original_name: str
    ) -> Tuple[str, str, str, Path, Path]:
        work_root = Path("/app/data/uploads_dast")
        work_root.mkdir(parents=True, exist_ok=True)
        unique_id    = uuid.uuid4().hex[:8]
        project_slug = _safe_name(Path(original_name).stem)
        extract_dir  = work_root / f"{project_slug}_{unique_id}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        try:
            _safe_extract_zip(zip_path, extract_dir)
        except Exception as e:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise ValueError(f"ZIP invalide : {e}")

        children    = list(extract_dir.iterdir())
        project_dir = children[0] if (len(children) == 1 and children[0].is_dir()) else extract_dir
        image_name     = f"cybersentinel-upload-{project_slug}:{unique_id}"
        container_name = f"cybersentinel_target_{unique_id}"

        code, target_url, error_msg, _ = await self._build_and_run(project_dir, image_name, container_name)
        if code != 0:
            logger.error(f"Build échoué — dossier conservé pour debug : {extract_dir}")
            raise RuntimeError(error_msg)

        return container_name, image_name, target_url, extract_dir, project_dir

    # ─────────────────────────────────────────────────────────
    # Mode 3 — repo GitHub → clone → build natif ou auto → ZAP
    # ─────────────────────────────────────────────────────────

    async def run_git_project(
        self,
        repo_url: str,
        branch: str = "main",
        project_name: str = "git-project",
    ) -> dict:
        work_root = Path("/app/data/uploads_dast")
        work_root.mkdir(parents=True, exist_ok=True)

        unique_id    = uuid.uuid4().hex[:8]
        project_slug = _safe_name(project_name)
        clone_dir    = work_root / f"{project_slug}_{unique_id}"

        container_name: Optional[str] = None
        image_name: Optional[str]     = None

        try:
            if self._session_active:
                return {"error": "Session DAST déjà active", "session_id": self._current_session_id}

            isolation_ok = await self._verify_isolation()
            if not isolation_ok:
                return {"error": "sandbox-net non isolé", "constraint": "C-05"}

            deploy_info = await self._ensure_zap_only()
            if not deploy_info.get("success"):
                return {"error": "ZAP non disponible", "details": deploy_info}

            logger.info(f"Clone {repo_url}@{branch} → {clone_dir}")
            clone_dir.mkdir(parents=True, exist_ok=True)

            code, out, err = await self._run_command(
                "git", "clone", "--depth", "1", "--branch", branch,
                "--single-branch", repo_url, str(clone_dir), timeout=120,
            )
            if code != 0:
                shutil.rmtree(clone_dir, ignore_errors=True)
                clone_dir.mkdir(parents=True, exist_ok=True)
                code, out, err = await self._run_command(
                    "git", "clone", "--depth", "1", repo_url, str(clone_dir), timeout=120,
                )
                if code != 0:
                    return {"error": f"Clone échoué : {err[:600] or out[:600]}"}

            children    = [c for c in clone_dir.iterdir() if c.name != ".git"]
            project_dir = children[0] if (len(children) == 1 and children[0].is_dir()) else clone_dir

            image_name      = f"cybersentinel-git-{project_slug}:{unique_id}"
            container_name  = f"cybersentinel_target_{unique_id}"
            dockerfile_path = project_dir / "Dockerfile"

            if dockerfile_path.exists():
                logger.info("Dockerfile trouvé dans le repo → build direct")
                build_code, build_out, build_err = await self._run_command(
                    "docker", "build", "--no-cache", "-t", image_name, str(project_dir),
                    timeout=900, env={"DOCKER_BUILDKIT": "0"},
                )
                if build_code != 0:
                    return {
                        "error": f"Build échoué:\n\nSTDOUT:\n{build_out[-12000:]}"
                                 f"\n\nSTDERR:\n{build_err[-12000:]}"
                    }

                port = self._detect_port_from_dockerfile(dockerfile_path)
                run_code, run_out, run_err = await self._run_command(
                    "docker", "run", "-d",
                    "--name", container_name,
                    "--network", "cybersentinel_sandbox-net",
                    "--restart", "no",
                    image_name, timeout=120,
                )
                if run_code != 0:
                    return {"error": f"Lancement échoué : {(run_err or run_out)[:600]}"}

                try:
                    target_url = await self._target_url_from_container(container_name, port)
                except Exception as e:
                    target_url = f"http://{container_name}:{port}"
                    logger.warning(f"Fallback DNS: {e}")
                stack_type = "dockerfile"

            else:
                logger.info("Aucun Dockerfile trouvé → build automatique CyberSentinel")
                code, target_url, error_msg, stack_type = await self._build_and_run(
                    project_dir, image_name, container_name,
                )
                if code != 0:
                    return {"error": error_msg}

            logger.info(f"Container lancé → {target_url} (stack: {stack_type})")

            # Délai initial pour laisser le temps aux services de démarrer
            await asyncio.sleep(30)
            running, crash_logs = await self._check_container_running(container_name)
            if not running:
                logger.error(f"Container crashé — logs:\n{crash_logs}")
                return {
                    "error": f"Application '{project_name}' crashée au démarrage.",
                    "container_logs": crash_logs,
                }

            # FIX v14.3 : timeout augmenté à 300s pour stacks lourdes (postgres+migrations)
            ready = await self._wait_for_uploaded_app(target_url, timeout=300)

            # FIX v14 : LLM retry universel — uniquement pour stack auto (pas Dockerfile natif)
            if not ready and stack_type != "dockerfile":
                llm_ok, target_url, final_logs = await _llm_retry(
                    self, project_dir, container_name, image_name,
                    target_url, stack_type, project_name,
                )
                ready = llm_ok
                if not ready:
                    return {
                        "error": f"Application '{project_name}' non accessible après retry LLM.",
                        "container_logs": final_logs[:3000],
                        "llm_retry": True,
                    }
            elif not ready:
                _, flo, fle = await self._run_command(
                    "docker", "logs", "--tail", "50", container_name, timeout=10,
                )
                return {
                    "error": f"Application '{project_name}' non accessible après 300s.",
                    "container_logs": (flo + "\n" + fle).strip()[:1000],
                }

            result = await self.run_session(
                target="custom", target_url=target_url,
                deploy_target=False, internal_target=True,
            )
            result["git_project"] = {
                "repo_url":       repo_url,
                "branch":         branch,
                "project_name":   project_name,
                "stack":          stack_type,
                "dockerfile":     "native" if (project_dir / "Dockerfile").exists() else "auto",
                "container_name": container_name,
                "image_name":     image_name,
                "target_url":     target_url,
            }
            return result

        except ValueError as e:
            logger.warning(f"run_git_project ValueError: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.exception(f"run_git_project erreur: {e}")
            return {"error": str(e)}
        finally:
            if os.getenv("DAST_KEEP_FAILED_CONTAINERS", "false").lower() == "true":
                logger.warning(
                    f"[DEBUG DAST] Container conservé pour inspection : "
                    f"container={container_name} image={image_name} clone={clone_dir}"
                )
            else:
                await self._cleanup_uploaded_target(container_name, image_name)
                shutil.rmtree(clone_dir, ignore_errors=True)

    # ─────────────────────────────────────────────────────────
    # Mode 4 — image Docker pré-buildée → Trivy + ZAP
    # ─────────────────────────────────────────────────────────

    async def run_docker_image(
        self,
        image_name: str,
        internal_port: int = 3000,
        healthcheck_path: str = "/",
        scan_profile: str = "baseline",
    ) -> dict:
        container_name = f"cybersentinel_target_{uuid.uuid4().hex[:8]}"
        try:
            if self._session_active:
                return {"error": "Session DAST déjà active", "session_id": self._current_session_id}

            code, out, _ = await self._run_command("docker", "image", "inspect", image_name, timeout=10)
            if code != 0:
                return {"error": f"Image '{image_name}' introuvable. Lance : docker build -t {image_name} ."}

            logger.info(f"Scan Trivy image : {image_name}")
            trivy_code, trivy_out, _ = await self._run_command(
                "docker", "run", "--rm",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "aquasec/trivy:latest", "image", "--format", "json",
                "--severity", "HIGH,CRITICAL", image_name, timeout=120,
            )
            trivy_results = {}
            try:
                trivy_results = json.loads(trivy_out) if trivy_out else {}
            except Exception:
                pass

            deploy_info = await self._ensure_zap_only()
            if not deploy_info.get("success"):
                return {"error": "ZAP non disponible", "details": deploy_info}

            run_code, run_out, run_err = await self._run_command(
                "docker", "run", "-d",
                "--name", container_name,
                "--network", "cybersentinel_sandbox-net",
                "--restart", "no",
                "--memory", "512m", "--cpus", "1",
                "--pids-limit", "256", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                image_name, timeout=60,
            )
            if run_code != 0:
                return {"error": f"Lancement container échoué : {(run_err or run_out)[:500]}"}

            try:
                target_url = await self._target_url_from_container(container_name, internal_port)
            except Exception as e:
                target_url = f"http://{container_name}:{internal_port}"
                logger.warning(f"Fallback DNS: {e}")

            logger.info(f"Container lancé → {target_url}")

            await asyncio.sleep(5)
            running, crash_logs = await self._check_container_running(container_name)
            if not running:
                logger.error(f"Container crashé — logs:\n{crash_logs}")
                return {"error": f"Image '{image_name}' crashée au démarrage.", "container_logs": crash_logs}

            ready = await self._wait_for_uploaded_app(target_url, timeout=120)
            if not ready:
                return {"error": f"Application non accessible après 120s sur le port {internal_port}"}

            result = await self.run_session(
                target="custom", target_url=target_url, deploy_target=False, internal_target=True,
            )
            result["docker_image_scan"] = {
                "image_name": image_name, "container_name": container_name,
                "internal_port": internal_port,
                "trivy_summary": trivy_results.get("Results", []),
            }
            return result

        except Exception as e:
            logger.exception(f"run_docker_image erreur: {e}")
            return {"error": str(e)}
        finally:
            await self._cleanup_uploaded_target(container_name, None)

    # ─────────────────────────────────────────────────────────
    # Phases internes ZAP
    # ─────────────────────────────────────────────────────────

    async def _phase_deploy(self, target: str, deploy_target: bool = True) -> dict:
        logger.info("Phase 1 — Déploiement sandbox DAST")
        try:
            if not deploy_target:
                isolation_ok = await self._verify_isolation()
                zap_ready    = await self._wait_for_zap(timeout=240)
                return {"success": bool(isolation_ok and zap_ready),
                        "isolation_ok": isolation_ok, "zap_ready": zap_ready,
                        "details": "Mode custom — pas de déploiement cible"}

            target_service = TARGET_SERVICES[target]
            code, stdout, stderr = await self._run_compose(
                "--profile", "dast", "up", "-d", "--no-recreate",
                "zap", target_service, timeout=180,
            )
            if code != 0:
                return {"success": False, "error": (stderr or stdout)[:1200]}

            await asyncio.sleep(5)
            isolation_ok = await self._verify_isolation()
            zap_ready    = await self._wait_for_zap(timeout=240)
            return {"success": bool(isolation_ok and zap_ready),
                    "isolation_ok": isolation_ok, "zap_ready": zap_ready,
                    "details": stdout[:300] if stdout else None}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout (>180s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _phase_spider(self, target_url: str) -> dict:
        logger.info(f"Phase 2 — Spider {target_url}")
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                data    = (await client.get(
                    f"{ZAP_HOST}/JSON/spider/action/scan/",
                    params={"url": target_url, "maxChildren": 10},
                )).json()
                scan_id = data.get("scan")
                if scan_id is None:
                    return {"success": False, "error": f"Spider invalide: {data}", "urls_found": 0}
                while True:
                    progress = int((await client.get(
                        f"{ZAP_HOST}/JSON/spider/view/status/",
                        params={"scanId": scan_id},
                    )).json().get("status", 0))
                    if progress >= 100:
                        break
                    await asyncio.sleep(3)
                urls = (await client.get(
                    f"{ZAP_HOST}/JSON/spider/view/results/",
                    params={"scanId": scan_id},
                )).json().get("results", [])
                return {"success": True, "urls_found": len(urls), "scan_id": scan_id}
        except Exception as e:
            return {"success": False, "error": str(e), "urls_found": 0}

    async def _phase_inject(self, target_url: str) -> dict:
        logger.info(f"Phase 3 — Active scan {target_url}")
        parsed      = urlparse(target_url)
        target_base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(timeout=300) as client:

                logger.info(f"Spider complet avant active scan : {target_url}")
                try:
                    spider_resp = await client.get(
                        f"{ZAP_HOST}/JSON/spider/action/scan/",
                        params={"url": target_url, "maxChildren": 50, "recurse": "true"},
                        timeout=30,
                    )
                    spider_data = spider_resp.json()
                    spider_id   = spider_data.get("scan")
                    if spider_id:
                        logger.info(f"Spider lancé : id={spider_id}")
                        deadline_sp = time.time() + 120
                        while time.time() < deadline_sp:
                            st = (await client.get(
                                f"{ZAP_HOST}/JSON/spider/view/status/",
                                params={"scanId": spider_id}, timeout=10,
                            )).json()
                            prog = int(st.get("status", 0))
                            if prog >= 100:
                                logger.info(f"✅ Spider terminé à {prog}%")
                                break
                            await asyncio.sleep(3)
                except Exception as e:
                    logger.warning(f"Spider pré-scan failed (non bloquant): {e}")

                site_ok = False
                try:
                    sites_resp = await client.get(f"{ZAP_HOST}/JSON/core/view/sites/", timeout=10)
                    raw_sites = sites_resp.json()
                    sites_list = raw_sites.get("sites", [])
                    if isinstance(sites_list, str):
                        sites_list = [sites_list] if sites_list else []
                    logger.info(f"Sites ZAP connus : {sites_list}")
                    if any(target_base in str(s) for s in sites_list):
                        logger.info(f"✅ URL dans Sites ZAP : {target_base}")
                        site_ok = True
                except Exception as e:
                    logger.warning(f"Sites ZAP check failed: {e}")

                if not site_ok:
                    logger.info(f"URL absente des Sites ZAP → forceAddToSiteMap")
                    try:
                        await client.get(
                            f"{ZAP_HOST}/JSON/core/action/sendRequest/",
                            params={
                                "request": f"GET / HTTP/1.1\r\nHost: {parsed.netloc}\r\n\r\n",
                                "followRedirects": "true",
                            },
                            timeout=15,
                        )
                    except Exception:
                        pass
                    try:
                        await client.get(
                            f"{ZAP_HOST}/JSON/core/action/accessUrl/",
                            params={"url": target_url, "followRedirects": "true"},
                            timeout=20,
                        )
                        logger.info("accessUrl forcé OK")
                    except Exception as e:
                        logger.warning(f"accessUrl failed: {e}")
                    await asyncio.sleep(3)

                logger.info(f"Lancement active scan : {target_url}")
                scan_resp = await client.get(
                    f"{ZAP_HOST}/JSON/ascan/action/scan/",
                    params={"url": target_url, "recurse": "true"},
                    timeout=60,
                )

                try:
                    scan_data = scan_resp.json()
                except Exception:
                    return {"success": False, "error": f"Réponse ZAP invalide : {scan_resp.text[:300]}"}

                if scan_resp.status_code == 400:
                    logger.warning(f"ascan 400 — réponse ZAP: {scan_data}")
                    try:
                        scan_resp2 = await client.get(
                            f"{ZAP_HOST}/JSON/ascan/action/scan/",
                            params={"recurse": "true"}, timeout=60,
                        )
                        scan_data = scan_resp2.json()
                    except Exception as e:
                        return {"success": False, "error": f"Active scan refusé par ZAP : {e}"}

                scan_id = scan_data.get("scan")
                if scan_id is None:
                    return {"success": False, "error": f"Active scan invalide : {scan_data}"}

                logger.info(f"✅ Active scan démarré : {scan_id}")

                deadline_a = time.time() + 600
                while time.time() < deadline_a:
                    progress = int((await client.get(
                        f"{ZAP_HOST}/JSON/ascan/view/status/",
                        params={"scanId": scan_id}, timeout=15,
                    )).json().get("status", 0))
                    logger.info(f"Active scan progress: {progress}%")
                    if progress >= 100:
                        logger.info("✅ Active scan terminé")
                        return {"success": True, "scan_id": scan_id, "progress": progress}
                    await asyncio.sleep(5)

                return {"success": False, "scan_id": scan_id, "error": "Timeout active scan (>600s)"}

        except Exception as e:
            logger.exception("Erreur active scan")
            return {"success": False, "error": str(e)}

    async def _start_pcap_capture(self, session_id: str) -> Optional[Path]:
            """
            Capture le trafic réseau pendant le scan ZAP.

            Correction :
            - tcpdump est lancé dans ZAP avec docker exec -u root
            - le PCAP est écrit dans /shared/dast_captures/{session_id}.pcap
            - le backend vérifie aussi /shared/dast_captures
            - permissions corrigées après capture avec chmod 644

            Volume attendu dans docker-compose :
                ./data/dast_captures:/shared/dast_captures
            """
            backend_pcap_storage = Path("/shared/dast_captures")
            container_pcap_storage = "/shared/dast_captures"

            backend_pcap_storage.mkdir(parents=True, exist_ok=True)

            host_path = backend_pcap_storage / f"{session_id}.pcap"
            container_path = f"{container_pcap_storage}/{session_id}.pcap"

            # 1. Vérifier que le volume partagé existe dans ZAP
            check_code, _, check_err = await self._run_command(
                "docker", "exec", "-u", "root", "cybersentinel_zap",
                "test", "-d", container_pcap_storage,
                timeout=5,
            )

            if check_code != 0:
                logger.warning(
                    "Volume PCAP non accessible dans ZAP : %s | erreur=%s",
                    container_pcap_storage,
                    check_err,
                )
                return None

            # 2. Vérifier que tcpdump existe dans ZAP
            td_code, _, td_err = await self._run_command(
                "docker", "exec", "-u", "root", "cybersentinel_zap",
                "which", "tcpdump",
                timeout=5,
            )

            if td_code != 0:
                logger.warning(
                    "tcpdump absent dans cybersentinel_zap. "
                    "Ajoute tcpdump dans docker/zap/Dockerfile. erreur=%s",
                    td_err,
                )
                return None

            # 3. Nettoyer un ancien fichier éventuel
            await self._run_command(
                "docker", "exec", "-u", "root", "cybersentinel_zap",
                "rm", "-f", container_path,
                timeout=5,
            )

            try:
                logger.info(
                    "Démarrage capture PCAP DAST | session=%s | fichier=%s",
                    session_id,
                    container_path,
                )

                # 4. Lancer tcpdump dans ZAP avec root
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", "-u", "root", "cybersentinel_zap",
                    "timeout", "180",
                    "tcpdump",
                    "-i", "any",
                    "-w", container_path,
                    "-s", "0",
                    "not", "arp",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=190,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Timeout local capture PCAP session=%s — arrêt forcé tcpdump",
                        session_id,
                    )

                    try:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=5)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass

                    stdout = b""
                    stderr = b"timeout local"

                stdout_text = stdout.decode(errors="ignore") if stdout else ""
                stderr_text = stderr.decode(errors="ignore") if stderr else ""

                logger.info(
                    "tcpdump terminé session=%s | code=%s | stdout=%s | stderr=%s",
                    session_id,
                    proc.returncode,
                    stdout_text[-500:],
                    stderr_text[-1000:],
                )

                # 5. Vérifier côté ZAP que le fichier existe et n'est pas vide
                check_file, _, check_file_err = await self._run_command(
                    "docker", "exec", "-u", "root", "cybersentinel_zap",
                    "test", "-s", container_path,
                    timeout=5,
                )

                if check_file != 0:
                    logger.warning(
                        "PCAP non créé ou vide dans ZAP | session=%s | path=%s | erreur=%s",
                        session_id,
                        container_path,
                        check_file_err,
                    )
                    return None

                # 6. Rendre le fichier lisible par backend / host / celery
                await self._run_command(
                    "docker", "exec", "-u", "root", "cybersentinel_zap",
                    "chmod", "644", container_path,
                    timeout=5,
                )

                # 7. Vérifier côté backend via /shared/dast_captures
                if host_path.exists() and host_path.stat().st_size > 0:
                    logger.info(
                        "PCAP créé et visible backend : %s | %.1f KB",
                        host_path,
                        host_path.stat().st_size / 1024,
                    )
                    return host_path

                # 8. Debug si ZAP voit le fichier mais backend ne le voit pas
                ls_code, ls_out, ls_err = await self._run_command(
                    "docker", "exec", "-u", "root", "cybersentinel_zap",
                    "ls", "-lh", container_path,
                    timeout=5,
                )

                logger.warning(
                    "PCAP créé côté ZAP mais non visible côté backend | "
                    "session=%s | backend_path=%s | backend_exists=%s | "
                    "zap_ls_code=%s | zap_ls_out=%s | zap_ls_err=%s",
                    session_id,
                    host_path,
                    host_path.exists(),
                    ls_code,
                    ls_out,
                    ls_err,
                )

                return None

            except Exception as e:
                logger.exception(
                    "Erreur capture PCAP session=%s : %s",
                    session_id,
                    e,
                )
                return None

    async def _phase_collect_proofs(self, target_url: str, session_id: str) -> list:
        logger.info("Phase 5 — Collecte des preuves ZAP")
        findings = []
        HOST_PCAP_STORAGE.mkdir(parents=True, exist_ok=True)
        sev_map = {
            "High": SASTSeverity.CRITICAL, "Medium": SASTSeverity.HIGH,
            "Low": SASTSeverity.MEDIUM, "Informational": SASTSeverity.INFO,
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                alerts = (await client.get(
                    f"{ZAP_HOST}/JSON/alert/view/alerts/",
                    params={"baseurl": target_url},
                )).json().get("alerts", [])

            for alert in alerts:
                if alert.get("confidence") in ("False Positive", "Low"):
                    continue
                proof = {
                    "session_id": session_id,
                    "timestamp":  datetime.now(timezone.utc).isoformat(),
                    "alert_name": alert.get("alert", ""),
                    "risk":       alert.get("risk", ""),
                    "confidence": alert.get("confidence", ""),
                    "url":        alert.get("url", ""),
                    "method":     alert.get("method", ""),
                    "param":      alert.get("param", ""),
                    "attack":     alert.get("attack", ""),
                    "evidence":   alert.get("evidence", ""),
                    "description": alert.get("description", "")[:500],
                    "solution":   alert.get("solution", "")[:300],
                    "cwe_id":     alert.get("cweid", ""),
                }
                proof_path = HOST_PCAP_STORAGE / f"{session_id}_proof_{len(findings)}.json"
                proof_path.write_text(json.dumps(proof, indent=2, ensure_ascii=False))
                findings.append({
                    **proof,
                    "severity":   sev_map.get(alert.get("risk", ""), SASTSeverity.MEDIUM).value,
                    "title":      alert.get("alert", "ZAP Finding"),
                    "cwe":        f"CWE-{alert['cweid']}" if alert.get("cweid") else None,
                    "proof_path": str(proof_path),
                    "zap_alert":  alert.get("alert", ""),
                    "tool":       "dast_zap",
                })
        except Exception as e:
            logger.error(f"Collecte preuves erreur: {e}")
        logger.info(f"Phase 5: {len(findings)} vulnérabilités")
        return findings

    async def _phase_teardown(self) -> dict:
        logger.info("Phase 6 — Teardown sandbox")
        try:
            # ZAP est conservé pour les scans suivants — on nettoie seulement webgoat/dvwa
            await self._run_compose(
                "--profile", "dast", "stop", "webgoat", "dvwa", timeout=120,
            )
            await self._run_compose(
                "--profile", "dast", "rm", "-f", "webgoat", "dvwa", timeout=120,
            )
            logger.info("✅ Teardown terminé — ZAP conservé pour scans suivants")
            return {"success": True, "zap_kept": True}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout teardown"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _process_findings(self, findings: list, session_id: str) -> None:
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            for finding in findings:
                zap_alert    = finding.get("zap_alert", "")
                cwe          = finding.get("cwe", "")
                technique_id = self.mitre_engine.resolve_ml_dast(zap_alert)
                if technique_id:
                    try:
                        await self.mitre_engine.enrich_by_technique_id(technique_id)
                    except Exception as e:
                        logger.warning(f"MITRE enrich: {e}")
                if cwe:
                    result = await db.execute(
                        select(SASTFinding)
                        .where(SASTFinding.cwe == cwe)
                        .where(SASTFinding.dast_confirmed == 0)
                        .limit(1)
                    )
                    sf = result.scalar_one_or_none()
                    if sf:
                        sf.dast_confirmed = 1
                        try:
                            await self.scoring_engine.create_incident_from_sast(sf)
                        except Exception as e:
                            logger.warning(f"Scoring: {e}")
            await db.commit()

    def get_status(self) -> dict:
        return {"active": self._session_active, "session_id": self._current_session_id}