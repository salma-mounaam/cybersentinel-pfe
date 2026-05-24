# ============================================================
# M5 — Service DAST Sandbox Isolée — v15
#
# FIX v15 — Network Switch Build → Sandbox
#   Principe : le container est d'abord lancé sur un réseau
#   bridge temporaire (internet OK) pour que l'app démarre
#   proprement (npm install runtime, migrations DB, plugins...).
#   Une fois l'app prête, on bascule vers sandbox-net
#   (internal:true) et on vérifie l'isolation avant le scan ZAP.
#
#   Méthodes ajoutées :
#     _create_build_network()      → crée bridge temporaire
#     _run_on_build_network()      → lance container avec internet
#     _switch_to_sandbox()         → connect sandbox + disconnect build
#     _verify_container_isolated() → socket TCP python3 puis docker inspect
#     _cleanup_build_network()     → supprime le réseau temporaire
#     _deploy_with_network_switch()→ orchestration complète
#
#   run_uploaded_project(), run_git_project(), run_docker_image()
#   utilisent maintenant _deploy_with_network_switch() au lieu
#   de lancer directement dans sandbox-net.
#
# Fix v14.3 : _wait_for_uploaded_app TCP + HTTP + ZAP notify
# Fix v14   : Retry intelligent LLM (Ollama llama3.1:8b)
# Fix v13   : DVPWA/aiohttp — patch config/dev.yaml
# Fix v12   : support DVPWA/aiohttp + installation Python robuste
# Fix v11   : ZAP 500 non accessible, abort si container crashé
# Fix v10   : Dockerfile natif du repo si présent
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
    """
    Trouve la vraie racine applicative.

    Amélioration v15.1 :
    - vérifie que les dossiers référencés par les scripts npm existent
    - gère les monorepos frontend/backend/client/server
    - utile pour Juice Shop, Angular, Vue, React avec workspace
    """
    if depth > 6:
        return None

    if (base / "pom.xml").exists():
        return base

    if (base / "package.json").exists():
        try:
            pkg = json.loads((base / "package.json").read_text(encoding="utf-8"))
            scripts = pkg.get("scripts", {})
            scripts_text = " ".join(str(v) for v in scripts.values()).lower()

            # Dossiers que les scripts npm référencent explicitement
            required_dirs = []
            if "frontend" in scripts_text:
                required_dirs.append("frontend")
            if "backend" in scripts_text:
                required_dirs.append("backend")
            if "client" in scripts_text:
                required_dirs.append("client")
            if "cd server" in scripts_text:
                required_dirs.append("server")

            missing_dirs = [d for d in required_dirs if not (base / d).exists()]

            if missing_dirs:
                logger.warning(
                    f"package.json ignoré : dossiers référencés absents "
                    f"{missing_dirs} dans {base}"
                )
            elif any(k in scripts for k in ["start", "serve", "dev", "build"]):
                return base

        except Exception as e:
            logger.warning(f"Lecture package.json impossible dans {base}: {e}")

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


def _collect_project_text(project_dir: Path, max_file_size: int = 500_000) -> str:
    """
    Lit plusieurs fichiers de configuration/code pour détecter les besoins
    runtime cachés (Redis/Postgres/etc.) qui ne sont pas toujours présents
    dans requirements.txt.

    Utile pour DVPWA/aiohttp : aioredis ou redis:// peut apparaître dans
    config/dev.yaml, pyproject.toml, requirements-dev.txt, etc.
    """
    patterns = [
        "*.py",
        "*.yaml",
        "*.yml",
        "*.toml",
        "*.ini",
        "*.cfg",
        "*.conf",
        "requirements*.txt",
        "Pipfile",
        "poetry.lock",
    ]

    chunks = []
    for pattern in patterns:
        try:
            for f in project_dir.rglob(pattern):
                if not f.is_file():
                    continue
                if any(part in _IGNORE_DIRS for part in f.parts):
                    continue
                try:
                    if f.stat().st_size <= max_file_size:
                        chunks.append(f.read_text(errors="ignore").lower())
                except Exception:
                    pass
        except Exception:
            pass

    return "\n".join(chunks)


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
        combined_full = combined + "\n" + _collect_project_text(project_dir)

        redis_indicators = [
            "redis",
            "aioredis",
            "redis://",
            "redis_host",
            "redis:",
            "localhost:6379",
            "127.0.0.1:6379",
        ]

        analysis["needs_mongo"]    = any(x in combined_full for x in ["pymongo", "mongoengine", "motor", "mongodb://", "mongo:"])
        analysis["needs_redis"]    = any(x in combined_full for x in redis_indicators)
        analysis["needs_postgres"] = any(x in combined_full for x in ["psycopg2", "asyncpg", "sqlalchemy", "postgres", "postgresql://", "postgres:"])
        analysis["needs_mysql"]    = any(x in combined_full for x in ["pymysql", "mysqlclient", "aiomysql", "mysql://", "mariadb"])

        if "fastapi" in combined_full or "uvicorn" in combined_full:
            analysis["stack"] = "fastapi"; analysis["port"] = 8000
        elif "aiohttp" in combined_full:
            analysis["stack"] = "aiohttp"; analysis["port"] = 8080
            # DVPWA/aiohttp utilise souvent aioredis au runtime.
            # On force Redis pour éviter Empty reply / connection reset.
            analysis["needs_redis"] = True
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
    if analysis["needs_redis"] or analysis.get("stack") == "aiohttp":
        lines += [
            "echo 'Démarrage Redis...'",
            "redis-server --daemonize yes --loglevel warning",
            "sleep 2",
        ]
    if analysis["needs_postgres"]:
        lines += [
            "service postgresql start",
            "echo 'Attente PostgreSQL...'",
            "for i in $(seq 1 15); do pg_isready -q && break || sleep 2; done",
            "su postgres -c \"psql -c \\\"CREATE USER mock WITH PASSWORD 'mock';\\\" 2>/dev/null\" || true",
            "su postgres -c \"createdb -O mock mockdb 2>/dev/null\" || true",
            "su postgres -c \"psql -c \\\"ALTER USER postgres WITH PASSWORD 'postgres';\\\" 2>/dev/null\" || true",
            "su postgres -c \"createdb sqli 2>/dev/null\" || true",
            "for sql_file in $(find /app/migrations /app/db /app/sql /app/database -name '*.sql' 2>/dev/null | sort); do",
            "  echo \"[CyberSentinel] Migration: $sql_file\"",
            "  su postgres -c \"psql -d sqli -f $sql_file 2>/dev/null\" || true",
            "  su postgres -c \"psql -d mockdb -f $sql_file 2>/dev/null\" || true",
            "done",
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


def _detect_node_version(project_dir: Path) -> str:
    """
    Détecte la version Node.js optimale depuis package.json.

    Corrections :
    - OWASP Juice Shop 20 exige Node 22 à 25.
    - Respecte engines.node si le projet demande Node 22/23/24/25.
    - Garde la compatibilité avec les projets Node 20/18/16.
    """
    package_json = project_dir / "package.json"

    try:
        if not package_json.exists():
            logger.info("Version Node : 20 (package.json absent, défaut sécurisé)")
            return "20"

        pkg = json.loads(package_json.read_text(encoding="utf-8"))

        engines = pkg.get("engines", {}) or {}
        node_engine = str(engines.get("node", "")).lower().strip()
        name = str(pkg.get("name", "")).lower().strip()
        version = str(pkg.get("version", "")).lower().strip()
        path_hint = str(project_dir).lower()

        # Cas spécial OWASP Juice Shop récent.
        # Les versions 20.x refusent de démarrer avec Node 20.
        if "juice-shop" in name or "juice-shop" in path_hint:
            logger.info(
                f"Version Node : 22 détectée pour Juice Shop "
                f"(name={name}, version={version}, engines.node={node_engine})"
            )
            return "22"

        # engines.node explicite : versions récentes
        if any(x in node_engine for x in [">=25", "^25", "25.", " 25"]):
            logger.info(f"Version Node : 25 (engines.node={node_engine})")
            return "25"

        if any(x in node_engine for x in [">=24", "^24", "24.", " 24"]):
            logger.info(f"Version Node : 24 (engines.node={node_engine})")
            return "24"

        if any(x in node_engine for x in [">=23", "^23", "23.", " 23"]):
            logger.info(f"Version Node : 23 (engines.node={node_engine})")
            return "23"

        if any(x in node_engine for x in [">=22", "^22", "22.", " 22"]):
            logger.info(f"Version Node : 22 (engines.node={node_engine})")
            return "22"

        # >=21 → choisir Node 22, stable et compatible.
        if any(x in node_engine for x in [">=21", "^21", "21.", " 21"]):
            logger.info(f"Version Node : 22 choisie pour compatibilité >=21 ({node_engine})")
            return "22"

        if any(x in node_engine for x in [">=20", "^20", "20.", " 20"]):
            logger.info(f"Version Node : 20 (engines.node={node_engine})")
            return "20"

        if any(x in node_engine for x in [">=18", "^18", "18.", " 18"]):
            logger.info(f"Version Node : 18 (engines.node={node_engine})")
            return "18"

        if any(x in node_engine for x in [">=16", "^16", "16.", " 16"]):
            logger.info(f"Version Node : 16 (engines.node={node_engine})")
            return "16"

        deps = {
            **pkg.get("dependencies", {}),
            **pkg.get("devDependencies", {}),
        }
        deps_text = " ".join(deps.keys()).lower()

        if any(d in deps_text for d in ["vite", "angular", "cypress", "nx"]):
            logger.info("Version Node : 20 (dépendances modernes détectées)")
            return "20"

    except Exception as e:
        logger.warning(f"Détection version Node impossible : {e}")

    logger.info("Version Node : 18 (défaut)")
    return "18"

def _validate_project_structure(project_dir: Path, analysis: dict) -> Tuple[bool, str]:
    """
    Vérifie la cohérence de la structure avant le build.
    Retourne (ok, message_erreur).

    Évite les erreurs opaques :
    - npm ERR! sh -c cd frontend — dossier absent
    - node-gyp Python not found
    - package.json valide mais racine incorrecte
    """
    if analysis.get("stack") != "node":
        return True, ""

    package_json = project_dir / "package.json"

    if not package_json.exists():
        return False, "Projet Node.js invalide : package.json introuvable."

    try:
        pkg = json.loads(package_json.read_text(encoding="utf-8"))
        scripts = pkg.get("scripts", {})
        scripts_text = " ".join(str(v) for v in scripts.values()).lower()

        required_dirs = []
        if "frontend" in scripts_text:
            required_dirs.append("frontend")
        if "backend" in scripts_text:
            required_dirs.append("backend")
        if "client" in scripts_text:
            required_dirs.append("client")
        if "cd server" in scripts_text:
            required_dirs.append("server")

        missing_dirs = [d for d in required_dirs if not (project_dir / d).exists()]

        if missing_dirs:
            return False, (
                "Projet Node.js incomplet ou mauvaise racine détectée : "
                f"package.json référence {missing_dirs} mais ces dossiers sont absents. "
                "Uploadez le projet complet depuis sa racine."
            )

        if not any(k in scripts for k in ["start", "serve", "dev", "build"]):
            logger.warning(
                f"Projet Node.js sans script start/serve/dev/build : {project_dir}"
            )

    except Exception as e:
        return False, f"Impossible de lire package.json : {e}"

    return True, ""


def _generate_dockerfile(analysis: dict) -> str:
    stack = analysis["stack"]
    needs_mongo = analysis["needs_mongo"]
    needs_redis = analysis["needs_redis"]
    needs_postgres = analysis["needs_postgres"]
    needs_mysql = analysis["needs_mysql"]
    entry = analysis.get("entry")
    port = analysis["port"]
    project_dir = Path(analysis["project_dir"])
    forced_redis = needs_redis or stack == "aiohttp"
    services_needed = needs_mongo or forced_redis or needs_postgres or needs_mysql
    python_version = "python:3.8-slim" if stack == "aiohttp" else "python:3.11-slim"

    build_deps = """RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc g++ make python3-dev libffi-dev libssl-dev libpq-dev \\
    && rm -rf /var/lib/apt/lists/*

"""
    replace_psycopg2 = """RUN sed -i -E 's/^psycopg2([=><!~].*)?$/psycopg2-binary/g' requirements.txt && \\
    sed -i -E 's/^psycopg2-binary-binary/psycopg2-binary/g' requirements.txt

"""

    if stack == "node":
        # Détecter la version Node requise depuis engines.node
        node_version = _detect_node_version(project_dir)

        # Dépendances build natives obligatoires :
        # - python3 + make + g++ → node-gyp pour modules natifs (libxmljs2, bcrypt, canvas...)
        # - libxml2-dev + libxslt1-dev → libxmljs2 spécifiquement
        # - git → postinstall scripts qui clonent des dépôts
        node_build_packages = """RUN apt-get update && apt-get install -y --no-install-recommends \\
    python3 python3-pip make g++ gcc build-essential pkg-config \\
    libxml2-dev libxslt1-dev git ca-certificates curl \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*
ENV PYTHON=/usr/bin/python3

"""
        # IMPORTANT : COPY . . AVANT npm install
        # Certains projets (Juice Shop, monorepos) ont un postinstall
        # qui dépend de dossiers internes (frontend/, lib/, etc.).
        # L'ancien pattern COPY package*.json + npm install + COPY . .
        # cassait ces projets.
        if services_needed:
            _write_start_script(project_dir, analysis, "npm start")

            mongo_repo = ""
            if needs_mongo:
                # MongoDB repo Ubuntu Jammy (22.04) → libc6 >= 2.34 + libssl3 disponibles
                # NE PAS utiliser node:bullseye avec ce repo (Debian 11 = libc6 2.31 → incompatible)
                mongo_repo = """RUN curl -fsSL https://www.mongodb.org/static/pgp/server-6.0.asc | \\
    gpg --dearmor -o /usr/share/keyrings/mongodb.gpg && \\
    echo "deb [ arch=amd64 signed-by=/usr/share/keyrings/mongodb.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \\
    > /etc/apt/sources.list.d/mongodb-org-6.0.list && \\
    apt-get update && apt-get install -y --no-install-recommends mongodb-org && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

"""

            extra_pkgs = []
            if needs_redis: extra_pkgs.append("redis-server")
            if needs_postgres: extra_pkgs += ["postgresql", "postgresql-client"]
            if needs_mysql: extra_pkgs.append("mariadb-server")
            extra_install = (
                f"RUN apt-get update && apt-get install -y --no-install-recommends "
                f"{' '.join(extra_pkgs)} "
                f"&& apt-get clean && rm -rf /var/lib/apt/lists/*\n"
            ) if extra_pkgs else ""

            if needs_mongo:
                # MongoDB est compatible Ubuntu Jammy seulement.
                # On utilise ubuntu:22.04 + NodeSource au lieu de node:bullseye
                # pour éviter l'incompatibilité libc6/libssl3 (Debian 11 vs Ubuntu 22.04)
                return f"""FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl gnupg2 ca-certificates \\
    python3 python3-pip make g++ gcc build-essential pkg-config \\
    libxml2-dev libxslt1-dev git \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PYTHON=/usr/bin/python3

RUN curl -fsSL https://deb.nodesource.com/setup_{node_version}.x | bash - \\
    && apt-get install -y nodejs \\
    && npm install -g npm@latest \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

{mongo_repo}
{extra_install}
WORKDIR /app
COPY . .
RUN npm install --legacy-peer-deps || npm install --force
RUN chmod +x /app/start.cybersentinel.sh

EXPOSE {port}
CMD ["/bin/bash", "/app/start.cybersentinel.sh"]
"""
            # Services sans MongoDB (redis/postgres/mysql) → node:bullseye OK
            return f"""FROM node:{node_version}-bullseye
ENV DEBIAN_FRONTEND=noninteractive
{node_build_packages}
{extra_install}
WORKDIR /app
COPY . .
RUN npm install --legacy-peer-deps || npm install --force
RUN chmod +x /app/start.cybersentinel.sh
EXPOSE {port}
CMD ["/bin/bash", "/app/start.cybersentinel.sh"]
"""
        # Node sans services — même principe : COPY . . avant npm install
        return f"""FROM node:{node_version}-bullseye
{node_build_packages}
WORKDIR /app
COPY . .
RUN npm install --legacy-peer-deps || npm install --force
EXPOSE {port}
CMD ["npm", "start"]
"""

    elif stack in ("flask", "fastapi", "aiohttp"):
        extra_pip = ""
        if needs_mongo: extra_pip += "\nRUN pip install --no-cache-dir mongomock"
        if forced_redis: extra_pip += "\nRUN pip install --no-cache-dir fakeredis"

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
            if forced_redis:
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
    needs_mongo    = analysis["needs_mongo"]
    needs_redis    = analysis["needs_redis"]
    needs_postgres = analysis["needs_postgres"]
    needs_mysql    = analysis["needs_mysql"]
    port           = analysis["port"]
    env_example    = analysis.get("env_example", {})

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
    if needs_redis or analysis.get("stack") == "aiohttp":
        env += [
            "REDIS_URL=redis://127.0.0.1:6379/0", "REDIS_HOST=127.0.0.1", "REDIS_PORT=6379",
            "REDIS_DSN=redis://127.0.0.1:6379/0",
            "CACHE_URL=redis://127.0.0.1:6379/0",
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

    # Valider la structure avant de générer le Dockerfile
    ok, validation_error = _validate_project_structure(project_dir, analysis)
    if not ok:
        raise ValueError(validation_error)

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
# LLM retry universel (v14)
# ─────────────────────────────────────────────────────────────

async def _llm_retry(
    orchestrator,
    project_dir: Path,
    container_name: str,
    image_name: str,
    target_url: str,
    stack_type: str,
    project_name: str,
    build_network: Optional[str] = None,
) -> Tuple[bool, str, str]:
    """
    Retry intelligent LLM après échec healthcheck.
    Si build_network est fourni, le nouveau container est lancé sur ce réseau
    (internet OK) pour que le LLM puisse corriger et que l'app démarre.
    Le switch vers sandbox-net est fait par l'appelant après succès.
    """
    try:
        from app.services.dast_llm_helper import generate_start_script

        logger.warning(f"[LLM RETRY] App '{project_name}' non accessible — tentative réparation LLM")

        _, logs_out, logs_err = await orchestrator._run_command(
            "docker", "logs", "--tail", "120", container_name, timeout=10,
        )
        final_logs = (logs_out + "\n" + logs_err).strip()

        try:
            stack_info = _detect_stack(project_dir)
            real_project_dir = Path(stack_info.get("project_dir", str(project_dir)))
        except Exception:
            real_project_dir = project_dir

        analysis = _analyze_project(real_project_dir)

        current_script = ""
        script_path = real_project_dir / "start.cybersentinel.sh"
        if script_path.exists():
            current_script = script_path.read_text(errors="ignore")

        new_script = await generate_start_script(
            project_dir=real_project_dir,
            current_script=current_script,
            container_logs=final_logs,
            analysis=analysis,
        )

        if not new_script:
            logger.warning("[LLM RETRY] LLM n'a pas généré de script valide")
            return False, target_url, final_logs

        script_path.write_text(new_script, encoding="utf-8")
        script_path.chmod(0o755)
        logger.info(f"[LLM RETRY] Nouveau script écrit ({len(new_script)} chars)")

        await orchestrator._cleanup_uploaded_target(container_name, image_name)

        # Rebuild et lancement sur réseau build (internet) si disponible
        code, new_target_url, error_msg, _ = await orchestrator._build_and_run_on_network(
            real_project_dir, image_name, container_name,
            network=build_network or "bridge",
        )

        if code != 0:
            logger.error(f"[LLM RETRY] Rebuild échoué: {error_msg[:300]}")
            return False, target_url, error_msg

        await asyncio.sleep(30)
        running, crash_logs = await orchestrator._check_container_running(container_name)
        if not running:
            logger.error(f"[LLM RETRY] Container crashé après LLM: {crash_logs[:300]}")
            return False, new_target_url, crash_logs

        ready = await orchestrator._wait_for_app_via_backend_on_build_network(
            new_target_url, build_network, timeout=240
        ) if build_network else await orchestrator._wait_for_app_direct(new_target_url, timeout=240)
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

    async def _resolve_container_ip(self, container_name: str, network: Optional[str] = None) -> str:
        """
        Résout l'IP du container.
        Si network est fourni, retourne l'IP sur ce réseau spécifique.
        Sinon retourne la première IP disponible.
        """
        if network:
            # Les noms de réseau Docker contiennent parfois des tirets.
            # Le template .Networks.cybersentinel_sandbox-net casse avec '-' ;
            # il faut utiliser index.
            fmt = f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}'
        else:
            fmt = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"

        code, out, err = await self._run_command(
            "docker", "inspect", "-f", fmt, container_name, timeout=10,
        )
        if code != 0:
            raise RuntimeError(f"Impossible de résoudre IP container {container_name}: {err or out}")
        ip = out.strip()
        if not ip:
            raise RuntimeError(f"IP vide pour le container {container_name} (réseau: {network})")
        logger.info(f"IP container {container_name} sur {network or 'any'} → {ip}")
        return ip

    async def _target_url_from_container(self, container_name: str, port: int, network: Optional[str] = None) -> str:
        ip = await self._resolve_container_ip(container_name, network)
        return f"http://{ip}:{port}"

    def _detect_port_from_dockerfile(self, dockerfile_path: Path) -> int:
        try:
            content = dockerfile_path.read_text(errors="ignore")
            match = re.search(r"EXPOSE\s+(\d+)", content, re.MULTILINE | re.IGNORECASE)
            if match:
                return int(match.group(1))
            lower = content.lower()
            if any(kw in lower for kw in ["spring", "java", "maven", "gradle", ".jar"]):
                return 8080
            if any(kw in lower for kw in ["node", "npm", "yarn"]):
                return 3000
            if any(kw in lower for kw in ["uvicorn", "fastapi"]):
                return 8000
            if any(kw in lower for kw in ["aiohttp", "flask", "gunicorn", "python"]):
                return 5000
            if any(kw in lower for kw in ["php", "apache", "nginx"]):
                return 80
        except Exception as e:
            logger.warning(f"_detect_port_from_dockerfile erreur: {e}")
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
            logger.info("✅ Isolation sandbox-net OK" if is_internal else "❌ sandbox-net NON isolé")
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
            code, out, _ = await self._run_command(
                "docker", "inspect", "--format", "{{.State.Running}}",
                "cybersentinel_zap", timeout=10,
            )
            if code == 0 and out.strip().lower() == "true":
                isolation_ok = await self._verify_isolation()
                zap_ready    = await self._wait_for_zap(timeout=60)
                if isolation_ok and zap_ready:
                    return {"success": True, "isolation_ok": isolation_ok, "zap_ready": zap_ready,
                            "details": "ZAP déjà existant et opérationnel"}
                await self._run_command("docker", "rm", "-f", "cybersentinel_zap", timeout=60)

            code, stdout, stderr = await self._run_compose(
                "--profile", "dast", "up", "-d", "--no-recreate", "zap", timeout=180,
            )
            if code != 0:
                return {"success": False, "error": (stderr or stdout)[:1200]}

            await asyncio.sleep(5)
            isolation_ok = await self._verify_isolation()
            zap_ready    = await self._wait_for_zap(timeout=240)
            return {"success": bool(isolation_ok and zap_ready),
                    "isolation_ok": isolation_ok, "zap_ready": zap_ready}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout ZAP (>180s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ─────────────────────────────────────────────────────────
    # v15 — Network Switch : build → sandbox
    # ─────────────────────────────────────────────────────────

    async def _create_build_network(self, unique_id: str) -> str:
        """
        Crée un réseau bridge temporaire AVEC accès internet.
        Utilisé pour que l'app puisse démarrer complètement
        (téléchargements runtime, migrations, plugins) avant
        d'être basculée dans sandbox-net (internal:true).
        """
        network_name = f"cybersentinel_build_{unique_id}"
        code, out, err = await self._run_command(
            "docker", "network", "create",
            "--driver", "bridge",
            "--label", "cybersentinel=build-temp",
            network_name,
            timeout=30,
        )
        if code != 0:
            raise RuntimeError(f"Création réseau build échouée : {err or out}")
        logger.info(f"✅ Réseau build créé : {network_name}")
        return network_name

    async def _cleanup_build_network(self, build_network: str) -> None:
        """
        Supprime le réseau build temporaire.

        Problème : si un container est encore attaché au réseau,
        docker network rm échoue. On force la déconnexion de tous
        les containers encore présents avant la suppression.
        """
        try:
            # Lister les containers encore attachés au réseau build
            code, out, err = await self._run_command(
                "docker", "network", "inspect",
                "--format",
                "{{range .Containers}}{{.Name}} {{end}}",
                build_network,
                timeout=10,
            )

            if code == 0 and out.strip():
                attached = out.strip().split()
                logger.info(
                    f"[CLEANUP] Containers encore sur {build_network} : {attached}"
                )
                # Forcer la déconnexion de chaque container
                for cname in attached:
                    dc_code, _, dc_err = await self._run_command(
                        "docker", "network", "disconnect", "-f",
                        build_network, cname,
                        timeout=15,
                    )
                    if dc_code == 0:
                        logger.info(f"[CLEANUP] {cname} déconnecté de {build_network}")
                    else:
                        logger.warning(
                            f"[CLEANUP] Déconnexion {cname} échouée (non bloquant) : {dc_err}"
                        )

            # Supprimer le réseau build
            rm_code, _, rm_err = await self._run_command(
                "docker", "network", "rm", build_network,
                timeout=30,
            )
            if rm_code == 0:
                logger.info(f"✅ Réseau build supprimé : {build_network}")
            else:
                logger.warning(
                    f"Réseau build non supprimé {build_network} : {rm_err}"
                )

        except Exception as e:
            logger.warning(f"Erreur cleanup réseau build {build_network}: {e}")

    async def _wait_for_app_direct(self, target_url: str, timeout: int = 300) -> bool:
        """
        Healthcheck direct depuis le backend pendant la phase build.

        v15.3 :
        - TCP seul n'est plus suffisant, car DVPWA ouvrait le port puis
          retournait "Empty reply from server".
        - On exige une vraie réponse HTTP sur / ou sur des chemins courants.
        - Un statut < 500 est considéré comme prêt, même 404/403, car cela
          prouve qu'un serveur HTTP répond correctement.
        """
        from urllib.parse import urlparse as _urlparse
        import socket as _socket

        parsed = _urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or 80

        base = target_url.rstrip("/")
        health_urls = [
            base + "/",
            base + "/login",
            base + "/search",
            base + "/products",
            base + "/api/products",
        ]

        deadline = time.time() + timeout
        consecutive_tcp_ok = 0

        logger.info(f"Attente démarrage app direct HTTP réel : {host}:{port}")

        async with httpx.AsyncClient(follow_redirects=True) as client:
            while time.time() < deadline:
                # 1. TCP informatif uniquement
                try:
                    loop = asyncio.get_event_loop()

                    def _tcp_check():
                        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                        sock.settimeout(5)
                        try:
                            return sock.connect_ex((host, port))
                        finally:
                            sock.close()

                    tcp_result = await loop.run_in_executor(None, _tcp_check)

                    if tcp_result == 0:
                        consecutive_tcp_ok += 1
                        logger.info(
                            f"Port {port} ouvert depuis backend "
                            f"({consecutive_tcp_ok}) : {target_url}"
                        )
                    else:
                        consecutive_tcp_ok = 0

                except Exception as e:
                    consecutive_tcp_ok = 0
                    logger.info(f"Attente TCP app... {e}")

                # 2. HTTP réel : critère principal
                for url in health_urls:
                    try:
                        resp = await client.get(url, timeout=8)

                        # Une réponse HTTP valide <500 suffit pour dire que
                        # l'app est exploitable par ZAP. Le body peut être vide.
                        if resp.status_code < 500:
                            logger.info(
                                f"✅ App prête via HTTP {resp.status_code} : "
                                f"{url} body_len={len(resp.text or '')}"
                            )
                            return True

                        logger.info(
                            f"HTTP {resp.status_code} sur {url}, "
                            f"body_len={len(resp.text or '')}"
                        )

                    except Exception as e:
                        # Ici on attrape Empty reply / reset / timeout.
                        logger.info(f"HTTP non prêt sur {url} : {e}")

                await asyncio.sleep(5)

        logger.error(f"❌ App non accessible HTTP après {timeout}s : {target_url}")
        return False

    async def _wait_for_app_via_backend_on_build_network(
        self,
        target_url: str,
        build_network: str,
        timeout: int = 300,
    ) -> bool:
        """
        Connecte temporairement le backend au réseau build pour tester
        l'URL http://IP_CONTAINER:PORT.

        Sans cette connexion, le backend est seulement sur main-net/mgmt-net
        et ne peut pas joindre l'IP privée du réseau cybersentinel_build_xxxxxxxx.
        """
        backend_container = os.getenv(
            "CYBERSENTINEL_BACKEND_CONTAINER",
            "cybersentinel_backend",
        )
        backend_connected = False

        logger.info(
            f"[SWITCH] Connexion backend au réseau build pour healthcheck : "
            f"{backend_container} → {build_network}"
        )

        code, out, err = await self._run_command(
            "docker", "network", "connect",
            build_network,
            backend_container,
            timeout=30,
        )
        msg = (err or out or "").strip()

        if code == 0:
            backend_connected = True
            logger.info(f"[SWITCH] ✅ Backend connecté à {build_network}")
        elif "already exists" in msg.lower() or "already connected" in msg.lower():
            backend_connected = True
            logger.info(f"[SWITCH] Backend déjà connecté à {build_network}")
        else:
            logger.warning(f"[SWITCH] Connexion backend au build_network échouée : {msg}")

        try:
            return await self._wait_for_app_direct(target_url, timeout=timeout)
        finally:
            if backend_connected:
                dc_code, dc_out, dc_err = await self._run_command(
                    "docker", "network", "disconnect",
                    build_network,
                    backend_container,
                    timeout=30,
                )
                dc_msg = (dc_err or dc_out or "").strip()
                if dc_code == 0:
                    logger.info(f"[SWITCH] ✅ Backend déconnecté du réseau build : {build_network}")
                else:
                    logger.warning(
                        f"[SWITCH] Déconnexion backend du build_network échouée : {dc_msg}"
                    )

    async def _switch_to_sandbox(
        self, container_name: str, build_network: str
    ) -> Tuple[bool, str]:
        """
        Bascule le container du réseau build (internet) vers sandbox-net (isolé).

        Ordre critique :
        1. Connecter à sandbox-net D'ABORD (ZAP doit pouvoir joindre le container)
        2. Déconnecter du réseau build (couper internet)
        3. Vérifier l'isolation (python3 socket TCP puis docker inspect)
        4. Résoudre la nouvelle IP sandbox-net

        Retourne (success, new_sandbox_ip)
        """
        logger.info(f"[SWITCH] Bascule réseau : {build_network} → sandbox-net")

        # 1. Connecter à sandbox-net
        code, out, err = await self._run_command(
            "docker", "network", "connect",
            "cybersentinel_sandbox-net",
            container_name,
            timeout=30,
        )
        if code != 0:
            logger.error(f"[SWITCH] Connexion sandbox-net échouée : {err}")
            return False, ""

        logger.info(f"[SWITCH] ✅ {container_name} connecté à sandbox-net")

        # 2. Déconnecter du réseau build (couper internet)
        code, out, err = await self._run_command(
            "docker", "network", "disconnect",
            build_network,
            container_name,
            timeout=30,
        )
        if code != 0:
            logger.warning(f"[SWITCH] Déconnexion build_network échouée (non bloquant) : {err}")
        else:
            logger.info(f"[SWITCH] ✅ {container_name} déconnecté de {build_network}")

        # 3. Vérifier l'isolation
        isolated = await self._verify_container_isolated(container_name)
        if not isolated:
            logger.error(f"[SWITCH] ❌ ISOLATION ÉCHOUÉE pour {container_name}")
            return False, ""

        # 4. Résoudre la nouvelle IP sur sandbox-net
        try:
            # Le nom du réseau Docker normalise les tirets en underscores
            net_key = "cybersentinel_sandbox-net"
            sandbox_ip = await self._resolve_container_ip(container_name, net_key)
            logger.info(f"[SWITCH] ✅ IP sandbox-net : {sandbox_ip}")
            return True, sandbox_ip
        except Exception as e:
            logger.warning(f"[SWITCH] Résolution IP sandbox échouée (fallback) : {e}")
            # Fallback : essayer sans réseau spécifique
            try:
                sandbox_ip = await self._resolve_container_ip(container_name)
                return True, sandbox_ip
            except Exception as e2:
                logger.error(f"[SWITCH] IP introuvable : {e2}")
                return False, ""

    async def _verify_container_isolated(self, container_name: str) -> bool:
        """
        Vérifie que le container n'a plus accès à internet.

        Cascade de tests — du plus fiable au fallback :

        Méthode 1 — python3 socket TCP (fiable, sans dépendance externe)
            Si python3 existe dans l'image, tente connexion TCP 8.8.8.8:53.
            Succès → internet accessible → isolation échouée.
            Échec (code=1) → isolé ✅
            Absent (code=126/127) → fallback M2

        Méthode 2 — docker network inspect (toujours disponible)
            Vérifie que le container n'est connecté QU'à sandbox-net
            ET que sandbox-net est bien internal:true.
            Ne dépend d'aucun binaire dans l'image uploadée → plus robuste.

        On évite ping car absent dans la plupart des images slim/alpine.
        """
        # ── Méthode 1 : python3 socket TCP vers 8.8.8.8:53 ──────────
        code, out, err = await self._run_command(
            "docker", "exec", container_name,
            "python3", "-c",
            (
                "import socket, sys; "
                "s = socket.socket(); "
                "s.settimeout(3); "
                "r = s.connect_ex(('8.8.8.8', 53)); "
                "s.close(); "
                "sys.exit(0 if r == 0 else 1)"
            ),
            timeout=10,
        )

        if code == 0:
            # python3 a contacté 8.8.8.8 → encore sur internet → pas isolé
            logger.error(
                f"❌ [M1] ISOLATION ÉCHOUÉE (python3 socket) : "
                f"{container_name} a encore accès à internet"
            )
            return False

        if code == 1:
            # python3 n'a pas pu joindre 8.8.8.8 → isolé ✅
            logger.info(
                f"✅ [M1] Isolation confirmée (python3 socket) : "
                f"{container_name} sans accès internet"
            )
            return True

        # code 126/127 → python3 absent dans l'image → méthode 2
        logger.info(
            f"[ISOLATION] python3 absent dans {container_name} "
            f"(code={code}) → fallback docker inspect"
        )

        # ── Méthode 2 : docker network inspect ───────────────────────
        # Récupère tous les réseaux auxquels le container est connecté
        code2, out2, err2 = await self._run_command(
            "docker", "inspect",
            "--format",
            "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
            container_name,
            timeout=10,
        )

        if code2 != 0:
            logger.warning(
                f"[ISOLATION] docker inspect échoué pour {container_name}: {err2}"
            )
            # Impossible de vérifier → on refuse le scan par précaution (C-05)
            return False

        connected_networks = out2.strip().split()
        logger.info(
            f"[ISOLATION] Réseaux de {container_name} : {connected_networks}"
        )

        # Le container doit être connecté UNIQUEMENT à sandbox-net
        sandbox_variants = {"cybersentinel_sandbox-net", "cybersentinel_sandbox_net"}
        non_sandbox = [n for n in connected_networks if n not in sandbox_variants]

        if non_sandbox:
            logger.error(
                f"❌ [M2] ISOLATION ÉCHOUÉE (docker inspect) : "
                f"{container_name} encore sur : {non_sandbox}"
            )
            return False

        # Vérifier que sandbox-net est bien internal:true
        code3, out3, _ = await self._run_command(
            "docker", "network", "inspect",
            "cybersentinel_sandbox-net",
            "--format", "{{.Internal}}",
            timeout=10,
        )

        if code3 == 0 and out3.strip().lower() == "true":
            logger.info(
                f"✅ [M2] Isolation confirmée (docker inspect) : "
                f"{container_name} sur sandbox-net internal:true uniquement"
            )
            return True

        logger.error(
            f"❌ [M2] sandbox-net non isolé (Internal={out3.strip()}) — "
            f"scan DAST annulé (contrainte C-05)"
        )
        return False

    async def _build_and_run_on_network(
        self,
        project_dir: Path,
        image_name: str,
        container_name: str,
        network: str = "bridge",
    ) -> Tuple[int, str, str, str]:
        """
        Build l'image et lance le container sur le réseau spécifié.
        Contrairement à _build_and_run(), ne lance PAS sur sandbox-net.
        C'est _switch_to_sandbox() qui s'en charge ensuite.
        """
        try:
            stack = _detect_stack(project_dir)
        except ValueError as e:
            return 1, "", str(e), ""

        real_project_dir = Path(stack.get("project_dir", str(project_dir)))
        dockerfile_path = real_project_dir / "Dockerfile.cybersentinel"
        dockerfile_path.write_text(stack["dockerfile"], encoding="utf-8")

        logger.info(f"Build {stack['type']} → {image_name}")

        build_code, build_out, build_err = await self._run_command(
            "docker", "build", "--no-cache",
            "-f", str(dockerfile_path), "-t", image_name, str(real_project_dir),
            timeout=900, env={"DOCKER_BUILDKIT": "0"},
        )

        if build_code != 0:
            dockerfile_content = dockerfile_path.read_text(errors="ignore") if dockerfile_path.exists() else ""
            error_msg = (
                f"Build échoué ({stack['type']}):\n\n"
                f"DOCKERFILE:\n{dockerfile_content[:3000]}\n\n"
                f"STDOUT:\n{build_out[-8000:]}\n\n"
                f"STDERR:\n{build_err[-8000:]}"
            )
            logger.error(error_msg)
            return build_code, "", error_msg, stack["type"]

        env_args = []
        for e in stack.get("env", []):
            env_args += ["--env", e]

        run_code, run_out, run_err = await self._run_command(
            "docker", "run", "-d",
            "--name", container_name,
            "--network", network,  # ← réseau passé en paramètre
            "--restart", "no",
            *env_args, image_name,
            timeout=120,
        )

        if run_code != 0:
            return run_code, "", f"Lancement échoué : {(run_err or run_out)[:2000]}", stack["type"]

        # IP sur le réseau de build
        try:
            ip = await self._resolve_container_ip(container_name)
            target_url = f"http://{ip}:{stack['port']}"
        except Exception as e:
            target_url = f"http://{container_name}:{stack['port']}"
            logger.warning(f"Fallback URL : {e}")

        logger.info(f"Container lancé sur {network} → {target_url}")
        return 0, target_url, "", stack["type"]

    async def _deploy_with_network_switch(
        self,
        project_dir: Path,
        image_name: str,
        container_name: str,
        unique_id: str,
        dockerfile_native: bool = False,
        port_override: Optional[int] = None,
        project_name: str = "project",
    ) -> Tuple[int, str, str, str]:
        """
        Pipeline complet v15 — Network Switch Build → Sandbox.

        Étapes :
        1. Créer réseau build temporaire (bridge + internet)
        2. Builder l'image
        3. Lancer le container sur réseau build
        4. Attendre que l'app soit prête (avec internet)
        5. LLM retry si nécessaire (sur réseau build toujours)
        6. Basculer vers sandbox-net (couper internet)
        7. Vérifier isolation (python3 socket TCP puis docker inspect)
        8. Retourner l'URL sandbox pour ZAP

        Retourne (code, sandbox_url, error_msg, stack_type)
        """
        build_network = None

        try:
            # ── Étape 1 : Créer réseau build ─────────────────
            build_network = await self._create_build_network(unique_id)

            # ── Étape 2+3 : Build + lancement sur réseau build ─
            if dockerfile_native and port_override:
                # Dockerfile natif du repo — build déjà fait par l'appelant
                # On lance directement sur le réseau build
                run_code, run_out, run_err = await self._run_command(
                    "docker", "run", "-d",
                    "--name", container_name,
                    "--network", build_network,
                    "--restart", "no",
                    image_name, timeout=120,
                )
                if run_code != 0:
                    return 1, "", f"Lancement échoué : {(run_err or run_out)[:600]}", "dockerfile"
                try:
                    ip = await self._resolve_container_ip(container_name)
                    target_url = f"http://{ip}:{port_override}"
                except Exception:
                    target_url = f"http://{container_name}:{port_override}"
                stack_type = "dockerfile"
            else:
                # Stack auto (node/python/php/spring)
                code, target_url, error_msg, stack_type = await self._build_and_run_on_network(
                    project_dir, image_name, container_name, network=build_network,
                )
                if code != 0:
                    return code, "", error_msg, stack_type

            # ── Étape 4 : Attendre prêt (avec internet) ──────
            logger.info(f"[SWITCH] Attente démarrage app avec internet : {target_url}")

            await asyncio.sleep(10)
            running, crash_logs = await self._check_container_running(container_name)
            if not running:
                return 1, "", f"Container crashé : {crash_logs[:1000]}", stack_type

            ready = await self._wait_for_app_via_backend_on_build_network(
                target_url, build_network, timeout=300
            )

            # ── Étape 5 : LLM retry si nécessaire ────────────
            if not ready and stack_type != "dockerfile":
                logger.warning(f"[SWITCH] App non prête — LLM retry sur réseau build")
                llm_ok, target_url, final_logs = await _llm_retry(
                    self, project_dir, container_name, image_name,
                    target_url, stack_type, project_name,
                    build_network=build_network,
                )
                if not llm_ok:
                    return 1, "", f"App non accessible après LLM retry.\n{final_logs[:2000]}", stack_type

            elif not ready:
                _, flo, fle = await self._run_command(
                    "docker", "logs", "--tail", "50", container_name, timeout=10,
                )
                return 1, "", (
                    f"App non accessible après 300s.\n{(flo + fle).strip()[:1000]}"
                ), stack_type

            # ── Étape 6+7 : Switch vers sandbox-net ──────────
            logger.info(f"[SWITCH] App prête — bascule vers sandbox-net (isolation)")
            isolated, sandbox_ip = await self._switch_to_sandbox(container_name, build_network)

            if not isolated:
                return 1, "", (
                    "ISOLATION ÉCHOUÉE — scan DAST annulé (contrainte C-05). "
                    "Le container a encore accès à internet après le switch réseau."
                ), stack_type

            # ── Étape 8 : URL sandbox pour ZAP ───────────────
            try:
                stack = _detect_stack(project_dir) if not dockerfile_native else {}
                port = port_override or stack.get("port", 3000)
            except Exception:
                port = port_override or 3000

            sandbox_url = f"http://{sandbox_ip}:{port}"
            logger.info(f"✅ [SWITCH] App isolée et prête pour ZAP : {sandbox_url}")
            return 0, sandbox_url, "", stack_type

        finally:
            # Toujours nettoyer le réseau build (même en cas d'erreur)
            if build_network:
                await self._cleanup_build_network(build_network)

    # ─────────────────────────────────────────────────────────
    # Healthcheck ZAP TCP (utilisé après switch réseau)
    # ─────────────────────────────────────────────────────────

    async def _wait_for_uploaded_app(self, target_url: str, timeout: int = 120) -> bool:
        """
        Healthcheck depuis ZAP après switch vers sandbox-net.

        v15.3 :
        - Le TCP prouve seulement que le port est ouvert.
        - On exige aussi une réponse HTTP via curl depuis le container ZAP.
        """
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or 80
        deadline = time.time() + timeout
        consecutive_tcp_ok = 0

        base = target_url.rstrip("/")
        health_urls = [
            base + "/",
            base + "/login",
            base + "/search",
            base + "/products",
            base + "/api/products",
        ]

        logger.info(f"Attente app via ZAP HTTP réel : {host}:{port}")

        while time.time() < deadline:
            # 1. TCP informatif
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
                    consecutive_tcp_ok += 1
                    logger.info(f"Port {port} ouvert depuis ZAP ({consecutive_tcp_ok})")
                else:
                    consecutive_tcp_ok = 0
                    logger.info(f"TCP depuis ZAP non prêt : {err or out}")

            except Exception as e:
                consecutive_tcp_ok = 0
                logger.info(f"Attente ZAP TCP... {e}")

            # 2. HTTP réel depuis ZAP
            for url in health_urls:
                try:
                    code_http, out_http, err_http = await self._run_command(
                        "docker", "exec", "-u", "root", "cybersentinel_zap",
                        "curl",
                        "-k",
                        "-sS",
                        "-L",
                        "--max-time", "10",
                        "-o", "/tmp/cs_http_body",
                        "-w", "%{http_code} %{size_download}",
                        url,
                        timeout=20,
                    )

                    if code_http == 0:
                        parts = out_http.strip().split()
                        http_code = int(parts[0]) if parts and parts[0].isdigit() else 0
                        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

                        if 0 < http_code < 500:
                            logger.info(
                                f"✅ App HTTP valide depuis ZAP : "
                                f"{url} code={http_code} size={size}"
                            )
                            try:
                                async with httpx.AsyncClient() as client:
                                    await client.get(
                                        f"{ZAP_HOST}/JSON/core/action/accessUrl/",
                                        params={"url": url, "followRedirects": "true"},
                                        timeout=10,
                                    )
                            except Exception as e:
                                logger.warning(f"ZAP accessUrl non bloquant : {e}")
                            return True

                        logger.info(
                            f"HTTP depuis ZAP non valide : {url} "
                            f"code={http_code} size={size}"
                        )
                    else:
                        logger.info(f"HTTP depuis ZAP échoué : {url} | {err_http or out_http}")

                except Exception as e:
                    logger.info(f"HTTP ZAP exception sur {url} : {e}")

            await asyncio.sleep(5)

        logger.error(f"❌ App non accessible HTTP depuis ZAP après {timeout}s")
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
                return False, (logs_out + "\n" + logs_err).strip()[:2000]
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

    # Conservé pour compatibilité interne (utilisé par _llm_retry v14 legacy)
    async def _build_and_run(
        self,
        project_dir: Path,
        image_name: str,
        container_name: str,
    ) -> Tuple[int, str, str, str]:
        """Lance directement sur sandbox-net (mode WebGoat/DVWA)."""
        try:
            stack = _detect_stack(project_dir)
        except ValueError as e:
            return 1, "", str(e), ""

        real_project_dir = Path(stack.get("project_dir", str(project_dir)))
        dockerfile_path = real_project_dir / "Dockerfile.cybersentinel"
        dockerfile_path.write_text(stack["dockerfile"], encoding="utf-8")

        build_code, build_out, build_err = await self._run_command(
            "docker", "build", "--no-cache",
            "-f", str(dockerfile_path), "-t", image_name, str(real_project_dir),
            timeout=900, env={"DOCKER_BUILDKIT": "0"},
        )
        if build_code != 0:
            return build_code, "", f"Build échoué:\n{build_err[-5000:]}", stack["type"]

        env_args = []
        for e in stack.get("env", []):
            env_args += ["--env", e]

        run_code, run_out, run_err = await self._run_command(
            "docker", "run", "-d",
            "--name", container_name,
            "--network", "cybersentinel_sandbox-net",
            "--restart", "no",
            *env_args, image_name, timeout=120,
        )
        if run_code != 0:
            return run_code, "", f"Lancement échoué : {(run_err or run_out)[:2000]}", stack["type"]

        try:
            target_url = await self._target_url_from_container(container_name, stack["port"])
        except Exception as e:
            target_url = f"http://{container_name}:{stack['port']}"
        return 0, target_url, "", stack["type"]

    # ─────────────────────────────────────────────────────────
    # Mode 1 — cible prédéfinie WebGoat / DVWA
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

        await self._reset_zap_session(session_id)

        results = {
            "session_id": session_id,
            "target": resolved_name,
            "target_url": resolved_url,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "phases": {},
            "findings": [],
            "pcap_path": None,
            "total_vulns": 0,
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

        return results

    # ─────────────────────────────────────────────────────────
    # Mode 2 — Upload ZIP — v15 Network Switch
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

            # Extraction ZIP
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
                return {"error": f"ZIP invalide : {e}"}

            children    = list(extract_dir.iterdir())
            project_dir = children[0] if (len(children) == 1 and children[0].is_dir()) else extract_dir
            image_name     = f"cybersentinel-upload-{project_slug}:{unique_id}"
            container_name = f"cybersentinel_target_{unique_id}"

            # v15 — Deploy avec network switch
            code, sandbox_url, error_msg, stack_type = await self._deploy_with_network_switch(
                project_dir, image_name, container_name, unique_id,
                project_name=original_name,
            )

            if code != 0:
                return {
                    "error": f"Déploiement échoué pour '{original_name}'",
                    "details": error_msg,
                }

            # Vérifier accessible depuis ZAP
            ready = await self._wait_for_uploaded_app(sandbox_url, timeout=120)
            if not ready:
                return {"error": f"App '{original_name}' non accessible depuis ZAP après switch réseau."}

            result = await self.run_session(
                target="custom", target_url=sandbox_url,
                deploy_target=False, internal_target=True,
            )
            result["uploaded_project"] = {
                "filename": original_name, "container_name": container_name,
                "image_name": image_name, "target_url": sandbox_url,
                "stack": stack_type, "network_switch": True,
            }
            return result

        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            logger.exception(f"run_uploaded_project erreur: {e}")
            return {"error": str(e)}
        finally:
            if os.getenv("DAST_KEEP_FAILED_CONTAINERS", "false").lower() == "true":
                logger.warning(
                    f"[DEBUG] Container/upload conservé : {container_name} | {extract_dir}"
                )
            else:
                await self._cleanup_uploaded_target(container_name, image_name)
                if extract_dir:
                    shutil.rmtree(extract_dir, ignore_errors=True)
            try:
                Path(zip_path).unlink(missing_ok=True)
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────
    # Mode 3 — Repo GitHub — v15 Network Switch
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

            # Clone du repo
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
            dockerfile_native = dockerfile_path.exists()

            # Build image
            if dockerfile_native:
                logger.info("Dockerfile natif trouvé — build direct")
                build_code, build_out, build_err = await self._run_command(
                    "docker", "build", "--no-cache", "-t", image_name, str(project_dir),
                    timeout=900, env={"DOCKER_BUILDKIT": "0"},
                )
                if build_code != 0:
                    return {"error": f"Build échoué:\nSTDOUT:\n{build_out[-8000:]}\nSTDERR:\n{build_err[-8000:]}"}
                port = self._detect_port_from_dockerfile(dockerfile_path)
            else:
                port = None  # détecté dans _deploy_with_network_switch

            # v15 — Deploy avec network switch
            code, sandbox_url, error_msg, stack_type = await self._deploy_with_network_switch(
                project_dir, image_name, container_name, unique_id,
                dockerfile_native=dockerfile_native,
                port_override=port,
                project_name=project_name,
            )

            if code != 0:
                return {"error": f"Déploiement échoué pour '{project_name}'", "details": error_msg}

            # Vérifier accessible depuis ZAP
            ready = await self._wait_for_uploaded_app(sandbox_url, timeout=120)
            if not ready:
                return {"error": f"App '{project_name}' non accessible depuis ZAP après switch réseau."}

            result = await self.run_session(
                target="custom", target_url=sandbox_url,
                deploy_target=False, internal_target=True,
            )
            result["git_project"] = {
                "repo_url": repo_url, "branch": branch, "project_name": project_name,
                "stack": stack_type,
                "dockerfile": "native" if dockerfile_native else "auto",
                "container_name": container_name, "image_name": image_name,
                "target_url": sandbox_url, "network_switch": True,
            }
            return result

        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            logger.exception(f"run_git_project erreur: {e}")
            return {"error": str(e)}
        finally:
            if os.getenv("DAST_KEEP_FAILED_CONTAINERS", "false").lower() == "true":
                logger.warning(f"[DEBUG] Container conservé : {container_name} | {clone_dir}")
            else:
                await self._cleanup_uploaded_target(container_name, image_name)
                shutil.rmtree(clone_dir, ignore_errors=True)

    # ─────────────────────────────────────────────────────────
    # Mode 4 — Image Docker pré-buildée — v15 Network Switch
    # ─────────────────────────────────────────────────────────

    async def run_docker_image(
        self,
        image_name: str,
        internal_port: int = 3000,
        healthcheck_path: str = "/",
        scan_profile: str = "baseline",
    ) -> dict:
        container_name = f"cybersentinel_target_{uuid.uuid4().hex[:8]}"
        unique_id      = uuid.uuid4().hex[:8]
        build_network  = None

        try:
            if self._session_active:
                return {"error": "Session DAST déjà active", "session_id": self._current_session_id}

            code, out, _ = await self._run_command("docker", "image", "inspect", image_name, timeout=10)
            if code != 0:
                return {"error": f"Image '{image_name}' introuvable."}

            deploy_info = await self._ensure_zap_only()
            if not deploy_info.get("success"):
                return {"error": "ZAP non disponible", "details": deploy_info}

            # v15 — Lancer sur réseau build d'abord
            build_network = await self._create_build_network(unique_id)

            run_code, run_out, run_err = await self._run_command(
                "docker", "run", "-d",
                "--name", container_name,
                "--network", build_network,
                "--restart", "no",
                "--memory", "512m", "--cpus", "1",
                "--pids-limit", "256", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                image_name, timeout=60,
            )
            if run_code != 0:
                return {"error": f"Lancement container échoué : {(run_err or run_out)[:500]}"}

            try:
                ip = await self._resolve_container_ip(container_name)
                target_url = f"http://{ip}:{internal_port}"
            except Exception:
                target_url = f"http://{container_name}:{internal_port}"

            await asyncio.sleep(5)
            running, crash_logs = await self._check_container_running(container_name)
            if not running:
                return {"error": f"Image '{image_name}' crashée.", "container_logs": crash_logs}

            # Attendre prêt avec internet
            ready = await self._wait_for_app_via_backend_on_build_network(
                target_url, build_network, timeout=120
            )
            if not ready:
                return {"error": f"Application non accessible après 120s sur le port {internal_port}"}

            # Switch vers sandbox-net
            isolated, sandbox_ip = await self._switch_to_sandbox(container_name, build_network)
            if not isolated:
                return {"error": "ISOLATION ÉCHOUÉE — scan annulé (contrainte C-05)"}

            sandbox_url = f"http://{sandbox_ip}:{internal_port}"

            ready_zap = await self._wait_for_uploaded_app(sandbox_url, timeout=60)
            if not ready_zap:
                return {"error": "App non accessible depuis ZAP après switch réseau."}

            result = await self.run_session(
                target="custom", target_url=sandbox_url,
                deploy_target=False, internal_target=True,
            )
            result["docker_image_scan"] = {
                "image_name": image_name, "container_name": container_name,
                "internal_port": internal_port, "network_switch": True,
            }
            return result

        except Exception as e:
            logger.exception(f"run_docker_image erreur: {e}")
            return {"error": str(e)}
        finally:
            if build_network:
                await self._cleanup_build_network(build_network)
            await self._cleanup_uploaded_target(container_name, None)

    async def _zap_proxy_browse(self, target_url: str) -> None:
        """
        Force ZAP à voir la cible dans son Scan Tree via son proxy HTTP.

        accessUrl retourne parfois 500 avec certaines apps aiohttp/DVPWA.
        En passant par curl -x http://127.0.0.1:8090 depuis le container ZAP,
        on force réellement du trafic HTTP à travers le proxy ZAP.
        """
        paths = [
            "",
            "/",
            "/robots.txt",
            "/sitemap.xml",

            "/login",
            "/login/",
            "/register",
            "/users",
            "/products",
            "/search",

            # URLs avec paramètres pour donner une surface d'attaque à ZAP
            "/search?q=test",
            "/search?q=admin",
            "/search?q=%27",
            "/products?id=1",
            "/products?id=1%27",
            "/users?id=1",
            "/users?id=1%27",

            # APIs fréquentes dans DVPWA / apps vulnérables
            "/api/products",
            "/api/products?id=1",
            "/api/products?id=1%27",
            "/api/users",
            "/api/users?id=1",
            "/api/users?id=1%27",
            "/api/search?q=test",
            "/api/search?q=%27",
        ]

        base = target_url.rstrip("/")

        logger.info("[DAST] Warmup ZAP proxy browse : %s", target_url)

        for path in paths:
            url = base + path

            try:
                code, out, err = await self._run_command(
                    "docker", "exec", "-u", "root", "cybersentinel_zap",
                    "curl",
                    "-k",
                    "-sS",
                    "-L",
                    "--max-time", "10",
                    "-x", "http://127.0.0.1:8090",
                    url,
                    timeout=20,
                )

                logger.info(
                    "[DAST] Proxy browse %s → code=%s",
                    url,
                    code,
                )

            except Exception as e:
                logger.warning("[DAST] Proxy browse ignoré %s : %s", url, e)

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
                    "isolation_ok": isolation_ok, "zap_ready": zap_ready}
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
        """
        Phase 3 — Active scan ZAP.

        Correction DVPWA :
        - accessUrl peut retourner 500 même si l'app est accessible.
        - ascan/action/scan peut retourner 400 si l'URL n'est pas bien dans le site tree.
        - On force l'exploration des URLs du spider avant de relancer l'active scan.
        - Si l'active scan échoue encore, on continue quand même pour collecter les alertes passives.
        """
        logger.info(f"Phase 3 — Active scan {target_url}")
        await self._zap_proxy_browse(target_url)
        await asyncio.sleep(3)

        try:
            async with httpx.AsyncClient(timeout=180) as client:
                # 1. Spider renforcé pour peupler le site tree ZAP
                try:
                    spider_resp = await client.get(
                        f"{ZAP_HOST}/JSON/spider/action/scan/",
                        params={
                            "url": target_url,
                            "maxChildren": "50",
                            "recurse": "true",
                        },
                    )
                    spider_data = spider_resp.json()
                    spider_id = spider_data.get("scan")

                    if spider_id is not None:
                        for _ in range(60):
                            status_resp = await client.get(
                                f"{ZAP_HOST}/JSON/spider/view/status/",
                                params={"scanId": spider_id},
                            )
                            status = int(status_resp.json().get("status", 0))
                            if status >= 100:
                                break
                            await asyncio.sleep(2)

                        try:
                            results_resp = await client.get(
                                f"{ZAP_HOST}/JSON/spider/view/results/",
                                params={"scanId": spider_id},
                            )
                            urls = results_resp.json().get("results", []) or []
                            logger.info(f"[DAST] Spider URLs découvertes : {len(urls)}")

                            # Forcer ZAP à accéder à quelques URLs découvertes
                            for u in urls[:30]:
                                try:
                                    await client.get(
                                        f"{ZAP_HOST}/JSON/core/action/accessUrl/",
                                        params={
                                            "url": u,
                                            "followRedirects": "true",
                                        },
                                        timeout=10,
                                    )
                                except Exception:
                                    pass

                        except Exception as e:
                            logger.warning(f"[DAST] Lecture résultats spider ignorée : {e}")

                except Exception as e:
                    logger.warning(f"[DAST] Spider renforcé ignoré : {e}")

                # 2. accessUrl sur l'URL principale, non bloquant
                try:
                    access_resp = await client.get(
                        f"{ZAP_HOST}/JSON/core/action/accessUrl/",
                        params={
                            "url": target_url,
                            "followRedirects": "true",
                        },
                        timeout=20,
                    )
                    if access_resp.status_code >= 400:
                        logger.warning(
                            f"[DAST] accessUrl non OK mais non bloquant : "
                            f"{access_resp.status_code} {access_resp.text[:300]}"
                        )
                except Exception as e:
                    logger.warning(f"[DAST] accessUrl échoué mais non bloquant : {e}")

                # 3. Activer les scanners ZAP de manière plus agressive
                try:
                    await client.get(
                        f"{ZAP_HOST}/JSON/ascan/action/enableAllScanners/",
                        timeout=20,
                    )
                    await client.get(
                        f"{ZAP_HOST}/JSON/ascan/action/setOptionAttackStrength/",
                        params={"String": "HIGH"},
                        timeout=20,
                    )
                    await client.get(
                        f"{ZAP_HOST}/JSON/ascan/action/setOptionAlertThreshold/",
                        params={"String": "LOW"},
                        timeout=20,
                    )
                    logger.info(
                        "[DAST] ZAP scanners activés : attackStrength=HIGH, alertThreshold=LOW"
                    )
                except Exception as e:
                    logger.warning(f"[DAST] Configuration scanners ZAP ignorée : {e}")

                # 4. Active scan
                scan_resp = await client.get(
                    f"{ZAP_HOST}/JSON/ascan/action/scan/",
                    params={
                        "url": target_url,
                        "recurse": "true",
                    },
                    timeout=30,
                )

                if scan_resp.status_code != 200:
                    logger.warning(
                        f"[DAST] Active scan refusé par ZAP "
                        f"HTTP {scan_resp.status_code} : {scan_resp.text[:500]}"
                    )
                    return {
                        "success": True,
                        "active_scan_started": False,
                        "warning": "Active scan refusé par ZAP, collecte passive maintenue",
                        "http_status": scan_resp.status_code,
                    }

                data = scan_resp.json()
                scan_id = data.get("scan")

                if scan_id is None:
                    return {
                        "success": True,
                        "active_scan_started": False,
                        "warning": f"Réponse ZAP sans scan id : {data}",
                    }

                logger.info(f"[DAST] Active scan lancé scanId={scan_id}")

                # 4. Attendre fin active scan
                last_status = -1
                for _ in range(180):
                    status_resp = await client.get(
                        f"{ZAP_HOST}/JSON/ascan/view/status/",
                        params={"scanId": scan_id},
                        timeout=20,
                    )
                    status = int(status_resp.json().get("status", 0))

                    if status != last_status:
                        logger.info(f"Active scan progress: {status}%")
                        last_status = status

                    if status >= 100:
                        break

                    await asyncio.sleep(5)

                return {
                    "success": True,
                    "active_scan_started": True,
                    "scan_id": scan_id,
                    "status": last_status,
                }

        except Exception as e:
            logger.exception(f"Phase active scan échouée : {e}")
            return {
                "success": True,
                "active_scan_started": False,
                "warning": str(e),
            }

    async def _start_pcap_capture(self, session_id: str) -> Optional[Path]:
        backend_pcap_storage   = Path("/shared/dast_captures")
        container_pcap_storage = "/shared/dast_captures"

        backend_pcap_storage.mkdir(parents=True, exist_ok=True)

        host_path      = backend_pcap_storage / f"{session_id}.pcap"
        container_path = f"{container_pcap_storage}/{session_id}.pcap"

        check_code, _, check_err = await self._run_command(
            "docker", "exec", "-u", "root", "cybersentinel_zap",
            "test", "-d", container_pcap_storage, timeout=5,
        )
        if check_code != 0:
            logger.warning("Volume PCAP non accessible dans ZAP : %s", check_err)
            return None

        td_code, _, td_err = await self._run_command(
            "docker", "exec", "-u", "root", "cybersentinel_zap",
            "which", "tcpdump", timeout=5,
        )
        if td_code != 0:
            logger.warning("tcpdump absent dans cybersentinel_zap : %s", td_err)
            return None

        await self._run_command(
            "docker", "exec", "-u", "root", "cybersentinel_zap",
            "rm", "-f", container_path, timeout=5,
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", "-u", "root", "cybersentinel_zap",
                "timeout", "180", "tcpdump",
                "-i", "any", "-w", container_path, "-s", "0", "not", "arp",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=190)
            except asyncio.TimeoutError:
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

            check_file, _, _ = await self._run_command(
                "docker", "exec", "-u", "root", "cybersentinel_zap",
                "test", "-s", container_path, timeout=5,
            )
            if check_file != 0:
                return None

            await self._run_command(
                "docker", "exec", "-u", "root", "cybersentinel_zap",
                "chmod", "644", container_path, timeout=5,
            )

            if host_path.exists() and host_path.stat().st_size > 0:
                logger.info("PCAP créé : %s | %.1f KB", host_path, host_path.stat().st_size / 1024)
                return host_path
            return None

        except Exception as e:
            logger.exception("Erreur capture PCAP session=%s : %s", session_id, e)
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
                if not alerts:
                    logger.warning(
                        "[DAST] Aucun alert avec baseurl=%s — fallback global ZAP alerts",
                        target_url,
                    )

                    all_alerts = (await client.get(
                        f"{ZAP_HOST}/JSON/alert/view/alerts/",
                    )).json().get("alerts", [])

                    parsed = urlparse(target_url)
                    host = parsed.hostname or ""

                    alerts = [
                        a for a in all_alerts
                        if host in str(a.get("url", ""))
                        or target_url.rstrip("/") in str(a.get("url", ""))
                    ]

                    logger.info(
                        "[DAST] Alertes ZAP filtrées pour %s : %s/%s",
                        host,
                        len(alerts),
                        len(all_alerts),
                    )

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
        """
        Phase 6 — Teardown sandbox.

        On garde ZAP actif pour éviter de le redémarrer à chaque scan.
        Les containers uploadés sont nettoyés ailleurs selon
        DAST_KEEP_FAILED_CONTAINERS.
        """
        logger.info("Phase 6 — Teardown sandbox")

        try:
            # On ne supprime pas ZAP, car il est réutilisé entre les scans.
            # On ne fait pas docker compose down sinon on casse sandbox/mgmt.
            logger.info("✅ Teardown terminé — ZAP conservé")
            return {
                "success": True,
                "zap_kept": True,
                "details": "ZAP conservé pour les prochains scans",
            }

        except Exception as e:
            logger.warning(f"Teardown DAST échoué : {e}")
            return {
                "success": False,
                "error": str(e),
            }
        
    async def _reset_zap_session(self, session_id: str) -> None:
        """
        Nettoie le scan tree ZAP avant chaque scan.

        Sans ça, ZAP garde les anciennes cibles :
        172.20.0.9, 172.20.0.17, etc.
        Puis la collecte récupère des alertes anciennes au lieu
        de la cible courante.
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{ZAP_HOST}/JSON/core/action/newSession/",
                    params={
                        "name": session_id,
                        "overwrite": "true",
                    },
                )

                if resp.status_code == 200:
                    logger.info(f"[DAST] Session ZAP réinitialisée : {session_id}")
                else:
                    logger.warning(
                        f"[DAST] Reset session ZAP non OK : "
                        f"{resp.status_code} {resp.text[:300]}"
                    )

        except Exception as e:
            logger.warning(f"[DAST] Reset session ZAP ignoré : {e}")

    async def _process_findings(self, findings: list, session_id: str) -> None:
        """
        Persiste les résultats DAST ZAP dans sast_findings.

        Fix :
        - une erreur sur un finding ne bloque plus toute la transaction ;
        - rollback après chaque erreur ;
        - insertion commitée finding par finding ;
        - normalisation des valeurs avant insertion.
        """
        from sqlalchemy import select
        from app.models.sast_finding import SASTFinding

        if not findings:
            logger.info("[DAST] Aucun finding ZAP à persister | session=%s", session_id)
            return

        inserted = 0
        confirmed_sast = 0
        skipped = 0
        failed = 0

        for finding in findings:
            async with AsyncSessionLocal() as db:
                try:
                    zap_alert = (
                        finding.get("zap_alert")
                        or finding.get("alert_name")
                        or finding.get("title")
                        or "ZAP Finding"
                    )

                    cwe = finding.get("cwe")
                    url = finding.get("url") or finding.get("file_path") or ""
                    method = finding.get("method") or "GET"
                    param = finding.get("param") or ""
                    evidence = finding.get("evidence") or ""
                    description = finding.get("description") or ""
                    solution = finding.get("solution") or ""
                    severity = finding.get("severity") or "MEDIUM"

                    if hasattr(severity, "value"):
                        severity = severity.value

                    severity = str(severity).upper()

                    if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                        if severity in ["CRITIQUE"]:
                            severity = "CRITICAL"
                        elif severity in ["ELEVE", "ÉLEVÉ"]:
                            severity = "HIGH"
                        elif severity in ["MOYEN"]:
                            severity = "MEDIUM"
                        elif severity in ["FAIBLE"]:
                            severity = "LOW"
                        else:
                            severity = "MEDIUM"

                    existing = await db.execute(
                        select(SASTFinding)
                        .where(SASTFinding.tool == "dast_zap")
                        .where(SASTFinding.scan_id == session_id)
                        .where(SASTFinding.title == zap_alert)
                        .where(SASTFinding.file_path == url)
                        .limit(1)
                    )

                    if existing.scalar_one_or_none():
                        skipped += 1
                        await db.rollback()
                        continue

                    technique_id = None
                    technique_name = None
                    tactic = None
                    apt_groups = []

                    try:
                        technique_id = self.mitre_engine.resolve_ml_dast(zap_alert)

                        if technique_id:
                            mitre_data = await self.mitre_engine.enrich_by_technique_id(
                                technique_id
                            )
                            technique_name = mitre_data.get("technique_name")
                            tactic = mitre_data.get("tactic")
                            apt_groups = mitre_data.get("apt_groups", []) or []

                    except Exception as e:
                        logger.warning("[DAST] MITRE enrich ignoré : %s", e)

                    dast_finding = SASTFinding(
                        tool="dast_zap",
                        severity=severity,

                        file_path=url[:1000] if url else "",
                        line_number=None,
                        line_start=None,
                        line_end=None,
                        col_start=None,
                        col_end=None,

                        code_snippet=f"{method} {url}".strip()[:4000],
                        vulnerable_line=f"Parameter: {param}"[:1000] if param else None,

                        rule_id=zap_alert[:500],
                        cwe=cwe,
                        cve=None,
                        cvss_score=None,

                        title=zap_alert[:500],
                        description=description[:4000] if description else "",
                        message=(evidence or description or zap_alert)[:4000],

                        fix_suggestion=solution[:4000] if solution else "",
                        fix_code=None,

                        references=[],
                        category="DAST",

                        package_name=None,
                        package_version=None,
                        fix_version=None,

                        secret_type=None,
                        secret_preview=None,

                        technique_id=technique_id,
                        technique_name=technique_name,
                        tactic=tactic,

                        dast_confirmed=1,

                        repo_name=finding.get("project_name") or "DAST_SCAN",
                        commit_sha=None,
                        pr_number=None,
                        scan_id=session_id,

                        sarif_raw={
                            "source": "OWASP ZAP",
                            "session_id": session_id,
                            "alert_name": zap_alert,
                            "risk": finding.get("risk"),
                            "confidence": finding.get("confidence"),
                            "url": url,
                            "method": method,
                            "param": param,
                            "attack": finding.get("attack"),
                            "evidence": evidence,
                            "description": description,
                            "solution": solution,
                            "proof_path": finding.get("proof_path"),
                            "cwe_id": finding.get("cwe_id"),
                            "apt_groups": apt_groups,
                            "raw": finding,
                        },
                    )

                    db.add(dast_finding)
                    await db.commit()
                    inserted += 1

                    if cwe:
                        async with AsyncSessionLocal() as db2:
                            try:
                                sast_result = await db2.execute(
                                    select(SASTFinding)
                                    .where(SASTFinding.cwe == cwe)
                                    .where(SASTFinding.tool != "dast_zap")
                                    .where(SASTFinding.dast_confirmed == 0)
                                    .limit(1)
                                )

                                sast_finding = sast_result.scalar_one_or_none()

                                if sast_finding:
                                    sast_finding.dast_confirmed = 1
                                    await db2.commit()
                                    confirmed_sast += 1

                            except Exception as e:
                                await db2.rollback()
                                logger.warning(
                                    "[DAST] Confirmation SAST ignorée : %s",
                                    e,
                                )

                except Exception as e:
                    failed += 1
                    await db.rollback()
                    logger.exception(
                        "[DAST] Erreur insertion finding ZAP ignorée | title=%s | url=%s | error=%s",
                        finding.get("title") or finding.get("zap_alert"),
                        finding.get("url"),
                        e,
                    )

        logger.info(
            "[DAST] Findings persistés | session=%s | inserted=%s | confirmed_sast=%s | skipped=%s | failed=%s",
            session_id,
            inserted,
            confirmed_sast,
            skipped,
            failed,
        )

    def get_status(self) -> dict:
        return {"active": self._session_active, "session_id": self._current_session_id}