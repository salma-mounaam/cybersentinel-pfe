# ============================================================
# M5 — LLM Helper universel — Auto-réparation DAST
# Ollama local (llama3.1:8b) — fallback après échec healthcheck
# Fonctionne pour toutes les stacks : Python, Node, PHP, Java
# Fix v2 : correction stack mismatch (LLM génère npm start pour Python)
#          post-validation et correction automatique de la commande exec
#          prompt plus directif avec exemples concrets
# ============================================================

import httpx
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

OLLAMA_HOST  = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
OLLAMA_MODEL = "llama3.1:8b"


def validate_generated_script(script: str) -> bool:
    """Valide la sécurité du script généré par le LLM."""
    forbidden = [
        "rm -rf /", "mkfs", "dd if=",
        "curl http", "wget http",
        "nc ", "netcat", "chmod 777 /",
        "docker ", "/var/run/docker.sock",
        "systemctl",
    ]
    if not script.strip().startswith("#!/bin/bash"):
        return False
    if "exec " not in script:
        return False
    return not any(x in script.lower() for x in forbidden)


def _fix_exec_command(script: str, stack: str, entry: str, port: int) -> str:
    """
    FIX v2 : corrige la commande exec si le LLM a généré la mauvaise.
    Ex : LLM génère 'exec npm start' pour une app Python → on corrige.
    """
    lines = script.strip().split("\n")

    # Déterminer la bonne commande selon la stack
    if stack in ("flask", "aiohttp"):
        correct_exec = f"exec python {entry}"
    elif stack == "fastapi":
        module = entry.replace(".py", "") + ":app"
        correct_exec = f"exec uvicorn {module} --host 0.0.0.0 --port {port}"
    elif stack == "node":
        correct_exec = "exec npm start"
    elif stack == "springboot":
        correct_exec = "exec java -jar app.jar"
    elif stack == "php":
        correct_exec = "exec apache2-foreground"
    else:
        correct_exec = f"exec python {entry}"

    # Vérifier si la dernière ligne exec est correcte
    wrong_execs = {
        "flask":      ["exec npm start", "exec java -jar", "exec apache2"],
        "aiohttp":    ["exec npm start", "exec java -jar", "exec apache2"],
        "fastapi":    ["exec npm start", "exec java -jar", "exec apache2"],
        "node":       ["exec python ", "exec java -jar", "exec apache2"],
        "springboot": ["exec python ", "exec npm start", "exec apache2"],
        "php":        ["exec python ", "exec npm start", "exec java -jar"],
    }

    wrong_for_stack = wrong_execs.get(stack, [])

    # Chercher la dernière ligne exec et la corriger si nécessaire
    for i in range(len(lines) - 1, -1, -1):
        stripped = lines[i].strip()
        if stripped.startswith("exec "):
            is_wrong = any(wrong in stripped for wrong in wrong_for_stack)
            if is_wrong:
                logger.warning(f"[LLM DAST] Stack mismatch détecté: '{stripped}' → corrigé en '{correct_exec}'")
                lines[i] = correct_exec
            break

    return "\n".join(lines)


async def generate_start_script(
    project_dir: Path,
    current_script: str,
    container_logs: str,
    analysis: dict,
) -> str | None:
    """
    Appelle Ollama pour générer un start.sh corrigé.
    Fallback universel après échec healthcheck — toutes stacks.
    """
    # Collecter les fichiers clés du projet
    file_contents = {}
    for fname in [
        "requirements.txt", "package.json", "pom.xml",
        "docker-compose.yml", "docker-compose.yaml",
        "config/dev.yaml", "config/app.yaml", "config/config.yaml",
        ".env.example", ".env.sample", "README.md", "README.rst",
    ]:
        fpath = project_dir / fname
        if fpath.exists():
            try:
                file_contents[fname] = fpath.read_text(errors="ignore")[:1500]
            except Exception:
                pass

    # Migrations SQL
    migrations = []
    for pattern in ["migrations/*.sql", "db/*.sql", "sql/*.sql", "database/*.sql"]:
        migrations += sorted([f.name for f in project_dir.glob(pattern)])

    files_str = "\n\n".join(
        f"=== {name} ===\n{content}"
        for name, content in file_contents.items()
    )

    entry = analysis.get("entry") or "run.py"
    stack = analysis.get("stack", "unknown")
    port  = analysis.get("port", 3000)

    # Commande de démarrage exacte selon la stack
    if stack == "node":
        start_cmd = "exec npm start"
        stack_desc = "Node.js application"
    elif stack == "fastapi":
        module = entry.replace(".py", "") + ":app"
        start_cmd = f"exec uvicorn {module} --host 0.0.0.0 --port {port}"
        stack_desc = "Python FastAPI application"
    elif stack == "springboot":
        start_cmd = "exec java -jar app.jar"
        stack_desc = "Java Spring Boot application"
    elif stack == "php":
        start_cmd = "exec apache2-foreground"
        stack_desc = "PHP application"
    elif stack == "aiohttp":
        start_cmd = f"exec python {entry}"
        stack_desc = "Python aiohttp application"
    else:
        start_cmd = f"exec python {entry}"
        stack_desc = "Python Flask application"

    # Exemple concret pour DVPWA/aiohttp avec postgres+redis
    example = ""
    if stack == "aiohttp" and analysis.get("needs_postgres") and analysis.get("needs_redis"):
        example = f"""
EXAMPLE of correct script for this type of project:
#!/bin/bash
set -e
redis-server --daemonize yes --loglevel warning
sleep 1
service postgresql start
echo 'Waiting for PostgreSQL...'
for i in $(seq 1 20); do pg_isready -q && break || sleep 2; done
su postgres -c "psql -c \\"ALTER USER postgres WITH PASSWORD 'postgres';\\" 2>/dev/null" || true
su postgres -c "createdb sqli 2>/dev/null" || true
for sql_file in $(find /app/migrations -name '*.sql' 2>/dev/null | sort); do
  su postgres -c "psql -d sqli -f $sql_file 2>/dev/null" || true
done
find /app -name '*.yaml' -exec grep -l 'host: postgres' {{}} \\; | while read f; do
  sed -i 's/host: postgres/host: 127.0.0.1/g' "$f"
  sed -i 's/host: redis/host: 127.0.0.1/g' "$f"
done
echo 'Starting application...'
{start_cmd}
"""

    prompt = f"""You are a DevOps expert fixing a Docker container startup script.

THIS IS A {stack_desc.upper()}. The final command MUST be: {start_cmd}
DO NOT use npm, java, or any other runtime. Only use: {start_cmd}

PROJECT DETAILS:
- Stack: {stack} ({stack_desc})
- Port: {port}
- Entry file: {entry}
- Needs Redis: {analysis.get('needs_redis', False)}
- Needs PostgreSQL: {analysis.get('needs_postgres', False)}
- Needs MongoDB: {analysis.get('needs_mongo', False)}
- Needs MySQL: {analysis.get('needs_mysql', False)}
- SQL migrations available: {', '.join(migrations) if migrations else 'none'}
{example}
CURRENT FAILED SCRIPT:
{current_script}

ERROR LOGS FROM CONTAINER:
{container_logs[-1500:]}

PROJECT KEY FILES:
{files_str[:2000]}

STRICT RULES:
1. First line: #!/bin/bash
2. Second line: set -e
3. Start Redis if needed: redis-server --daemonize yes --loglevel warning
4. Start PostgreSQL if needed: service postgresql start
5. Wait for PostgreSQL: for i in $(seq 1 20); do pg_isready -q && break || sleep 2; done
6. Create needed DB users and databases
7. Run SQL migrations: su postgres -c "psql -d <dbname> -f <filepath>"
8. Patch YAML configs: sed -i 's/host: postgres/host: 127.0.0.1/g'
9. LAST LINE MUST BE EXACTLY: {start_cmd}
10. Output ONLY the bash script, nothing else

Write the corrected bash script now:"""

    try:
        logger.info(f"[LLM DAST] Appel Ollama — stack={stack} entry={entry} port={port}")

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.05, "num_predict": 1500},
                }
            )

            if resp.status_code != 200:
                logger.error(f"[LLM DAST] Ollama erreur {resp.status_code}")
                return None

            script = resp.json().get("response", "").strip()

            # Nettoyer les backticks markdown
            if "```" in script:
                lines = script.split("\n")
                script = "\n".join(
                    l for l in lines if not l.strip().startswith("```")
                ).strip()

            # Extraire à partir de #!/bin/bash
            if "#!/bin/bash" in script:
                script = script[script.find("#!/bin/bash"):]

            # FIX v2 : corriger automatiquement la commande exec si mauvaise stack
            script = _fix_exec_command(script, stack, entry, port)

            # S'assurer que la dernière commande exec est correcte
            # (au cas où le LLM n'a pas mis de commande exec du tout)
            lines = script.strip().split("\n")
            last_exec = next((l for l in reversed(lines) if l.strip().startswith("exec ")), None)
            if not last_exec:
                logger.warning("[LLM DAST] Aucune commande exec trouvée — ajout automatique")
                script = script.rstrip() + f"\n{start_cmd}\n"

            if not validate_generated_script(script):
                logger.warning("[LLM DAST] Script refusé par validation sécurité")
                return None

            logger.info(f"✅ [LLM DAST] Script généré ({len(script)} chars)")
            logger.info(f"[LLM DAST] Dernière commande: {start_cmd}")
            return script

    except Exception as e:
        logger.error(f"[LLM DAST] Erreur: {e}")
        return None