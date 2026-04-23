# ============================================================
# M5 — Service DAST Sandbox Isolée — v3 (fix wait réseau)
# ============================================================

import asyncio
import json
import logging
import os
import shutil
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

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
    "dvwa":    "http://cybersentinel_dvwa:80",
}
TARGET_SERVICES = {"webgoat": "webgoat", "dvwa": "dvwa"}

HOST_PCAP_STORAGE      = Path("data/dast_captures")
CONTAINER_PCAP_STORAGE = "/shared/dast_captures"


# ── Helpers globaux ───────────────────────────────────────────

def _is_valid_target_url(url: str) -> bool:
    if not url:
        return False
    v = url.strip().lower()
    if not (v.startswith("http://") or v.startswith("https://")):
        return False
    for b in ["127.0.0.1", "localhost", "0.0.0.0"]:
        if b in v:
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
    """Extraction protégée contre Zip Slip."""
    dest_str = str(dest_dir.resolve())
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = dest_dir / member.filename
            if not str(member_path.resolve()).startswith(dest_str):
                raise ValueError(f"Archive ZIP dangereuse : {member.filename}")
        zf.extractall(dest_dir)


def _detect_stack(project_dir: Path) -> dict:
    project_dir = Path(project_dir)

    # Spring Boot
    if (project_dir / "pom.xml").exists():
        return {
            "type": "springboot", "port": 8080,
            "dockerfile": """FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]""",
        }

    # Node / Express
    if (project_dir / "package.json").exists():
        try:
            pkg = json.loads((project_dir / "package.json").read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"package.json invalide: {e}")
        if "start" not in pkg.get("scripts", {}):
            raise ValueError("Script 'start' absent dans package.json")
        return {
            "type": "node", "port": 3000,
            "dockerfile": """FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]""",
        }

    # Python
    if (project_dir / "requirements.txt").exists():
        reqs = (project_dir / "requirements.txt").read_text(
            encoding="utf-8", errors="ignore"
        ).lower()

        if "fastapi" in reqs or "uvicorn" in reqs:
            module = "main:app" if (project_dir / "main.py").exists() else "app:app"
            if not (project_dir / "main.py").exists() and not (project_dir / "app.py").exists():
                raise ValueError("FastAPI : main.py ou app.py introuvable")
            return {
                "type": "python-fastapi", "port": 8000,
                "dockerfile": f"""FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "{module}", "--host", "0.0.0.0", "--port", "8000"]""",
            }

        entry = next(
            (c for c in ["app.py","main.py","run.py","server.py","wsgi.py"]
             if (project_dir / c).exists()), None
        )
        if not entry:
            raise ValueError("Python : aucun fichier d'entrée trouvé")

        port = 5000 if "flask" in reqs else 8000
        return {
            "type": "python", "port": port,
            "dockerfile": f"""FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE {port}
CMD ["python", "{entry}"]""",
        }

    # PHP
    if (project_dir / "composer.json").exists() or any(project_dir.glob("*.php")):
        return {
            "type": "php", "port": 80,
            "dockerfile": """FROM php:8.2-apache
WORKDIR /var/www/html
COPY . /var/www/html
EXPOSE 80""",
        }

    raise ValueError(
        "Stack non reconnue. Support V1 : Spring Boot, Node, Python, PHP."
    )


def _resolve_compose_file() -> Path:
    env_file = os.getenv("CYBERSENTINEL_COMPOSE_FILE")
    candidates = []
    if env_file:
        candidates.append(Path(env_file))
    candidates += [
        Path("/workspace/docker-compose.yml"),
        Path("/app/docker-compose.yml"),
        Path("./docker-compose.yml"),
        Path("./compose.yml"),
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    raise FileNotFoundError("Aucun docker-compose.yml trouvé.")


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

    async def _run_command(self, *cmd: str, timeout: int = 60,
                           cwd: Optional[str] = None) -> Tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

    async def _run_compose(self, *args: str, timeout: int = 60) -> Tuple[int, str, str]:
        cf  = self._get_compose_file()
        cmd = ["docker","compose","-p",COMPOSE_PROJECT_NAME,"-f",str(cf),*args]
        return await self._run_command(*cmd, timeout=timeout, cwd=str(cf.parent))

    # ── Vérifier que l'app uploadée est prête ─────────────────
    # FIX v3 : passe par ZAP (sandbox-net) au lieu du backend (main-net)
    # Le backend ne peut PAS atteindre sandbox-net directement.

    async def _wait_for_uploaded_app(
        self, target_url: str, timeout: int = 120
    ) -> bool:
        """
        Demande à ZAP (sur sandbox-net + mgmt-net) de tester l'accessibilité
        de l'app cible. Le backend ne peut pas accéder à sandbox-net directement.
        """
        deadline = time.time() + timeout
        logger.info(f"Attente démarrage app via ZAP proxy : {target_url}")

        async with httpx.AsyncClient() as client:
            while time.time() < deadline:
                try:
                    resp = await client.get(
                        f"{ZAP_HOST}/JSON/core/action/accessUrl/",
                        params={"url": target_url, "followRedirects": "true"},
                        timeout=10,
                    )

                    if resp.status_code == 200:
                        data     = resp.json()
                        result   = data.get("Result", "") or data.get("result", "")
                        zap_err  = str(data.get("error", "") or data.get("Error", "")).lower()

                        # L'app est prête si ZAP a pu s'y connecter
                        if result == "OK" or (not zap_err and "connection refused" not in zap_err):
                            logger.info(f"✅ App prête via ZAP : {target_url}")
                            return True

                        logger.info(f"App pas encore prête — ZAP: {data}")
                    else:
                        logger.info(f"ZAP API — HTTP {resp.status_code}")

                except Exception as e:
                    logger.info(f"Attente app ({target_url})... {e}")

                await asyncio.sleep(5)

        logger.error(f"❌ App non prête après {timeout}s : {target_url}")
        return False

    # ── ZAP seul (mode upload) ────────────────────────────────

    async def _ensure_zap_only(self) -> dict:
        logger.info("Démarrage ZAP seul (mode upload)")
        try:
            code, stdout, stderr = await self._run_compose(
                "--profile","dast","up","-d","--no-recreate","zap",
                timeout=180,
            )
            if code != 0:
                return {"success": False, "error": (stderr or stdout)[:1200]}

            await asyncio.sleep(5)
            isolation_ok = await self._verify_isolation()
            zap_ready    = await self._wait_for_zap(timeout=240)

            return {
                "success":      bool(isolation_ok and zap_ready),
                "isolation_ok": isolation_ok,
                "zap_ready":    zap_ready,
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout ZAP (>180s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Mode upload ZIP ───────────────────────────────────────

    async def run_uploaded_project(
        self, zip_path: str, original_name: str
    ) -> dict:
        container_name = None
        image_name     = None

        try:
            if self._session_active:
                return {"error": "Session DAST déjà active",
                        "session_id": self._current_session_id}

            isolation_ok = await self._verify_isolation()
            if not isolation_ok:
                return {"error": "sandbox-net non isolé",
                        "constraint": "C-05"}

            deploy_info = await self._ensure_zap_only()
            if not deploy_info.get("success"):
                return {"error": "ZAP non disponible", "details": deploy_info}

            container_name, image_name, target_url = \
                await self._deploy_uploaded_project(zip_path, original_name)

            # FIX : on passe par ZAP pour tester l'accessibilité
            ready = await self._wait_for_uploaded_app(target_url, timeout=120)
            if not ready:
                return {
                    "error": (
                        f"Application '{original_name}' non accessible depuis la sandbox après 120s. "
                        "Vérifiez que l'app démarre sans base de données externe."
                    )
                }

            result = await self.run_session(
                target="custom",
                target_url=target_url,
                deploy_target=False,
            )
            result["uploaded_project"] = {
                "filename":       original_name,
                "container_name": container_name,
                "image_name":     image_name,
                "target_url":     target_url,
            }
            return result

        except ValueError as e:
            logger.warning(f"run_uploaded_project ValueError: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.exception(f"run_uploaded_project erreur: {e}")
            return {"error": str(e)}
        finally:
            await self._cleanup_uploaded_target(container_name, image_name)
            try:
                Path(zip_path).unlink(missing_ok=True)
            except Exception:
                pass

    async def _deploy_uploaded_project(
        self, zip_path: str, original_name: str
    ) -> Tuple[str, str, str]:
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
        project_dir = (children[0]
                       if (len(children) == 1 and children[0].is_dir())
                       else extract_dir)

        stack          = _detect_stack(project_dir)
        dockerfile_path= project_dir / "Dockerfile.cybersentinel"
        dockerfile_path.write_text(stack["dockerfile"], encoding="utf-8")

        image_name     = f"cybersentinel-upload-{project_slug}:{unique_id}"
        container_name = f"cybersentinel_target_{unique_id}"

        logger.info(f"Build {stack['type']} → {image_name}")
        build_code, build_out, build_err = await self._run_command(
            "docker","build","-f",str(dockerfile_path),
            "-t",image_name,str(project_dir),
            timeout=900,
        )
        shutil.rmtree(extract_dir, ignore_errors=True)

        if build_code != 0:
            raise RuntimeError(
                f"Build échoué ({stack['type']}): {(build_err or build_out)[:1200]}"
            )

        # Run dans sandbox-net — ZAP est aussi sur sandbox-net → accès OK
        run_code, run_out, run_err = await self._run_command(
            "docker","run","-d",
            "--name", container_name,
            "--network","cybersentinel_sandbox-net",
            image_name,
            timeout=120,
        )
        if run_code != 0:
            raise RuntimeError(
                f"Lancement échoué: {(run_err or run_out)[:1200]}"
            )

        target_url = f"http://{container_name}:{stack['port']}"
        logger.info(f"Container démarré → {target_url}")
        return container_name, image_name, target_url

    async def _cleanup_uploaded_target(
        self, container_name: Optional[str], image_name: Optional[str]
    ):
        if container_name:
            try:
                await self._run_command("docker","rm","-f",container_name, timeout=60)
                logger.info(f"Container supprimé : {container_name}")
            except Exception as e:
                logger.warning(f"Erreur rm {container_name}: {e}")
        if image_name:
            try:
                await self._run_command("docker","rmi","-f",image_name, timeout=60)
                logger.info(f"Image supprimée : {image_name}")
            except Exception as e:
                logger.warning(f"Erreur rmi {image_name}: {e}")

    # ── Session normale (prédéfinie / URL custom) ─────────────

    async def run_session(
        self,
        target: str = "webgoat",
        target_url: Optional[str] = None,
        deploy_target: bool = True,
    ) -> dict:
        if self._session_active:
            return {"error": "Session DAST déjà active",
                    "session_id": self._current_session_id}

        if target_url:
            if not _is_valid_target_url(target_url):
                return {"error": "URL invalide", "constraint": "C-05"}
            if not _is_custom_target_inside_sandbox(target_url):
                return {"error": "Cible hors sandbox refusée", "constraint": "C-05"}
            resolved_name = "custom"
            resolved_url  = target_url.strip()
        else:
            if target not in ALLOWED_TARGETS:
                return {"error": f"Cible non autorisée: {list(ALLOWED_TARGETS.keys())}",
                        "constraint": "C-05"}
            resolved_name = target
            resolved_url  = ALLOWED_TARGETS[target]

        session_id = f"dast_{int(time.time())}"
        self._session_active        = True
        self._current_session_id    = session_id

        results = {
            "session_id":  session_id,
            "target":      resolved_name,
            "target_url":  resolved_url,
            "started_at":  datetime.now(timezone.utc).isoformat(),
            "phases":      {},
            "findings":    [],
            "pcap_path":   None,
            "total_vulns": 0,
        }

        try:
            results["phases"]["1_deploy"] = await self._phase_deploy(
                target=target,
                deploy_target=deploy_target and not bool(target_url),
            )
            if not results["phases"]["1_deploy"]["success"]:
                return results

            results["phases"]["2_spider"] = await self._phase_spider(resolved_url)
            capture_task = asyncio.create_task(self._start_pcap_capture(session_id))
            results["phases"]["3_inject"] = await self._phase_inject(resolved_url)

            pcap_path = await capture_task
            results["phases"]["4_capture"] = {
                "success":   bool(pcap_path),
                "pcap_path": str(pcap_path) if pcap_path else None,
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

    # ── Phase 1 — Deploy ──────────────────────────────────────

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
                "--profile","dast","up","-d","--no-recreate",
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

    async def _verify_isolation(self) -> bool:
        try:
            code, stdout, _ = await self._run_command(
                "docker","network","inspect","cybersentinel_sandbox-net",
                "--format","{{.Internal}}", timeout=20,
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
                    resp = await client.get(
                        f"{ZAP_HOST}/JSON/core/view/version/", timeout=5,
                    )
                    if resp.status_code == 200:
                        logger.info("✅ ZAP prêt")
                        return True
                except Exception as e:
                    logger.info(f"Attente ZAP... {e}")
                await asyncio.sleep(5)
        logger.error("ZAP non disponible")
        return False

    # ── Phases 2-6 (inchangées) ───────────────────────────────

    async def _phase_spider(self, target_url: str) -> dict:
        logger.info(f"Phase 2 — Spider {target_url}")
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                data    = (await client.get(
                    f"{ZAP_HOST}/JSON/spider/action/scan/",
                    params={"url": target_url, "maxChildren": 10},
                )).json()
                scan_id = data.get("scan")
                if not scan_id:
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
        try:
            async with httpx.AsyncClient(timeout=300) as client:
                scan_id = (await client.get(
                    f"{ZAP_HOST}/JSON/ascan/action/scan/",
                    params={"url": target_url, "recurse": "true", "inScopeOnly": "false"},
                )).json().get("scan")
                if not scan_id:
                    return {"success": False, "error": "Active scan invalide"}

                deadline = time.time() + 300
                while time.time() < deadline:
                    progress = int((await client.get(
                        f"{ZAP_HOST}/JSON/ascan/view/status/",
                        params={"scanId": scan_id},
                    )).json().get("status", 0))
                    if progress >= 100:
                        return {"success": True, "scan_id": scan_id, "progress": progress}
                    await asyncio.sleep(10)

                return {"success": False, "scan_id": scan_id, "error": "Timeout (>300s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _start_pcap_capture(self, session_id: str) -> Optional[Path]:
        HOST_PCAP_STORAGE.mkdir(parents=True, exist_ok=True)
        host_path      = HOST_PCAP_STORAGE / f"{session_id}.pcap"
        container_path = f"{CONTAINER_PCAP_STORAGE}/{session_id}.pcap"
        script = f"""
import sys
from scapy.all import sniff, wrpcap
pkts = sniff(timeout=180, filter="not arp", store=True)
wrpcap("{container_path}", pkts)
print(f"PCAP: {{len(pkts)}} paquets")
"""
        try:
            code, stdout, stderr = await self._run_command(
                "docker","exec","cybersentinel_zap","python3","-c",script,
                timeout=210,
            )
            if code == 0 and host_path.exists():
                return host_path
        except Exception as e:
            logger.error(f"PCAP erreur: {e}")
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
                    "session_id":  session_id,
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                    "alert_name":  alert.get("alert", ""),
                    "risk":        alert.get("risk", ""),
                    "confidence":  alert.get("confidence", ""),
                    "url":         alert.get("url", ""),
                    "method":      alert.get("method", ""),
                    "param":       alert.get("param", ""),
                    "attack":      alert.get("attack", ""),
                    "evidence":    alert.get("evidence", ""),
                    "description": alert.get("description", "")[:500],
                    "solution":    alert.get("solution", "")[:300],
                    "cwe_id":      alert.get("cweid", ""),
                }
                proof_path = HOST_PCAP_STORAGE / f"{session_id}_proof_{len(findings)}.json"
                proof_path.write_text(json.dumps(proof, indent=2, ensure_ascii=False))

                findings.append({
                    **proof,
                    "severity":   sev_map.get(alert.get("risk",""), SASTSeverity.MEDIUM).value,
                    "title":      alert.get("alert","ZAP Finding"),
                    "cwe":        f"CWE-{alert['cweid']}" if alert.get("cweid") else None,
                    "proof_path": str(proof_path),
                    "zap_alert":  alert.get("alert",""),
                    "tool":       "dast_zap",
                })
        except Exception as e:
            logger.error(f"Collecte preuves erreur: {e}")
        logger.info(f"Phase 5: {len(findings)} vulnérabilités")
        return findings

    async def _phase_teardown(self) -> dict:
        logger.info("Phase 6 — Teardown sandbox")
        try:
            await self._run_compose("--profile","dast","stop","zap","webgoat","dvwa", timeout=120)
            await self._run_compose("--profile","dast","rm","-f","zap","webgoat","dvwa", timeout=120)

            proc = await asyncio.create_subprocess_exec(
                "docker","ps","-a",
                "--filter","name=cybersentinel_zap",
                "--filter","name=cybersentinel_webgoat",
                "--filter","name=cybersentinel_dvwa",
                "--format","{{.Names}}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            residual = out.decode().strip()
            if residual:
                return {"success": False, "residual": residual}
            logger.info("✅ Sandbox DAST détruite")
            return {"success": True}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout teardown"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _process_findings(self, findings: list, session_id: str):
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            for finding in findings:
                zap_alert = finding.get("zap_alert", "")
                cwe       = finding.get("cwe", "")
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