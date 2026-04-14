# ============================================================
# M8 — API REST CI/CD
# GitHub webhooks + réception résultats + scan repo à la demande
# ============================================================

import asyncio
import hashlib
import hmac
import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

router = APIRouter(tags=["CI/CD"])
logger = logging.getLogger(__name__)

_pipeline_runs = []

# Si vide dans .env, la signature GitHub est ignorée (utile pour tests locaux)
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()


# ============================================================
# Webhook interne GitHub Actions
# ============================================================

@router.post("/webhook")
async def receive_cicd_webhook(request: Request):
    """
    Reçoit les notifications d'un workflow GitHub Actions interne
    pour alimenter la page M9.
    """
    try:
        data = await request.json()
    except Exception:
        data = {}

    run = {
        "run_id": data.get("run_id"),
        "decision": data.get("decision", "UNKNOWN"),
        "pr_number": data.get("pr_number"),
        "commit_sha": str(data.get("commit_sha", ""))[:8],
        "repo": data.get("repo"),
        "timestamp": datetime.utcnow().isoformat(),
        "source": "internal_workflow",
    }

    _pipeline_runs.insert(0, run)
    if len(_pipeline_runs) > 100:
        _pipeline_runs.pop()

    blocked = run["decision"] == "BLOCK"
    if blocked:
        logger.warning(
            f"🚨 PR bloquée | PR#{run['pr_number']} | "
            f"commit={run['commit_sha']} | {run['repo']}"
        )

    return {"received": True, "blocked": blocked}


# ============================================================
# Webhook GitHub externe
# ============================================================

@router.post("/github-webhook")
async def receive_github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Reçoit les webhooks GitHub des repos utilisateurs.

    Si GITHUB_WEBHOOK_SECRET est défini, la signature est vérifiée.
    Si GITHUB_WEBHOOK_SECRET est vide, la vérification est ignorée
    pour faciliter les tests locaux.
    """
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if GITHUB_WEBHOOK_SECRET:
        expected = "sha256=" + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode(),
            body,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=401, detail="Signature webhook invalide")

    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        payload = {}

    event_type = request.headers.get("X-GitHub-Event", "")
    logger.info(f"Webhook GitHub reçu | event={event_type}")

    if event_type == "push":
        repo_url = payload.get("repository", {}).get("clone_url", "")
        repo_name = payload.get("repository", {}).get("full_name", "")
        branch = payload.get("ref", "").replace("refs/heads/", "")
        commit_sha = payload.get("after", "")[:8]

        if not repo_url:
            return {"received": True, "skipped": "URL repo manquante"}

        logger.info(
            f"Push détecté | repo={repo_name} | branch={branch} | commit={commit_sha}"
        )

        background_tasks.add_task(
            _scan_github_repo,
            repo_url=repo_url,
            repo_name=repo_name,
            branch=branch,
            commit_sha=commit_sha,
            pr_number=None,
            token=None,
        )

        return {
            "received": True,
            "event": "push",
            "repo": repo_name,
            "branch": branch,
            "commit": commit_sha,
            "scan": "started",
        }

    if event_type == "pull_request":
        action = payload.get("action", "")
        if action not in ("opened", "synchronize", "reopened"):
            return {"received": True, "skipped": f"Action ignorée: {action}"}

        repo_url = payload.get("repository", {}).get("clone_url", "")
        repo_name = payload.get("repository", {}).get("full_name", "")
        pr_number = payload.get("number")
        head_sha = payload.get("pull_request", {}).get("head", {}).get("sha", "")[:8]
        head_branch = payload.get("pull_request", {}).get("head", {}).get("ref", "")

        if not repo_url:
            return {"received": True, "skipped": "URL repo manquante"}

        logger.info(
            f"PR détectée | repo={repo_name} | pr={pr_number} | "
            f"branch={head_branch} | sha={head_sha}"
        )

        background_tasks.add_task(
            _scan_github_repo,
            repo_url=repo_url,
            repo_name=repo_name,
            branch=head_branch,
            commit_sha=head_sha,
            pr_number=pr_number,
            token=None,
        )

        return {
            "received": True,
            "event": "pull_request",
            "repo": repo_name,
            "pr_number": pr_number,
            "scan": "started",
        }

    return {"received": True, "skipped": f"Event ignoré: {event_type}"}


# ============================================================
# Réception résultats depuis GitHub Actions repo utilisateur
# ============================================================

@router.post("/submit-results")
async def submit_scan_results(request: Request):
    """
    Reçoit les résultats GitHub Actions venant d'un repo utilisateur.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body JSON invalide")

    repo_name = data.get("repo_name", "unknown")
    commit_sha = str(data.get("commit_sha", ""))[:8]
    branch = data.get("branch", "main")
    pr_number = data.get("pr_number")

    logger.info(
        f"Résultats SAST reçus | repo={repo_name} | "
        f"branch={branch} | commit={commit_sha}"
    )

    try:
        from app.services.sast_service import SASTOrchestrator
        from app.models.sast_finding import SASTTool, SASTSeverity
        from app.services.mitre_service import MitreEnrichmentEngine
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Imports SAST impossibles: {e}")

    orchestrator = SASTOrchestrator()
    mitre_engine = MitreEnrichmentEngine()
    all_findings = []

    # ---- Semgrep
    if "semgrep_sarif" in data:
        with tempfile.NamedTemporaryFile(
            suffix=".sarif", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(data["semgrep_sarif"], f)
            semgrep_path = f.name

        try:
            findings = orchestrator._parse_sarif(semgrep_path, SASTTool.SEMGREP)
            for finding in findings:
                finding.repo_name = repo_name
                finding.commit_sha = commit_sha
                finding.pr_number = pr_number
            all_findings.extend(findings)
        finally:
            Path(semgrep_path).unlink(missing_ok=True)

    # ---- Trivy
    if "trivy_sarif" in data:
        with tempfile.NamedTemporaryFile(
            suffix=".sarif", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(data["trivy_sarif"], f)
            trivy_path = f.name

        try:
            findings = orchestrator._parse_sarif(trivy_path, SASTTool.TRIVY)
            for finding in findings:
                finding.repo_name = repo_name
                finding.commit_sha = commit_sha
                finding.pr_number = pr_number
            all_findings.extend(findings)
        finally:
            Path(trivy_path).unlink(missing_ok=True)

    # ---- Gitleaks
    if "gitleaks_json" in data:
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as f:
            json.dump(data["gitleaks_json"], f)
            gitleaks_path = f.name

        try:
            findings = orchestrator._parse_gitleaks(gitleaks_path)
            for finding in findings:
                finding.repo_name = repo_name
                finding.commit_sha = commit_sha
                finding.pr_number = pr_number
            all_findings.extend(findings)
        finally:
            Path(gitleaks_path).unlink(missing_ok=True)

    # ---- Enrichissement MITRE
    for finding in all_findings:
        try:
            technique_id = mitre_engine.resolve_sast({
                "tool": finding.tool.value if finding.tool else "",
                "cwe": finding.cwe or ""
            })
            mitre_data = await mitre_engine.enrich_by_technique_id(technique_id)
            finding.technique_id = mitre_data.get("technique_id")
            finding.technique_name = mitre_data.get("technique_name")
            finding.tactic = mitre_data.get("tactic")
        except Exception as e:
            logger.warning(f"MITRE enrichissement échoué: {e}")

    saved_findings = await orchestrator._save_findings(all_findings)

    critical_count = sum(
        1 for f in all_findings
        if f.severity == SASTSeverity.CRITICAL
    )
    high_count = sum(
        1 for f in all_findings
        if f.severity == SASTSeverity.HIGH
    )
    secrets_found = any(
        f.tool == SASTTool.GITLEAKS
        for f in all_findings
    )

    gate_result = {
        "decision": "BLOCK" if (critical_count >= 1 or high_count > 5 or secrets_found) else "PASS",
        "critical_count": critical_count,
        "high_count": high_count,
        "secrets_found": secrets_found,
        "total_findings": len(all_findings),
        "saved_ids": [f.id for f in saved_findings if getattr(f, "id", None) is not None],
        "repo_name": repo_name,
        "commit_sha": commit_sha,
        "pr_number": pr_number,
    }

    run = {
        "run_id": f"submit_{commit_sha}",
        "decision": gate_result["decision"],
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "repo": repo_name,
        "timestamp": datetime.utcnow().isoformat(),
        "source": "github_actions_submit",
    }
    _pipeline_runs.insert(0, run)

    if len(_pipeline_runs) > 100:
        _pipeline_runs.pop()

    logger.info(
        f"Submit results terminé | repo={repo_name} | "
        f"decision={gate_result['decision']} | findings={len(all_findings)}"
    )

    return gate_result


# ============================================================
# Scan manuel d'un repo
# ============================================================

@router.post("/scan/repo")
async def scan_repo_url(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    """
    Lance un scan manuel d'un repo GitHub à la demande.
    """
    repo_url = payload.get("repo_url", "")
    branch = payload.get("branch", "main")
    repo_name = payload.get("repo_name") or repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    token = payload.get("token")

    if not repo_url:
        raise HTTPException(status_code=400, detail="repo_url requis")

    if not repo_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=400,
            detail="Seuls les repos GitHub sont supportés"
        )

    background_tasks.add_task(
        _scan_github_repo,
        repo_url=repo_url,
        repo_name=repo_name,
        branch=branch,
        commit_sha="",
        pr_number=None,
        token=token,
    )

    return {
        "status": "started",
        "repo_url": repo_url,
        "branch": branch,
        "message": f"Scan lancé pour {repo_name}@{branch}",
    }


# ============================================================
# Endpoints de consultation
# ============================================================

@router.get("/runs")
async def get_pipeline_runs():
    total = len(_pipeline_runs)
    blocked = sum(1 for r in _pipeline_runs if r["decision"] == "BLOCK")
    passed = sum(1 for r in _pipeline_runs if r["decision"] == "PASS")
    block_rate = round((blocked / max(total, 1)) * 100, 1)

    return {
        "total": total,
        "blocked": blocked,
        "passed": passed,
        "block_rate": block_rate,
        "h5_status": block_rate >= 100.0 if blocked > 0 else None,
        "runs": _pipeline_runs[:50],
    }


@router.get("/quality-gate/config")
async def get_quality_gate_config():
    return {
        "rules": {
            "block": [
                "≥ 1 vulnérabilité CRITIQUE",
                "> 5 vulnérabilités ÉLEVÉES",
                "≥ 1 secret exposé",
                "ML smoke test échoué",
            ],
            "warn": [
                "> 3 vulnérabilités MOYENNES",
                "Couverture tests < 80%",
                "Temps build > 6 min",
            ],
        },
        "h5_target": "Blocage = 100% des PRs critiques",
        "max_duration_minutes": 8,
    }


@router.get("/integration-guide")
async def get_integration_guide(request: Request):
    base_url = str(request.base_url).rstrip("/")

    return {
        "methods": {
            "option1_webhook": {
                "title": "Option 1 — Webhook GitHub automatique",
                "description": "GitHub notifie CyberSentinel à chaque push, puis CyberSentinel clone et analyse le repo.",
                "steps": [
                    "GitHub → Settings → Webhooks",
                    "Add webhook",
                    f"Payload URL : {base_url}/api/cicd/github-webhook",
                    "Content type : application/json",
                    f"Secret : {GITHUB_WEBHOOK_SECRET or '(désactivé pour tests locaux)'}",
                    "Events : Pushes + Pull requests",
                ],
            },
            "option2_actions": {
                "title": "Option 2 — GitHub Actions dans le repo utilisateur",
                "description": "Le repo utilisateur exécute les scans et soumet les résultats à CyberSentinel.",
                "workflow_url": f"{base_url}/api/cicd/workflow-template",
            },
            "option3_manual": {
                "title": "Option 3 — Scan manuel depuis le dashboard",
                "endpoint": f"{base_url}/api/cicd/scan/repo",
            },
        }
    }


@router.get("/workflow-template")
async def get_workflow_template():
    template_path = Path(".github/workflows/cybersentinel-integration.yml")
    if template_path.exists():
        return {
            "filename": "cybersentinel-integration.yml",
            "content": template_path.read_text(encoding="utf-8"),
        }

    return {
        "filename": "cybersentinel-integration.yml",
        "content": "# Template non trouvé",
    }


# ============================================================
# Worker scan repo GitHub
# ============================================================

async def _scan_github_repo(
    repo_url: str,
    repo_name: str,
    branch: str = "main",
    commit_sha: str = "",
    pr_number: Optional[int] = None,
    token: Optional[str] = None,
):
    """
    Clone le repo utilisateur et lance le scan SAST complet.
    """
    try:
        from app.services.sast_service import SASTOrchestrator
    except Exception as e:
        logger.error(f"Import SASTOrchestrator impossible: {e}")
        return

    clone_url = repo_url
    if token:
        clone_url = repo_url.replace("https://", f"https://{token}@")

    with tempfile.TemporaryDirectory() as tmp_dir:
        try:
            logger.info(f"Clone {repo_name}@{branch} -> {tmp_dir}")

            proc = await asyncio.create_subprocess_exec(
                "git", "clone",
                "--depth", "1",
                "--branch", branch,
                clone_url,
                tmp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            if proc.returncode != 0:
                logger.error(
                    f"Clone échoué pour {repo_name}: {stderr.decode(errors='ignore')[:300]}"
                )
                return

            if stdout:
                logger.debug(f"git clone stdout: {stdout.decode(errors='ignore')[:1000]}")

            orchestrator = SASTOrchestrator()
            results = await orchestrator.run_full_scan(
                repo_path=tmp_dir,
                repo_name=repo_name,
                commit_sha=commit_sha,
                pr_number=pr_number,
            )

            logger.info(
                f"Scan terminé | repo={repo_name} | total={results.get('total', 0)} | "
                f"critical={results.get('by_severity', {}).get('CRITICAL', 0)}"
            )

            decision = "BLOCK" if (
                results.get("by_severity", {}).get("CRITICAL", 0) >= 1
                or results.get("by_severity", {}).get("HIGH", 0) > 5
                or results.get("has_secrets", False)
            ) else "PASS"

            run = {
                "run_id": f"scan_{repo_name}_{commit_sha or branch}",
                "decision": decision,
                "pr_number": pr_number,
                "commit_sha": commit_sha[:8] if commit_sha else "",
                "repo": repo_name,
                "timestamp": datetime.utcnow().isoformat(),
                "source": "github_webhook_scan",
            }
            _pipeline_runs.insert(0, run)

            if len(_pipeline_runs) > 100:
                _pipeline_runs.pop()

        except asyncio.TimeoutError:
            logger.error(f"Timeout clone repo {repo_name}")
        except Exception as e:
            logger.error(f"Erreur scan repo {repo_name}: {e}")