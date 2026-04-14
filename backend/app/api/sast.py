# ============================================================
# M4 — API REST SAST
# Supporte :
# - scan par chemin local
# - scan synchrone
# - upload ZIP projet
# ============================================================

import tempfile
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    BackgroundTasks,
    Query,
    UploadFile,
    File,
    Form,
    HTTPException,
)
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.sast_finding import SASTFinding, SASTTool, SASTSeverity
from app.services.sast_service import SASTOrchestrator

router = APIRouter()
orchestrator = SASTOrchestrator()


# ============================================================
# Scan SAST async par chemin local
# ============================================================
@router.post("/scan")
async def trigger_scan(
    payload: dict,
    background_tasks: BackgroundTasks,
):
    """
    Lance un scan SAST complet en tâche de fond.
    Body:
    {
      "repo_path": "/path/to/your/code",
      "repo_name": "mon-projet",
      "commit_sha": "abc123"
    }
    """
    repo_path = payload.get("repo_path", ".")
    repo_name = payload.get("repo_name", "")
    commit_sha = payload.get("commit_sha", "")

    background_tasks.add_task(
        orchestrator.run_full_scan,
        repo_path=repo_path,
        repo_name=repo_name,
        commit_sha=commit_sha,
    )

    return {
        "status": "started",
        "repo_path": repo_path,
        "repo_name": repo_name,
        "message": "Scan SAST lancé — Semgrep + Trivy + Gitleaks en parallèle",
    }


# ============================================================
# Scan SAST sync par chemin local
# ============================================================
@router.post("/scan/sync")
async def trigger_scan_sync(payload: dict):
    """
    Lance un scan SAST synchrone.
    Pour les tests et la démo live.
    """
    result = await orchestrator.run_full_scan(
        repo_path=payload.get("repo_path", "."),
        repo_name=payload.get("repo_name", ""),
        commit_sha=payload.get("commit_sha", ""),
        pr_number=payload.get("pr_number"),
    )
    return result


# ============================================================
# Upload ZIP projet → scan SAST sync
# ============================================================
@router.post("/scan/upload")
async def trigger_scan_upload(
    file: UploadFile = File(...),
    project_name: str = Form(default=""),
    commit_sha: str = Form(default=""),
):
    """
    Reçoit un ZIP du projet et lance un scan SAST synchrone.
    Champs multipart:
    - file: archive .zip
    - project_name: nom logique du projet
    - commit_sha: optionnel
    """
    filename = file.filename or "project.zip"
    suffix = Path(filename).suffix.lower()

    if suffix != ".zip":
        raise HTTPException(
            status_code=400,
            detail="Format non supporté. Utilise un fichier .zip",
        )

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Fichier vide.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    repo_name = project_name.strip() or Path(filename).stem

    result = await orchestrator.run_uploaded_scan(
        zip_path=tmp_path,
        repo_name=repo_name,
        commit_sha=commit_sha.strip(),
    )
    return result


# ============================================================
# Liste des findings
# ============================================================
@router.get("/findings")
async def get_findings(
    tool: Optional[SASTTool] = None,
    severity: Optional[SASTSeverity] = None,
    cwe: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """
    Récupère les findings SAST avec filtres.
    """
    query = select(SASTFinding).order_by(desc(SASTFinding.cvss_score))

    if tool:
        query = query.where(SASTFinding.tool == tool)
    if severity:
        query = query.where(SASTFinding.severity == severity)
    if cwe:
        query = query.where(SASTFinding.cwe == cwe)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()

    return {
        "total": len(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }


# ============================================================
# KPIs SAST
# ============================================================
@router.get("/stats")
async def get_sast_stats(db: AsyncSession = Depends(get_db)):
    """
    KPIs SAST pour la page Overview.
    """
    total = await db.scalar(select(func.count(SASTFinding.id)))

    by_tool = {}
    for tool in SASTTool:
        count = await db.scalar(
            select(func.count(SASTFinding.id)).where(SASTFinding.tool == tool)
        )
        by_tool[tool.value] = count or 0

    by_severity = {}
    for sev in SASTSeverity:
        count = await db.scalar(
            select(func.count(SASTFinding.id)).where(SASTFinding.severity == sev)
        )
        by_severity[sev.value] = count or 0

    confirmed_by_dast = await db.scalar(
        select(func.count(SASTFinding.id)).where(SASTFinding.dast_confirmed == 1)
    )

    return {
        "total": total or 0,
        "by_tool": by_tool,
        "by_severity": by_severity,
        "confirmed_by_dast": confirmed_by_dast or 0,
        "critical_count": by_severity.get("CRITICAL", 0),
        "secrets_found": by_tool.get("gitleaks", 0),
    }


# ============================================================
# Détail d'un finding
# ============================================================
@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Détail d'un finding SAST.
    """
    result = await db.execute(
        select(SASTFinding).where(SASTFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding introuvable")

    return _finding_to_dict(finding)


# ============================================================
# Quality Gate
# ============================================================
@router.post("/quality-gate")
async def evaluate_quality_gate(payload: dict):
    """
    Évalue le quality gate M8 sur les résultats SAST.
    Body:
    {
      "critical_count": 1,
      "high_count": 3,
      "secrets_found": false,
      "ml_smoke_pass": true
    }
    """
    critical_count = payload.get("critical_count", 0)
    high_count = payload.get("high_count", 0)
    secrets_found = payload.get("secrets_found", False)
    ml_smoke_pass = payload.get("ml_smoke_pass", True)

    blockers = []
    warnings = []

    if critical_count >= 1:
        blockers.append(f"{critical_count} vulnérabilité(s) CRITIQUE(S) détectée(s)")
    if high_count > 5:
        blockers.append(f"{high_count} vulnérabilités ÉLEVÉES (seuil: 5)")
    if secrets_found:
        blockers.append("Secret(s) exposé(s) détecté(s) par Gitleaks")
    if not ml_smoke_pass:
        blockers.append("ML smoke test échoué")

    return {
        "decision": "BLOCK" if blockers else "PASS",
        "blockers": blockers,
        "warnings": warnings,
        "h5_contribution": len(blockers) > 0,
        "critical_count": critical_count,
        "high_count": high_count,
        "secrets_found": secrets_found,
    }


# ============================================================
# Mapping modèle -> dict
# ============================================================
def _finding_to_dict(f: SASTFinding) -> dict:
    return {
        "id": f.id,
        "tool": f.tool.value if f.tool else None,
        "severity": f.severity.value if f.severity else None,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "rule_id": f.rule_id,
        "cwe": f.cwe,
        "cve": f.cve,
        "cvss_score": f.cvss_score,
        "title": f.title,
        "description": f.description,
        "fix_version": f.fix_version,
        "technique_id": f.technique_id,
        "technique_name": f.technique_name,
        "tactic": f.tactic,
        "dast_confirmed": f.dast_confirmed,
        "repo_name": f.repo_name,
        "commit_sha": f.commit_sha,
        "pr_number": f.pr_number,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }