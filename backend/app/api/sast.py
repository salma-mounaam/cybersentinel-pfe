# ============================================================
# M4 — API REST SAST
# Supporte :
# - scan par chemin local
# - scan synchrone
# - upload ZIP projet
# DEBUG : logs ajoutés sur /scan/sync pour tracer scan_id
# ============================================================

import logging
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
logger = logging.getLogger(__name__)


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
    repo_path = payload.get("repo_path", ".")
    repo_name = payload.get("repo_name", "")

    # DEBUG — trace ce que le frontend envoie
    logger.info(
        f"[SAST /scan/sync] reçu → "
        f"repo_path={repo_path!r} | "
        f"repo_name={repo_name!r}"
    )

    result = await orchestrator.run_full_scan(
        repo_path=repo_path,
        repo_name=repo_name,
        commit_sha=payload.get("commit_sha", ""),
        pr_number=payload.get("pr_number"),
    )

    # DEBUG — trace ce que le backend retourne
    logger.info(
        f"[SAST /scan/sync] terminé → "
        f"scan_id={result.get('scan_id')!r} | "
        f"total={result.get('total')} | "
        f"error={result.get('error')!r}"
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

    logger.info(
        f"[SAST /scan/upload] reçu → "
        f"filename={filename!r} | "
        f"repo_name={repo_name!r}"
    )

    result = await orchestrator.run_uploaded_scan(
        zip_path=tmp_path,
        repo_name=repo_name,
        commit_sha=commit_sha.strip(),
    )

    logger.info(
        f"[SAST /scan/upload] terminé → "
        f"scan_id={result.get('scan_id')!r} | "
        f"total={result.get('total')} | "
        f"error={result.get('error')!r}"
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
    scan_id: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """
    Récupère les findings SAST avec filtres.
    """
    query = select(SASTFinding).order_by(desc(SASTFinding.cvss_score), desc(SASTFinding.created_at))

    if tool:
        query = query.where(SASTFinding.tool == tool)
    if severity:
        query = query.where(SASTFinding.severity == severity)
    if cwe:
        query = query.where(SASTFinding.cwe == cwe)
    if scan_id:
        query = query.where(SASTFinding.scan_id == scan_id)

    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()

    return {
        "total": total or 0,
        "findings": [_finding_to_dict(f) for f in findings],
    }


# ============================================================
# KPIs SAST
# ============================================================
@router.get("/stats")
async def get_sast_stats(
    scan_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    KPIs SAST pour la page Overview.
    """
    # DEBUG — trace le scan_id reçu par /stats
    logger.info(f"[SAST /stats] scan_id reçu = {scan_id!r}")

    base_query = select(SASTFinding)

    if scan_id:
        base_query = base_query.where(SASTFinding.scan_id == scan_id)

    total = await db.scalar(
        select(func.count()).select_from(base_query.subquery())
    )

    by_tool = {}
    for tool in SASTTool:
        q = select(func.count(SASTFinding.id)).where(SASTFinding.tool == tool)
        if scan_id:
            q = q.where(SASTFinding.scan_id == scan_id)
        count = await db.scalar(q)
        by_tool[tool.value] = count or 0

    by_severity = {}
    for sev in SASTSeverity:
        q = select(func.count(SASTFinding.id)).where(SASTFinding.severity == sev)
        if scan_id:
            q = q.where(SASTFinding.scan_id == scan_id)
        count = await db.scalar(q)
        by_severity[sev.value] = count or 0

    q = select(func.count(SASTFinding.id)).where(SASTFinding.dast_confirmed == 1)
    if scan_id:
        q = q.where(SASTFinding.scan_id == scan_id)

    confirmed_by_dast = await db.scalar(q)

    logger.info(f"[SAST /stats] résultat → total={total} | scan_id_filtre={scan_id!r}")

    return {
        "scan_id": scan_id,
        "total": total or 0,
        "by_tool": by_tool,
        "by_severity": by_severity,
        "confirmed_by_dast": confirmed_by_dast or 0,
        "critical_count": by_severity.get("CRITICAL", 0),
        "secrets_found": by_tool.get("gitleaks", 0),
    }


# ============================================================
# Dernier scan
# ============================================================
@router.get("/latest-scan")
async def get_latest_scan(
    repo_name: Optional[str] = None,
    commit_sha: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(
        SASTFinding.scan_id,
        SASTFinding.created_at,
        SASTFinding.repo_name,
        SASTFinding.commit_sha,
    ).where(SASTFinding.scan_id.is_not(None))

    if repo_name:
        query = query.where(SASTFinding.repo_name == repo_name)

    if commit_sha:
        query = query.where(SASTFinding.commit_sha == commit_sha)

    query = query.order_by(desc(SASTFinding.created_at))

    result = await db.execute(query)
    row = result.first()

    if not row:
        return {
            "scan_id": None,
            "repo_name": repo_name,
            "commit_sha": commit_sha,
        }

    return {
        "scan_id": row[0],
        "repo_name": row[2],
        "commit_sha": row[3],
    }


# ============================================================
# Détail d'un finding
# ============================================================
@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
):
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
        "scan_id": f.scan_id,
        "tool": f.tool.value if f.tool else None,
        "severity": f.severity.value if f.severity else None,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "col_start": f.col_start,
        "col_end": f.col_end,
        "rule_id": f.rule_id,
        "cwe": f.cwe,
        "cve": f.cve,
        "cvss_score": f.cvss_score,
        "title": f.title,
        "description": f.description,
        "message": f.message,
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