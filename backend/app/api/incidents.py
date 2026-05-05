# ============================================================
# M7 — API REST Incidents + Score R
# FIXES :
#   [#12] incident_stats : ajout resolved_this_week
#   [#11] list_incidents  : ajout offset pour pagination complète
# ============================================================

from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, desc, func

from app.core.database import AsyncSessionLocal
from app.models.alert import SeverityLevel
from app.models.incident import Incident, IncidentStatus
from app.services.scoring_service import RiskScoringEngine

router = APIRouter()
engine = RiskScoringEngine()


# ============================================================
# Schemas
# ============================================================

class ComputeRRequest(BaseModel):
    anomaly_score: float = Field(0.0, ge=0.0, le=10.0)
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    dast_confirmed: bool = False
    asset_criticality: float = Field(5.0, ge=0.0, le=10.0)


class ValidateH4Request(BaseModel):
    computed_scores: List[float]
    expert_scores: List[float]


class UpdateIncidentStatusRequest(BaseModel):
    status: IncidentStatus


# ============================================================
# Helpers
# ============================================================

def incident_to_dict(incident: Incident) -> dict:
    title = incident.title or ""
    attack_type = title.split(" — ")[0] if " — " in title else None
    return {
        "id": incident.id,
        "title": incident.title,
        "attack_type": attack_type,  # ← ajouter cette ligne
        "status": incident.status.value if incident.status else None,
        "severity": incident.severity.value if incident.severity else None,
        "score_r": incident.score_r,
        "score_a": incident.score_a,
        "score_v": incident.score_v,
        "score_e": incident.score_e,
        "score_c": incident.score_c,
        "alert_ids": incident.alert_ids or [],
        "sast_finding_ids": incident.sast_finding_ids or [],
        "dast_finding_ids": incident.dast_finding_ids or [],
        "technique_id": incident.technique_id,
        "technique_name": incident.technique_name,
        "tactic": incident.tactic,
        "apt_groups": incident.apt_groups or [],
        "mitre_url": incident.mitre_url,
        "asset_ip": incident.asset_ip,
        "asset_name": incident.asset_name,
        "asset_criticality": incident.asset_criticality,
        "sla_deadline": incident.sla_deadline.isoformat() if incident.sla_deadline else None,
        "description": incident.description,
        "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
    }


# ============================================================
# Endpoints
# ============================================================

@router.post("/compute-r")
async def compute_r(payload: ComputeRRequest):
    result = engine.compute_score_r(
        anomaly_score=payload.anomaly_score,
        cvss_score=payload.cvss_score,
        dast_confirmed=payload.dast_confirmed,
        asset_criticality=payload.asset_criticality,
    )
    return result


@router.post("/validate-h4")
async def validate_h4(payload: ValidateH4Request):
    return engine.validate_h4(
        computed_scores=payload.computed_scores,
        expert_scores=payload.expert_scores,
    )


@router.get("/")
async def list_incidents(
    severity: Optional[SeverityLevel] = None,
    status: Optional[IncidentStatus] = None,
    technique_id: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    # FIX [#11] : ajout du paramètre offset manquant
    offset: int = Query(0, ge=0),
):
    """
    Liste les incidents avec filtres et pagination complète.
    FIX [#11] : le paramètre `offset` était ignoré côté backend
    alors que le frontend (api.ts) l'envoyait correctement.
    """
    async with AsyncSessionLocal() as db:
        stmt = select(Incident)

        if severity:
            stmt = stmt.where(Incident.severity == severity)

        # FIX [#11] : filtres status et technique_id manquants
        if status:
            stmt = stmt.where(Incident.status == status)

        if technique_id:
            stmt = stmt.where(Incident.technique_id == technique_id)

        stmt = (
            stmt
            .order_by(desc(Incident.score_r))
            .offset(offset)   # FIX [#11] : offset maintenant appliqué
            .limit(limit)
        )

        result = await db.execute(stmt)
        incidents = result.scalars().all()

        # Compte total pour la pagination côté frontend
        count_stmt = select(func.count(Incident.id))
        if severity:
            count_stmt = count_stmt.where(Incident.severity == severity)
        if status:
            count_stmt = count_stmt.where(Incident.status == status)
        if technique_id:
            count_stmt = count_stmt.where(Incident.technique_id == technique_id)

        total = await db.scalar(count_stmt) or 0

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "incidents": [incident_to_dict(i) for i in incidents],
    }


@router.get("/critical")
async def get_critical_incidents():
    async with AsyncSessionLocal() as db:
        stmt = (
            select(Incident)
            .where(Incident.severity == SeverityLevel.CRITIQUE)
            .where(Incident.status == IncidentStatus.OPEN)
            .order_by(desc(Incident.score_r))
        )
        result = await db.execute(stmt)
        incidents = result.scalars().all()

    return {
        "total": len(incidents),
        "incidents": [incident_to_dict(i) for i in incidents],
    }


@router.get("/stats")
async def incident_stats():
    """
    KPIs incidents pour la page Overview M9.
    FIX [#12] : ajout de resolved_this_week qui était absent
    et causait l'affichage de "—" permanent dans Overview.tsx.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Incident))
        incidents = result.scalars().all()

    by_severity = {
        "CRITIQUE": 0,
        "ELEVE": 0,
        "MOYEN": 0,
        "FAIBLE": 0,
    }

    overdue_sla = 0
    total_score = 0.0
    resolved_count = 0
    now = datetime.now(timezone.utc)

    # FIX [#12] : fenêtre "cette semaine" = 7 derniers jours
    week_ago = now - timedelta(days=7)

    for inc in incidents:
        sev = inc.severity.value if inc.severity else None
        if sev in by_severity:
            by_severity[sev] += 1

        total_score += inc.score_r or 0.0

        # SLA dépassé : incident non résolu avec deadline passée
        if (
            inc.status != IncidentStatus.RESOLVED
            and inc.sla_deadline is not None
            and inc.sla_deadline.tzinfo is not None
            and inc.sla_deadline < now
        ):
            overdue_sla += 1

        # FIX [#12] : compter les incidents résolus cette semaine
        if (
            inc.status == IncidentStatus.RESOLVED
            and inc.updated_at is not None
        ):
            # S'assurer que updated_at est timezone-aware
            updated = inc.updated_at
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)

            if updated >= week_ago:
                resolved_count += 1

    total = len(incidents)
    avg_score_r = round(total_score / total, 2) if total else 0.0

    return {
        "total": total,
        "by_severity": by_severity,
        "avg_score_r": avg_score_r,
        "overdue_sla": overdue_sla,
        # FIX [#12] : champ ajouté — lu par Overview.tsx ligne :
        # const resolvedInc = incidentStats?.resolved_this_week ?? "—"
        "resolved_this_week": resolved_count,
    }


@router.get("/{incident_id}")
async def get_incident(incident_id: int):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        incident = result.scalar_one_or_none()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident introuvable")

        return incident_to_dict(incident)


@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: int,
    payload: UpdateIncidentStatusRequest,
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        incident = result.scalar_one_or_none()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident introuvable")

        incident.status = payload.status
        # Mettre à jour updated_at pour que resolved_this_week soit correct
        incident.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(incident)

    return {
        "id": incident.id,
        "status": incident.status.value,
    }