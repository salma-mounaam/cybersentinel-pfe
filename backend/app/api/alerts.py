# ============================================================
# M1 — API REST Alertes
# ============================================================

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from typing import List, Optional
import json

from app.core.database import get_db
from app.models.alert import Alert, SeverityLevel
from app.core.config import settings
import redis.asyncio as aioredis

router = APIRouter()


@router.get("/")
async def get_alerts(
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Récupère les alertes avec filtres optionnels."""
    query = select(Alert).order_by(desc(Alert.detected_at))

    if severity:
        query = query.where(Alert.severity == severity)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "total": len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts]
    }


@router.get("/recent")
async def get_recent_alerts(limit: int = 20):
    """
    Récupère les alertes récentes depuis Redis (< 5ms).
    Plus rapide que PostgreSQL pour le dashboard temps réel.
    """
    r = await aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True
    )
    try:
        # Récupérer les N dernières du Sorted Set (score DESC)
        raw = await r.zrevrange("alerts:recent", 0, limit - 1)
        alerts = [json.loads(item) for item in raw]
        return {"total": len(alerts), "alerts": alerts}
    finally:
        await r.aclose()


@router.get("/stats")
async def get_alert_stats(db: AsyncSession = Depends(get_db)):
    """KPIs pour la page Overview M9."""
    total = await db.scalar(select(func.count(Alert.id)))

    # Compter par sévérité
    counts = {}
    for sev in SeverityLevel:
        count = await db.scalar(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )
        counts[sev.value] = count

    return {
        "total": total,
        "by_severity": counts,
        "detection_rate": round(
            (counts.get("CRITIQUE", 0) + counts.get("ELEVE", 0)) / max(total, 1) * 100,
            1
        )
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Détail d'une alerte spécifique."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    return _alert_to_dict(alert)


def _alert_to_dict(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "source": alert.source.value if alert.source else None,
        "severity": alert.severity.value if alert.severity else None,
        "src_ip": alert.src_ip,
        "dest_ip": alert.dest_ip,
        "src_port": alert.src_port,
        "dest_port": alert.dest_port,
        "protocol": alert.protocol,
        "signature_id": alert.signature_id,
        "signature_name": alert.signature_name,
        "category": alert.category,
        "suricata_score": alert.suricata_score,
        "ml_score": alert.ml_score,
        "confidence": alert.confidence,
        "fusion_case": alert.fusion_case,
        "technique_id": alert.technique_id,
        "technique_name": alert.technique_name,
        "tactic": alert.tactic,
        "apt_groups": alert.apt_groups or [],
        "detected_at": alert.detected_at.isoformat() if alert.detected_at else None,
    }
