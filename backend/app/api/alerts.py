# ============================================================
# M1 — API REST Alertes
# FIXES :
#   [D] Ajout endpoint DELETE /alerts/cache/clear
#   [B] fusion_case stocké en int dans Redis (pas string)
# ============================================================

from datetime import datetime, timezone
from typing import List, Optional
import json

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
import redis.asyncio as aioredis

from app.core.database import get_db
from app.models.alert import Alert, SeverityLevel
from app.core.config import settings


router = APIRouter()


class AlertIn(BaseModel):
    title: Optional[str] = None
    signature_name: Optional[str] = None
    severity: str = "MOYEN"
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    category: Optional[str] = None
    source: str = "suricata"


def normalize_severity(severity: str) -> str:
    sev = (severity or "MOYEN").upper()
    mapping = {
        "CRITICAL":      "CRITIQUE",
        "HIGH":          "ELEVE",
        "MEDIUM":        "MOYEN",
        "LOW":           "FAIBLE",
        "INFO":          "FAIBLE",
        "INFORMATIONAL": "FAIBLE",
        "CRITIQUE":      "CRITIQUE",
        "ELEVE":         "ELEVE",
        "ÉLEVÉ":         "ELEVE",
        "MOYEN":         "MOYEN",
        "FAIBLE":        "FAIBLE",
    }
    return mapping.get(sev, "MOYEN")


# [B] Normalise fusion_case : string → int
# Problème : fusion_service.py publie parfois "SIGNATURE_ONLY"
# au lieu du numéro de cas, ce qui cassait l'affichage frontend
FUSION_CASE_STRING_MAP = {
    "SIGNATURE_ML_FLUX": 1,
    "SIGNATURE_ML_5S":   2,
    "SIGNATURE_ONLY":    3,
    "ML_ONLY":           4,
    "BRUIT":             5,
    "NOISE":             5,
}

def normalize_fusion_case(raw) -> Optional[int]:
    """Convertit fusion_case string ou int → int 1-5."""
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        from_map = FUSION_CASE_STRING_MAP.get(raw.upper())
        if from_map:
            return from_map
        try:
            return int(raw)
        except ValueError:
            return None
    return None


@router.post("/ingest")
async def ingest_alert(alert: AlertIn):
    """
    Reçoit une alerte externe depuis Suricata GNS3.
    Stockage rapide dans Redis pour affichage dashboard temps réel.
    """
    now = datetime.now(timezone.utc)
    signature = alert.signature_name or alert.title or "Suricata Alert"

    data = {
        "id":             int(now.timestamp() * 1000),
        "source":         alert.source,
        "severity":       normalize_severity(alert.severity),
        "src_ip":         alert.src_ip,
        "dest_ip":        alert.dest_ip,
        "src_port":       alert.src_port,
        "dest_port":      alert.dest_port,
        "protocol":       alert.protocol,
        "signature_id":   None,
        "signature_name": signature,
        "title":          signature,
        "category":       alert.category,
        "suricata_score": 1.0,
        "ml_score":       0.0,
        "confidence":     0.7,
        # [B] FIX : stocker en int, pas en string "SIGNATURE_ONLY"
        "fusion_case":    3,
        "technique_id":   None,
        "technique_name": None,
        "tactic":         None,
        "apt_groups":     [],
        "detected_at":    now.isoformat(),
    }

    r = await aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    try:
        await r.zadd("alerts:recent", {json.dumps(data): now.timestamp()})
        await r.zremrangebyrank("alerts:recent", 0, -501)
    finally:
        await r.aclose()

    return {"status": "ok", "message": "alert ingested", "alert": data}


@router.get("/recent")
async def get_recent_alerts(limit: int = 20):
    """Récupère les alertes récentes depuis Redis."""
    r = await aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    try:
        raw = await r.zrevrange("alerts:recent", 0, limit - 1)
        alerts = []
        for item in raw:
            try:
                a = json.loads(item)
                # [B] Normaliser fusion_case à la lecture aussi
                a["fusion_case"] = normalize_fusion_case(a.get("fusion_case"))
                alerts.append(a)
            except json.JSONDecodeError:
                continue
        return {"total": len(alerts), "alerts": alerts}
    finally:
        await r.aclose()


@router.delete("/cache/clear")
async def clear_alerts_cache():
    """
    [D] Vide le cache Redis des alertes récentes.
    Utile en dev pour repartir propre sans anciennes alertes
    qui s'affichent comme nouvelles au redémarrage.
    """
    r = await aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    try:
        deleted = await r.delete("alerts:recent")
        return {
            "status":  "ok",
            "message": "Cache Redis vidé",
            "deleted": bool(deleted),
        }
    finally:
        await r.aclose()


@router.get("/")
async def get_alerts(
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Récupère les alertes depuis PostgreSQL avec filtres optionnels."""
    query = select(Alert).order_by(desc(Alert.detected_at))

    if severity:
        query = query.where(Alert.severity == severity)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "total":  len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


@router.get("/stats")
async def get_alert_stats(db: AsyncSession = Depends(get_db)):
    """KPIs pour la page Overview M9."""
    total = await db.scalar(select(func.count(Alert.id)))

    counts = {}
    for sev in SeverityLevel:
        count = await db.scalar(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )
        counts[sev.value] = count

    return {
        "total":          total,
        "by_severity":    counts,
        "detection_rate": round(
            (counts.get("CRITIQUE", 0) + counts.get("ELEVE", 0)) / max(total, 1) * 100,
            1
        ),
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Détail d'une alerte spécifique."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    return _alert_to_dict(alert)


def _alert_to_dict(alert: Alert) -> dict:
    return {
        "id":             alert.id,
        "source":         alert.source.value if alert.source else None,
        "severity":       alert.severity.value if alert.severity else None,
        "src_ip":         alert.src_ip,
        "dest_ip":        alert.dest_ip,
        "src_port":       alert.src_port,
        "dest_port":      alert.dest_port,
        "protocol":       alert.protocol,
        "signature_id":   alert.signature_id,
        "signature_name": alert.signature_name,
        "category":       alert.category,
        "suricata_score": alert.suricata_score,
        "attack_type":    alert.attack_type,
        "attack_type":    alert.attack_type,
        "ml_score":       alert.ml_score,
        "confidence":     alert.confidence,
        # [B] FIX : normaliser fusion_case depuis la DB aussi
        "fusion_case":    normalize_fusion_case(alert.fusion_case),
        "technique_id":   alert.technique_id,
        "technique_name": alert.technique_name,
        "tactic":         alert.tactic,
        "apt_groups":     alert.apt_groups or [],
        "detected_at":    alert.detected_at.isoformat() if alert.detected_at else None,
    }