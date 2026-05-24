# ============================================================
# M11 — API HIDS / Wazuh
# Stats + Alertes HIDS avec filtrage temporel et machine
#
# Modifications :
#   [1] /stats compte par défaut les alertes des dernières 24h
#   [2] /alerts expose agent_ip / agent_hostname / asset_*
#   [3] /alerts accepte agent_ip, asset_ip, hostname
#   [4] total_historical ajouté pour garder la vision globale
# ============================================================

from datetime import datetime, timezone, timedelta
from typing import Optional, Any

from fastapi import APIRouter, Query
from sqlalchemy import select, func, desc, or_

from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource, SeverityLevel
from app.services.wazuh_service import WazuhConsumer

router = APIRouter()
wazuh_consumer = WazuhConsumer()


def enum_value(value):
    return value.value if hasattr(value, "value") else str(value)


def normalize_severity(severity: Optional[str]):
    if not severity:
        return None

    sev = severity.upper().strip()

    mapping = {
        "CRITICAL": SeverityLevel.CRITIQUE,
        "HIGH": SeverityLevel.ELEVE,
        "MEDIUM": SeverityLevel.MOYEN,
        "LOW": SeverityLevel.FAIBLE,
        "INFO": SeverityLevel.FAIBLE,
        "INFORMATIONAL": SeverityLevel.FAIBLE,
        "CRITIQUE": SeverityLevel.CRITIQUE,
        "ELEVE": SeverityLevel.ELEVE,
        "ÉLEVÉ": SeverityLevel.ELEVE,
        "MOYEN": SeverityLevel.MOYEN,
        "FAIBLE": SeverityLevel.FAIBLE,
    }

    return mapping.get(sev)


def raw_get(raw: Any, path: str):
    """
    Récupère une valeur dans un dict imbriqué.
    Exemple : raw_get(raw, "agent.ip")
    """
    if not isinstance(raw, dict):
        return None

    current = raw

    for part in path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

        if current is None:
            return None

    return current


def extract_agent_ip(alert: Alert) -> Optional[str]:
    raw = alert.raw_payload or {}

    return (
        raw_get(raw, "agent_ip")
        or raw_get(raw, "agent.ip")
        or raw_get(raw, "agent.ip_address")
        or raw_get(raw, "host.ip")
        or raw_get(raw, "manager.ip")
        or getattr(alert, "asset_ip", None)
    )


def extract_agent_hostname(alert: Alert) -> Optional[str]:
    raw = alert.raw_payload or {}

    return (
        raw_get(raw, "agent_hostname")
        or raw_get(raw, "agent.hostname")
        or raw_get(raw, "agent.name")
        or raw_get(raw, "host.hostname")
        or raw_get(raw, "host.name")
        or raw_get(raw, "hostname")
        or getattr(alert, "asset_name", None)
    )


def hids_alert_to_dict(alert: Alert) -> dict:
    raw_payload = alert.raw_payload or {}

    agent_ip = extract_agent_ip(alert)
    agent_hostname = extract_agent_hostname(alert)

    return {
        "id": alert.id,
        "source": enum_value(alert.source),
        "severity": enum_value(alert.severity),

        "src_ip": alert.src_ip,
        "dest_ip": alert.dest_ip,
        "src_port": getattr(alert, "src_port", None),
        "dest_port": getattr(alert, "dest_port", None),
        "protocol": getattr(alert, "protocol", None),

        "signature_id": getattr(alert, "signature_id", None),
        "signature_name": getattr(alert, "signature_name", None),
        "category": getattr(alert, "category", None),
        "confidence": getattr(alert, "confidence", None),

        # M12 — machine génératrice / asset
        "agent_ip": agent_ip,
        "agent_hostname": agent_hostname,
        "asset_ip": getattr(alert, "asset_ip", None),
        "asset_name": getattr(alert, "asset_name", None),
        "asset_criticality": getattr(alert, "asset_criticality", None),

        "raw_payload": raw_payload,

        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "detected_at": alert.detected_at.isoformat() if alert.detected_at else None,
        "timestamp": (
            alert.detected_at.isoformat()
            if alert.detected_at
            else alert.created_at.isoformat()
            if alert.created_at
            else None
        ),
    }


def apply_machine_filters(query, agent_ip: Optional[str], asset_ip: Optional[str], hostname: Optional[str]):
    """
    Filtre machine.
    agent_ip : machine qui a généré le log.
    asset_ip : machine concernée par l'alerte.
    hostname : nom machine si disponible.
    """

    if agent_ip:
        query = query.where(
            or_(
                Alert.asset_ip == agent_ip,
                Alert.src_ip == agent_ip,
                Alert.dest_ip == agent_ip,
                Alert.raw_payload["agent_ip"].as_string() == agent_ip,
                Alert.raw_payload["agent"]["ip"].as_string() == agent_ip,
                Alert.raw_payload["agent"]["ip_address"].as_string() == agent_ip,
                Alert.raw_payload["host"]["ip"].as_string() == agent_ip,
            )
        )

    if asset_ip:
        query = query.where(
            or_(
                Alert.asset_ip == asset_ip,
                Alert.src_ip == asset_ip,
                Alert.dest_ip == asset_ip,
                Alert.raw_payload["asset_ip"].as_string() == asset_ip,
            )
        )

    if hostname:
        query = query.where(
            or_(
                Alert.asset_name == hostname,
                Alert.raw_payload["agent_hostname"].as_string() == hostname,
                Alert.raw_payload["agent"]["hostname"].as_string() == hostname,
                Alert.raw_payload["agent"]["name"].as_string() == hostname,
                Alert.raw_payload["host"]["hostname"].as_string() == hostname,
                Alert.raw_payload["host"]["name"].as_string() == hostname,
                Alert.raw_payload["hostname"].as_string() == hostname,
            )
        )

    return query


@router.get("/stats")
async def get_hids_stats(
    hours: int = Query(24, ge=1, le=720),
):
    """
    Stats HIDS/Wazuh.

    Par défaut :
    - affiche les alertes des dernières 24h
    - évite d'afficher un total historique énorme comme 6000+ alertes
    """

    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    async with AsyncSessionLocal() as db:
        base_filter = [
            Alert.source == AlertSource.M11_WAZUH,
            Alert.detected_at >= since,
        ]

        total = await db.scalar(
            select(func.count(Alert.id)).where(*base_filter)
        )

        total_historical = await db.scalar(
            select(func.count(Alert.id)).where(Alert.source == AlertSource.M11_WAZUH)
        )

        by_severity_result = await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(*base_filter)
            .group_by(Alert.severity)
            .order_by(func.count(Alert.id).desc())
        )

        by_rule_result = await db.execute(
            select(Alert.signature_name, func.count(Alert.id))
            .where(*base_filter)
            .group_by(Alert.signature_name)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )

        by_category_result = await db.execute(
            select(Alert.category, func.count(Alert.id))
            .where(*base_filter)
            .group_by(Alert.category)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )

        by_ip_result = await db.execute(
            select(Alert.src_ip, Alert.dest_ip, func.count(Alert.id))
            .where(*base_filter)
            .group_by(Alert.src_ip, Alert.dest_ip)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )

    return {
        "success": True,
        "source": "M11_WAZUH",
        "period_hours": hours,
        "since": since.isoformat(),

        # Nouveau KPI propre pour le dashboard
        "total_alerts": total or 0,

        # Total historique gardé pour audit
        "total_historical": total_historical or 0,

        "by_severity": [
            {
                "severity": enum_value(sev),
                "count": count,
            }
            for sev, count in by_severity_result.all()
        ],
        "top_rules": [
            {
                "signature_name": signature_name or "unknown",
                "count": count,
            }
            for signature_name, count in by_rule_result.all()
        ],
        "top_categories": [
            {
                "category": category or "unknown",
                "count": count,
            }
            for category, count in by_category_result.all()
        ],
        "top_ip_pairs": [
            {
                "src_ip": src_ip or "0.0.0.0",
                "dest_ip": dest_ip or "0.0.0.0",
                "count": count,
            }
            for src_ip, dest_ip, count in by_ip_result.all()
        ],
    }


@router.get("/alerts")
async def get_hids_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),

    # période facultative pour éviter de charger tout l'historique
    hours: Optional[int] = Query(None, ge=1, le=720),

    # filtres machine
    agent_ip: Optional[str] = Query(None),
    asset_ip: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
):
    """
    Liste des alertes HIDS/Wazuh.

    Exemples :
    /api/hids/alerts?limit=100
    /api/hids/alerts?hours=24
    /api/hids/alerts?agent_ip=10.16.2.150
    /api/hids/alerts?hostname=ai-learn
    """

    async with AsyncSessionLocal() as db:
        query = select(Alert).where(Alert.source == AlertSource.M11_WAZUH)
        count_query = select(func.count(Alert.id)).where(Alert.source == AlertSource.M11_WAZUH)

        normalized_severity = normalize_severity(severity)

        if normalized_severity:
            query = query.where(Alert.severity == normalized_severity)
            count_query = count_query.where(Alert.severity == normalized_severity)

        if hours:
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            query = query.where(Alert.detected_at >= since)
            count_query = count_query.where(Alert.detected_at >= since)

        query = apply_machine_filters(query, agent_ip, asset_ip, hostname)
        count_query = apply_machine_filters(count_query, agent_ip, asset_ip, hostname)

        total = await db.scalar(count_query)

        query = (
            query
            .order_by(desc(Alert.id))
            .limit(limit)
            .offset(offset)
        )

        result = await db.execute(query)
        alerts = result.scalars().all()

    return {
        "success": True,
        "total": total or 0,
        "limit": limit,
        "offset": offset,
        "filters": {
            "severity": severity,
            "hours": hours,
            "agent_ip": agent_ip,
            "asset_ip": asset_ip,
            "hostname": hostname,
        },
        "items": [hids_alert_to_dict(alert) for alert in alerts],
    }


@router.get("/agent/status")
async def get_hids_agent_status(
    name: str = Query("ai-learn"),
):
    agents_response = await wazuh_consumer.get_agents()

    if not agents_response or agents_response.get("error") != 0:
        return {
            "success": False,
            "agent": name,
            "status": "unknown",
            "online": False,
            "message": "Impossible de contacter Wazuh Manager",
            "raw": agents_response,
        }

    items = agents_response.get("data", {}).get("affected_items", [])

    matched = None

    for agent in items:
        if agent.get("name") == name:
            matched = agent
            break

    if not matched:
        return {
            "success": True,
            "agent": name,
            "status": "not_found",
            "online": False,
        }

    status = matched.get("status", "unknown")

    return {
        "success": True,
        "agent": name,
        "id": matched.get("id"),
        "ip": matched.get("ip"),
        "status": status,
        "online": status == "active",
        "raw": matched,
    }