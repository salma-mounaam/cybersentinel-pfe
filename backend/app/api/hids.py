# ============================================================
# M11 — API HIDS / Wazuh
# ============================================================

from typing import Optional

from fastapi import APIRouter, Query
from sqlalchemy import select, func, desc

from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource
from app.services.wazuh_service import WazuhConsumer

router = APIRouter()
wazuh_consumer = WazuhConsumer()


def enum_value(value):
    return value.value if hasattr(value, "value") else str(value)


@router.get("/stats")
async def get_hids_stats():
    async with AsyncSessionLocal() as db:
        total = await db.scalar(
            select(func.count(Alert.id))
            .where(Alert.source == AlertSource.M11_WAZUH)
        )

        by_severity_result = await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.source == AlertSource.M11_WAZUH)
            .group_by(Alert.severity)
            .order_by(func.count(Alert.id).desc())
        )

        by_rule_result = await db.execute(
            select(Alert.signature_name, func.count(Alert.id))
            .where(Alert.source == AlertSource.M11_WAZUH)
            .group_by(Alert.signature_name)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )

        by_category_result = await db.execute(
            select(Alert.category, func.count(Alert.id))
            .where(Alert.source == AlertSource.M11_WAZUH)
            .group_by(Alert.category)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )

        by_ip_result = await db.execute(
            select(Alert.src_ip, Alert.dest_ip, func.count(Alert.id))
            .where(Alert.source == AlertSource.M11_WAZUH)
            .group_by(Alert.src_ip, Alert.dest_ip)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )

    return {
        "success": True,
        "source": "M11_WAZUH",
        "total_alerts": total or 0,
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
):
    async with AsyncSessionLocal() as db:
        query = (
            select(Alert)
            .where(Alert.source == AlertSource.M11_WAZUH)
            .order_by(desc(Alert.id))
            .limit(limit)
            .offset(offset)
        )

        if severity:
            query = (
                select(Alert)
                .where(Alert.source == AlertSource.M11_WAZUH)
                .where(Alert.severity == severity)
                .order_by(desc(Alert.id))
                .limit(limit)
                .offset(offset)
            )

        result = await db.execute(query)
        alerts = result.scalars().all()

        total = await db.scalar(
            select(func.count(Alert.id))
            .where(Alert.source == AlertSource.M11_WAZUH)
        )

    return {
        "success": True,
        "total": total or 0,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": alert.id,
                "source": enum_value(alert.source),
                "severity": enum_value(alert.severity),
                "src_ip": alert.src_ip,
                "dest_ip": alert.dest_ip,
                "signature_id": getattr(alert, "signature_id", None),
                "signature_name": getattr(alert, "signature_name", None),
                "category": getattr(alert, "category", None),
                "confidence": getattr(alert, "confidence", None),
                "created_at": getattr(alert, "created_at", None),
                "detected_at": getattr(alert, "detected_at", None),
                "timestamp": getattr(alert, "timestamp", None),
            }
            for alert in alerts
        ],
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