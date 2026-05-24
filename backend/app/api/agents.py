# ============================================================
# M12 — Agents API
# Heartbeat agents distants + statut des machines
# ============================================================

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, or_

from app.core.database import AsyncSessionLocal
from app.models.asset import Asset

router = APIRouter(prefix="/agents", tags=["Agents"])


class HeartbeatPayload(BaseModel):
    hostname: str
    ip: str
    status: str = "running"
    suricata_status: str | None = None
    wazuh_status: str | None = None
    environment: str = "production"


@router.post("/heartbeat")
async def agent_heartbeat(payload: HeartbeatPayload):
    hostname = (payload.hostname or "").strip()
    ip = (payload.ip or "").strip()

    if not hostname and not ip:
        raise HTTPException(status_code=400, detail="hostname ou ip requis")

    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Asset)
            .where(
                or_(
                    Asset.hostname == hostname,
                    Asset.ip_address == ip,
                )
            )
            .limit(1)
        )

        asset = result.scalar_one_or_none()

        if not asset:
            asset = Asset(
                hostname=hostname,
                ip_address=ip,
                criticality=5.0,
                environment=payload.environment or "production",
                agent_status="active",
                last_heartbeat=now,
                suricata_status=payload.suricata_status,
                wazuh_status=payload.wazuh_status,
                is_monitored=True,
            )
            db.add(asset)
        else:
            asset.hostname = hostname or asset.hostname
            asset.ip_address = ip or asset.ip_address
            asset.agent_status = "active"
            asset.last_heartbeat = now
            asset.suricata_status = payload.suricata_status
            asset.wazuh_status = payload.wazuh_status
            asset.environment = payload.environment or asset.environment or "production"
            asset.is_monitored = True

        await db.commit()
        await db.refresh(asset)

        return {
            "success": True,
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "agent_status": asset.agent_status,
            "last_heartbeat": asset.last_heartbeat.isoformat()
            if asset.last_heartbeat
            else None,
            "suricata_status": asset.suricata_status,
            "wazuh_status": asset.wazuh_status,
        }


@router.get("/status")
async def agents_status():
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(minutes=5)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Asset)
            .where(Asset.is_monitored == True)
            .order_by(Asset.hostname.asc())
        )

        assets = list(result.scalars().all())

    agents = []

    for asset in assets:
        if asset.last_heartbeat:
            if asset.last_heartbeat >= threshold:
                computed_status = "active"
            else:
                computed_status = "offline"
        else:
            computed_status = "unknown"

        agents.append(
            {
                "id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "environment": asset.environment,
                "criticality": asset.criticality,
                "owner": asset.owner,
                "agent_status": computed_status,
                "last_heartbeat": asset.last_heartbeat.isoformat()
                if asset.last_heartbeat
                else None,
                "suricata_status": asset.suricata_status,
                "wazuh_status": asset.wazuh_status,
                "wazuh_agent_id": asset.wazuh_agent_id,
                "tags": asset.tags or [],
                "created_at": asset.created_at.isoformat()
                if asset.created_at
                else None,
                "updated_at": asset.updated_at.isoformat()
                if asset.updated_at
                else None,
            }
        )

    return {
        "summary": {
            "total": len(agents),
            "active": sum(1 for a in agents if a["agent_status"] == "active"),
            "offline": sum(1 for a in agents if a["agent_status"] == "offline"),
            "unknown": sum(1 for a in agents if a["agent_status"] == "unknown"),
        },
        "agents": agents,
    }