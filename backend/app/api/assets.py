# ============================================================
# M12 — API Asset Registry
# Gestion des machines surveillées + heartbeat agents
# ============================================================

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.asset import Asset

router = APIRouter()


class AssetCreate(BaseModel):
    hostname: str
    ip_address: str
    environment: Optional[str] = "unknown"
    criticality: float = Field(default=5.0, ge=0.0, le=10.0)
    owner: Optional[str] = None
    agent_status: Optional[str] = "unknown"
    wazuh_agent_id: Optional[str] = None
    tags: Optional[List[str]] = []


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    owner: Optional[str] = None
    agent_status: Optional[str] = None
    wazuh_agent_id: Optional[str] = None
    tags: Optional[List[str]] = None


class HeartbeatPayload(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    suricata_status: Optional[str] = None
    wazuh_status: Optional[str] = None
    agent_status: Optional[str] = "active"


def serialize_asset(asset: Asset) -> Dict[str, Any]:
    return {
        "id": asset.id,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "environment": asset.environment,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "agent_status": asset.agent_status,
        "last_heartbeat": asset.last_heartbeat.isoformat() if asset.last_heartbeat else None,
        "wazuh_agent_id": asset.wazuh_agent_id,
        "tags": asset.tags or [],
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
    }


@router.get("/assets")
async def get_assets():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Asset).order_by(Asset.criticality.desc(), Asset.hostname.asc())
        )
        assets = result.scalars().all()

        return {
            "count": len(assets),
            "assets": [serialize_asset(a) for a in assets],
        }


@router.post("/assets")
async def create_asset(payload: AssetCreate):
    async with AsyncSessionLocal() as db:
        existing = await db.execute(
            select(Asset).where(Asset.hostname == payload.hostname).limit(1)
        )
        existing_asset = existing.scalar_one_or_none()

        if existing_asset:
            raise HTTPException(
                status_code=409,
                detail=f"Asset déjà existant avec hostname={payload.hostname}",
            )

        asset = Asset(
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            environment=payload.environment,
            criticality=payload.criticality,
            owner=payload.owner,
            agent_status=payload.agent_status,
            wazuh_agent_id=payload.wazuh_agent_id,
            tags=payload.tags or [],
        )

        db.add(asset)
        await db.commit()
        await db.refresh(asset)

        return {
            "success": True,
            "asset": serialize_asset(asset),
        }


@router.patch("/assets/{asset_id}")
async def update_asset(asset_id: int, payload: AssetUpdate):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Asset).where(Asset.id == asset_id).limit(1)
        )
        asset = result.scalar_one_or_none()

        if not asset:
            raise HTTPException(
                status_code=404,
                detail=f"Asset introuvable id={asset_id}",
            )

        data = payload.model_dump(exclude_unset=True)

        for key, value in data.items():
            setattr(asset, key, value)

        await db.commit()
        await db.refresh(asset)

        return {
            "success": True,
            "asset": serialize_asset(asset),
        }


@router.get("/assets/at-risk")
async def get_assets_at_risk():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Asset)
            .where(
                (Asset.criticality >= 7.0) |
                (Asset.agent_status == "offline")
            )
            .order_by(Asset.criticality.desc())
        )

        assets = result.scalars().all()

        return {
            "count": len(assets),
            "assets": [serialize_asset(a) for a in assets],
        }


@router.post("/agents/heartbeat")
async def agent_heartbeat(payload: HeartbeatPayload):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Asset)
            .where(
                (Asset.hostname == payload.hostname) |
                (Asset.ip_address == payload.ip_address)
            )
            .limit(1)
        )

        asset = result.scalar_one_or_none()

        if not asset:
            raise HTTPException(
                status_code=404,
                detail=f"Asset introuvable pour hostname={payload.hostname}",
            )

        asset.last_heartbeat = datetime.now(timezone.utc)
        asset.agent_status = payload.agent_status or "active"

        if payload.ip_address:
            asset.ip_address = payload.ip_address

        await db.commit()
        await db.refresh(asset)

        return {
            "success": True,
            "message": "Heartbeat reçu",
            "asset": serialize_asset(asset),
            "suricata_status": payload.suricata_status,
            "wazuh_status": payload.wazuh_status,
        }


@router.get("/agents/status")
async def get_agents_status():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Asset).order_by(Asset.hostname.asc())
        )

        assets = result.scalars().all()

        total = len(assets)
        active = len([a for a in assets if a.agent_status == "active"])
        offline = len([a for a in assets if a.agent_status == "offline"])
        unknown = len([a for a in assets if a.agent_status == "unknown"])

        return {
            "summary": {
                "total": total,
                "active": active,
                "offline": offline,
                "unknown": unknown,
            },
            "agents": [serialize_asset(a) for a in assets],
        }
