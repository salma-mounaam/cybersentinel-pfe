# ============================================================
# M12 — Asset Resolver
# Résolution IP/hostname vers Asset + criticité
# ============================================================

from typing import Optional

from sqlalchemy import select, or_

from app.core.database import AsyncSessionLocal
from app.models.asset import Asset


class AssetResolver:
    async def resolve(self, ip: str = "", hostname: str = "") -> Optional[Asset]:
        ip = (ip or "").strip()
        hostname = (hostname or "").strip()

        if not ip and not hostname:
            return None

        async with AsyncSessionLocal() as db:
            conditions = []

            if ip:
                conditions.append(Asset.ip_address == ip)

            if hostname:
                conditions.append(Asset.hostname == hostname)

            result = await db.execute(
                select(Asset)
                .where(or_(*conditions))
                .limit(1)
            )

            return result.scalar_one_or_none()

    async def get_criticality(self, ip: str = "", hostname: str = "") -> float:
        asset = await self.resolve(ip=ip, hostname=hostname)

        if not asset:
            return 5.0

        try:
            return float(asset.criticality)
        except Exception:
            return 5.0
