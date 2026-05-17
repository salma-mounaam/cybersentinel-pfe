# ============================================================
# M7 — Consommateur Redis pour création automatique d'incidents
# Écoute channel:incident_requests publié par M3
# ============================================================

import json
import logging
from typing import Optional

import redis.asyncio as aioredis
from sqlalchemy import select

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert
from app.services.scoring_service import RiskScoringEngine

logger = logging.getLogger(__name__)


class IncidentConsumer:
    """
    Écoute le channel Redis 'channel:incident_requests'.
    Crée automatiquement les incidents depuis les alertes fusionnées.

    Supporte maintenant :
    - dast_confirmed
    - hids_confirmed

    Ces deux flags sont utilisés pour alimenter le composant E du score R.
    """

    def __init__(self):
        self.scoring_engine = RiskScoringEngine()
        self.redis: Optional[aioredis.Redis] = None
        self._running = False

    async def start(self):
        self.redis = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        self._running = True
        logger.info("📥 Incident consumer démarré")
        await self._consume()

    async def stop(self):
        self._running = False
        if self.redis:
            await self.redis.aclose()

    async def _consume(self):
        """Boucle de consommation Redis Pub/Sub."""
        pubsub = self.redis.pubsub()
        await pubsub.subscribe("channel:incident_requests")

        async for message in pubsub.listen():
            if not self._running:
                break

            if message["type"] != "message":
                continue

            try:
                data = json.loads(message["data"])
                await self._process_incident_request(data)

            except Exception as e:
                logger.error(
                    "Erreur traitement incident: %s",
                    e,
                    exc_info=True,
                )

    async def _process_incident_request(self, data: dict):
        """
        Traite une demande de création d'incident.

        Format attendu depuis M3 :
        {
            "alert_id": 123,
            "dast_confirmed": true/false,
            "hids_confirmed": true/false
        }
        """
        alert_id = data.get("alert_id")

        if not alert_id:
            logger.warning("Message incident ignoré: alert_id absent")
            return

        dast_confirmed = bool(data.get("dast_confirmed", False))
        hids_confirmed = bool(data.get("hids_confirmed", False))

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Alert).where(Alert.id == alert_id)
            )
            alert = result.scalar_one_or_none()

        if not alert:
            logger.warning("Alerte #%s introuvable pour incident", alert_id)
            return

        # On attache les flags au runtime.
        # Le modèle Alert n'a pas besoin d'avoir des colonnes hids_confirmed/dast_confirmed.
        setattr(alert, "_cybersentinel_dast_confirmed", dast_confirmed)
        setattr(alert, "_cybersentinel_hids_confirmed", hids_confirmed)

        logger.info(
            "Incident request reçu | alert_id=%s | dast_confirmed=%s | hids_confirmed=%s",
            alert_id,
            dast_confirmed,
            hids_confirmed,
        )

        incident = await self.scoring_engine.create_incident_from_alert(alert)

        if incident:
            logger.info(
                "✅ Incident #%s créé automatiquement depuis alerte #%s | R=%s | E=%s | hids_confirmed=%s",
                incident.id,
                alert_id,
                incident.score_r,
                getattr(incident, "score_e", None),
                hids_confirmed,
            )