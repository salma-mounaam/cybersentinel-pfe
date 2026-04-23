# ============================================================
# M1 — Pipeline Suricata Eve JSON
# Lecture temps réel → parsing → DB → Redis Pub/Sub
# ============================================================

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource, SeverityLevel
from app.services.mitre_service import MitreEnrichmentEngine
from app.services.ml_service import MLAnomalyEngine
from app.services.fusion_service import FusionEngine

logger = logging.getLogger(__name__)

# Mapping sévérité Suricata (1,2,3) → SeverityLevel
SEVERITY_MAP = {
    1: SeverityLevel.CRITIQUE,
    2: SeverityLevel.ELEVE,
    3: SeverityLevel.MOYEN,
}


class SuricataEveWatcher:
    """
    Lit le fichier eve.json de Suricata en continu.
    Chaque nouvelle ligne = une alerte à traiter.
    """

    def __init__(self):
        self.eve_path = Path(settings.SURICATA_EVE_LOG)
        self.mitre_engine = MitreEnrichmentEngine()
        self.ml_engine = MLAnomalyEngine()
        self.redis: Optional[aioredis.Redis] = None
        self._running = False
        self.fusion_engine = FusionEngine()

    async def start(self):
        """Point d'entrée — démarre la boucle de lecture."""
        self.redis = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        self._running = True
        logger.info(f"👁️  Suricata watcher démarré — {self.eve_path}")
        await self._tail_eve_log()

    async def stop(self):
        self._running = False
        if self.redis:
            await self.redis.aclose()
        logger.info("Suricata watcher arrêté")

    async def _tail_eve_log(self):
        """
        Simule un 'tail -f' sur eve.json.
        Attend l'apparition du fichier si absent (Suricata pas encore démarré).
        """
        # Attendre que le fichier existe
        while not self.eve_path.exists() and self._running:
            logger.warning(f"eve.json introuvable, attente... ({self.eve_path})")
            await asyncio.sleep(5)

        with open(self.eve_path, "r") as f:
            # Aller à la fin du fichier (ignorer l'historique)
            f.seek(0, 2)
            logger.info("eve.json ouvert — écoute des nouvelles alertes")

            while self._running:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.1)  # Pause 100ms si pas de nouvelle ligne
                    continue

                await self._process_line(line.strip())

    async def _process_line(self, line: str):
        """Parse et traite une ligne JSON de eve.json."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return  # Ligne malformée, on ignore

        # On ne traite que les événements de type "alert"
        if event.get("event_type") != "alert":
            return

        alert_data = event.get("alert", {})
        if not alert_data:
            return

        # Construire l'objet alerte
        alert = await self._build_alert(event, alert_data)
        if not alert:
            return

        # Sauvegarder en base
        alert_id = await self._save_alert(alert)
        # Appeler M3 — Fusion Hybride
        if alert_id and alert:
            alert.id = alert_id
            await self.fusion_engine.process_suricata_alert(alert, event)
        else:
            return
        # Publier dans Redis pour le WebSocket (M9)
        await self._publish_to_redis(alert, alert_id)

        logger.info(
            f"✅ Alerte M1 traitée | "
            f"{alert.severity} | {alert.src_ip} → {alert.dest_ip} | "
            f"{alert.signature_name}"
        )

    async def _build_alert(self, event: dict, alert_data: dict) -> Optional[Alert]:
        """Construit un objet Alert depuis l'événement Suricata."""
        try:
            # Sévérité Suricata → SeverityLevel
            suricata_severity = alert_data.get("severity", 3)
            severity = SEVERITY_MAP.get(suricata_severity, SeverityLevel.MOYEN)

            # Extraction signature_id pour lookup MITRE
            signature_id = alert_data.get("signature_id", 0)
            signature_name = alert_data.get("signature", "Unknown")

            # Métadonnées MITRE pré-enrichies dans la règle
            metadata = alert_data.get("metadata", {})
            technique_id = None
            if isinstance(metadata, dict):
                technique_id = metadata.get("mitre_technique")
            elif isinstance(metadata, list):
                # Certaines règles ET Open encodent metadata en liste
                for item in metadata:
                    if "mitre_technique" in item:
                        technique_id = item.split("=")[-1].strip()
                        break

            # Si pas de technique dans la règle → lookup via M6
            if not technique_id:
                technique_id = self.mitre_engine.resolve_suricata_fallback(
                    signature_id, alert_data.get("category", "")
                )

            # Enrichissement MITRE complet
            mitre_data = await self.mitre_engine.enrich_by_technique_id(technique_id)

            # Score Suricata normalisé [0-1]
            # Sévérité 1 → 1.0, 2 → 0.70, 3 → 0.40
            suricata_score = {1: 1.0, 2: 0.70, 3: 0.40}.get(suricata_severity, 0.40)

            alert = Alert(
                source=AlertSource.M1_SURICATA,
                severity=severity,

                # Réseau
                src_ip=event.get("src_ip", ""),
                dest_ip=event.get("dest_ip", ""),
                src_port=event.get("src_port"),
                dest_port=event.get("dest_port"),
                protocol=event.get("proto", "").upper(),

                # Suricata
                signature_id=signature_id,
                signature_name=signature_name,
                category=alert_data.get("category", ""),
                suricata_score=suricata_score,

                # ML (sera mis à jour par M3 après scoring ML)
                ml_score=0.0,

                # Fusion (sera calculé par M3)
                confidence=suricata_score * 0.40,  # Contribution S seule pour l'instant
                fusion_case=3,  # Cas 3 par défaut (signature seule)

                # MITRE
                technique_id=mitre_data.get("technique_id"),
                technique_name=mitre_data.get("technique_name"),
                tactic=mitre_data.get("tactic"),
                apt_groups=mitre_data.get("apt_groups", []),

                # Payload brut
                raw_payload=event,

                detected_at=datetime.fromisoformat(
                    event.get("timestamp", datetime.utcnow().isoformat())
                    .replace("Z", "+00:00")
                )
            )
            return alert

        except Exception as e:
            logger.error(f"Erreur construction alerte: {e}")
            return None

    async def _save_alert(self, alert: Alert) -> Optional[int]:
        """Insère l'alerte en PostgreSQL."""
        try:
            async with AsyncSessionLocal() as session:
                session.add(alert)
                await session.commit()
                await session.refresh(alert)
                return alert.id
        except Exception as e:
            logger.error(f"Erreur insertion PostgreSQL: {e}")
            return None

    async def _publish_to_redis(self, alert: Alert, alert_id: int):
        """
        Publie l'alerte dans Redis pour :
        1. Sorted Set (cache dashboard, TTL 1h)
        2. Pub/Sub channel (WebSocket temps réel M9)
        """
        payload = {
            "id": alert_id,
            "source": alert.source.value,
            "severity": alert.severity.value,
            "src_ip": alert.src_ip,
            "dest_ip": alert.dest_ip,
            "protocol": alert.protocol,
            "signature_name": alert.signature_name,
            "technique_id": alert.technique_id,
            "technique_name": alert.technique_name,
            "tactic": alert.tactic,
            "confidence": round(alert.confidence, 3),
            "detected_at": alert.detected_at.isoformat() if alert.detected_at else None,
        }
        payload_json = json.dumps(payload)

        # 1. Sorted Set avec TTL 1h (score = timestamp)
        score = datetime.utcnow().timestamp()
        await self.redis.zadd("alerts:recent", {payload_json: score})
        await self.redis.expire("alerts:recent", 3600)

        # 2. Pub/Sub → WebSocket M9
        await self.redis.publish("channel:alerts", payload_json)
