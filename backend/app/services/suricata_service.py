# ============================================================
# M1 — Pipeline Suricata Eve JSON
# Lecture temps réel → parsing → DB → Fusion M3
# ============================================================

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource, SeverityLevel
from app.services.mitre_service import MitreEnrichmentEngine
from app.services.ml_service import MLAnomalyEngine
from app.services.fusion_service import FusionEngine
from app.services.attack_classifier import classify_attack_with_llm

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    1: SeverityLevel.CRITIQUE,
    2: SeverityLevel.ELEVE,
    3: SeverityLevel.MOYEN,
}

NOISE_SIGNATURE_PREFIXES = [
    "SURICATA STREAM",
    "SURICATA TCP",
    "SURICATA UDP",
    "SURICATA ICMP",
    "SURICATA TLS",
    "SURICATA HTTP",
    "SURICATA DNS",
    "SURICATA FRAG",
]

DEDUP_WINDOW_SECONDS = 30
_dedup_cache: dict[tuple[str, str, str], datetime] = {}


def _is_noise_signature(signature: str) -> bool:
    sig = (signature or "").upper().strip()
    return any(sig.startswith(prefix) for prefix in NOISE_SIGNATURE_PREFIXES)


def _is_duplicate(src_ip: str, dest_ip: str, signature_name: str) -> bool:
    key = (src_ip or "", dest_ip or "", signature_name or "")
    now = datetime.now(timezone.utc)

    last_seen = _dedup_cache.get(key)
    if last_seen and (now - last_seen).total_seconds() < DEDUP_WINDOW_SECONDS:
        return True

    _dedup_cache[key] = now

    expired = [
        k for k, v in _dedup_cache.items()
        if (now - v).total_seconds() > DEDUP_WINDOW_SECONDS * 2
    ]
    for k in expired:
        _dedup_cache.pop(k, None)

    return False


def _parse_suricata_timestamp(raw: str) -> datetime:
    try:
        from dateutil import parser as dtparser

        dt = dtparser.parse(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        logger.warning("Timestamp Suricata non parsable : %r", raw)
        return datetime.now(timezone.utc)


def _extract_technique_from_metadata(metadata) -> Optional[str]:
    if not metadata:
        return None

    if isinstance(metadata, dict):
        return metadata.get("mitre_technique") or metadata.get("mitre_technique_id")

    if isinstance(metadata, list):
        for item in metadata:
            if isinstance(item, dict):
                val = item.get("mitre_technique") or item.get("mitre_technique_id")
                if val:
                    return str(val).strip()
            elif isinstance(item, str) and "mitre_technique" in item:
                return item.replace("=", " ").split()[-1].strip()

    return None


class SuricataEveWatcher:
    def __init__(self):
        self.eve_path = Path(settings.SURICATA_EVE_LOG)
        self.mitre_engine = MitreEnrichmentEngine()
        self.ml_engine = MLAnomalyEngine()
        self.fusion_engine = FusionEngine()
        self.redis: Optional[aioredis.Redis] = None
        self._running = False

    async def start(self):
        self.redis = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        self._running = True
        logger.info("👁️ Suricata watcher démarré — %s", self.eve_path)
        await self._tail_eve_log()

    async def stop(self):
        self._running = False
        if self.redis:
            await self.redis.aclose()
        logger.info("Suricata watcher arrêté")

    async def _tail_eve_log(self):
        while not self.eve_path.exists() and self._running:
            logger.warning("eve.json introuvable, attente... (%s)", self.eve_path)
            await asyncio.sleep(5)

        with open(self.eve_path, "r") as f:
            f.seek(0, 2)
            logger.info("eve.json ouvert — écoute des nouvelles alertes")

            while self._running:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.1)
                    continue

                await self._process_line(line.strip())

    async def _process_line(self, line: str):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return

        if event.get("event_type") != "alert":
            return

        alert_data = event.get("alert", {})
        if not alert_data:
            return

        signature_name = alert_data.get("signature", "Unknown")
        src_ip = event.get("src_ip", "")
        dest_ip = event.get("dest_ip", "")

        if _is_noise_signature(signature_name):
            logger.info("🔇 Bruit Suricata ignoré : %s", signature_name)
            return

        if _is_duplicate(src_ip, dest_ip, signature_name):
            logger.info("🔁 Doublon ignoré : %s → %s | %s", src_ip, dest_ip, signature_name)
            return

        alert = await self._build_alert(event, alert_data)
        if not alert:
            return

        alert_id = await self._save_alert(alert)

        if alert_id is None:
            logger.error(
                "❌ Alerte non sauvegardée — src=%s sig=%s",
                alert.src_ip,
                alert.signature_name,
            )
            return

        alert.id = alert_id

        await self.fusion_engine.process_suricata_alert(alert, event)

        logger.info(
            "✅ Alerte M1 traitée | id=%s | %s | %s → %s | %s | attack_type=%s",
            alert.id,
            alert.severity.value,
            alert.src_ip,
            alert.dest_ip,
            alert.signature_name,
            alert.attack_type or "Unknown",
        )

    async def _build_alert(self, event: dict, alert_data: dict) -> Optional[Alert]:
        try:
            suricata_severity = alert_data.get("severity", 3)
            severity = SEVERITY_MAP.get(suricata_severity, SeverityLevel.MOYEN)

            signature_id = alert_data.get("signature_id", 0)
            signature_name = alert_data.get("signature", "Unknown")
            category = alert_data.get("category", "")

            raw_metadata = alert_data.get("metadata", {})
            technique_id = _extract_technique_from_metadata(raw_metadata)

            if not technique_id:
                technique_id = self.mitre_engine.resolve_suricata_fallback(
                    signature_id,
                    category,
                )

            mitre_data = await self.mitre_engine.enrich_by_technique_id(technique_id)

            suricata_score = {
                1: 1.0,
                2: 0.70,
                3: 0.40,
            }.get(suricata_severity, 0.40)

            raw_ts = event.get("timestamp", "")
            detected = (
                _parse_suricata_timestamp(raw_ts)
                if raw_ts
                else datetime.now(timezone.utc)
            )

            attack_type = "Unknown"

            try:
                classification = await classify_attack_with_llm(
                    signature_name=signature_name,
                    category=category,
                    src_ip=event.get("src_ip", ""),
                    dest_ip=event.get("dest_ip", ""),
                    dest_port=event.get("dest_port", 0),
                    protocol=event.get("proto", ""),
                    technique_id=technique_id,
                    tactic=mitre_data.get("tactic"),
                )

                attack_type = classification.get("attack_type", "Unknown")

                logger.info(
                    "🤖 LLM | %s → %s | conf=%.2f | %s",
                    signature_name,
                    attack_type,
                    classification.get("confidence", 0),
                    classification.get("reasoning", ""),
                )

            except Exception as e:
                logger.warning("LLM classification ignorée: %s", e)

            return Alert(
                source=AlertSource.M1_SURICATA,
                severity=severity,

                src_ip=event.get("src_ip", ""),
                dest_ip=event.get("dest_ip", ""),
                src_port=event.get("src_port"),
                dest_port=event.get("dest_port"),
                protocol=event.get("proto", "").upper(),

                signature_id=signature_id,
                signature_name=signature_name,
                category=category,
                attack_type=attack_type,
                suricata_score=suricata_score,

                ml_score=0.0,
                confidence=suricata_score * 0.40,
                fusion_case=3,

                technique_id=mitre_data.get("technique_id"),
                technique_name=mitre_data.get("technique_name"),
                tactic=mitre_data.get("tactic"),
                apt_groups=mitre_data.get("apt_groups", []),

                raw_payload=event,
                detected_at=detected,
            )

        except Exception as e:
            logger.error("Erreur construction alerte: %s", e, exc_info=True)
            return None

    async def _save_alert(self, alert: Alert) -> Optional[int]:
        try:
            async with AsyncSessionLocal() as session:
                session.add(alert)
                await session.commit()
                await session.refresh(alert)
                return alert.id
        except Exception as e:
            logger.error("Erreur insertion PostgreSQL: %s", e, exc_info=True)
            return None