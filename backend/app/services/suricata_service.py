# ============================================================
# M1 — Pipeline Suricata Eve JSON
# Lecture temps réel → parsing → DB → Fusion M3
#
# Fix :
#   - Filtrage bruit Suricata technique : STREAM/TCP/UDP/HTTP/DNS/APPLAYER
#   - Filtrage trafic légitime APT/Debian généré par les builds DAST
#   - Déduplication améliorée avec dest_port
#   - Évite de transformer le bruit en WebAttack/CommandInjection
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
from app.services.asset_resolver import AssetResolver

logger = logging.getLogger(__name__)


SEVERITY_MAP = {
    1: SeverityLevel.CRITIQUE,
    2: SeverityLevel.ELEVE,
    3: SeverityLevel.MOYEN,
}


# ============================================================
# Filtrage bruit Suricata
# ============================================================

# Signatures techniques internes Suricata.
# Elles décrivent souvent un problème de décodage/protocole,
# pas une attaque métier exploitable.
NOISE_SIGNATURE_PREFIXES = [
    "SURICATA STREAM",
    "SURICATA TCP",
    "SURICATA UDP",
    "SURICATA ICMP",
    "SURICATA TLS",
    "SURICATA HTTP",
    "SURICATA DNS",
    "SURICATA FRAG",
    "SURICATA APPLAYER",
]

# Signatures informatives/légitimes.
# Important pour ton cas : pendant un build DAST, le backend/target peut faire
# apt-get update / npm / Debian package downloads. Suricata les voit, mais ce
# n’est pas une attaque.
NOISE_SIGNATURE_CONTAINS = [
    "APT USER-AGENT",
    "PACKAGE MANAGEMENT",
    "DEBIAN APT",
    "GNU/LINUX APT",
    "USER-AGENT (APT",
    "USER-AGENT (PYTHON-REQUESTS) OUTBOUND",
    "SOFTWARE UPDATE",
    "OS PACKAGE",
]

# Catégories Suricata généralement non suspectes.
NOISE_CATEGORIES = [
    "NOT SUSPICIOUS TRAFFIC",
    "MISC ACTIVITY",
]

# IP locale du serveur CyberSentinel.
# Sert à filtrer le bruit généré par CyberSentinel lui-même
# vers Internet pendant les builds Docker.
CYBERSENTINEL_LOCAL_IPS = {
    "10.16.2.150",
    "127.0.0.1",
    "::1",
}


DEDUP_WINDOW_SECONDS = 60
_dedup_cache: dict[tuple[str, str, str, str], datetime] = {}


def _is_noise_signature(
    signature: str,
    category: str = "",
    src_ip: str = "",
    dest_ip: str = "",
    dest_port: Optional[int] = None,
) -> bool:
    """
    Retourne True si l'alerte Suricata est considérée comme bruit.

    Objectif :
    - Ne pas stocker/fusionner les alertes techniques Suricata.
    - Ne pas transformer les téléchargements apt/debian du build DAST en WebAttack.
    - Garder les vraies signatures : Nmap, SQLi, XSS, RCE, CVE, brute force, etc.
    """
    sig = (signature or "").upper().strip()
    cat = (category or "").upper().strip()
    src = (src_ip or "").strip()
    dst = (dest_ip or "").strip()

    # 1. Bruit technique Suricata
    if any(sig.startswith(prefix) for prefix in NOISE_SIGNATURE_PREFIXES):
        return True

    # 2. Bruit informatif connu
    if any(token in sig for token in NOISE_SIGNATURE_CONTAINS):
        return True

    # 3. Catégories non suspectes, sauf si la signature indique clairement une attaque
    clear_attack_tokens = [
        "NMAP",
        "SCAN",
        "SQL",
        "SQLI",
        "XSS",
        "CVE",
        "EXPLOIT",
        "RCE",
        "SHELL",
        "BRUTE",
        "HYDRA",
        "MALWARE",
        "TROJAN",
        "BOTNET",
        "C2",
    ]

    if cat in NOISE_CATEGORIES and not any(token in sig for token in clear_attack_tokens):
        return True

    # 4. Trafic sortant du serveur CyberSentinel vers Internet sur 80/443
    # avec signatures informatives. Cela arrive pendant docker build / apt / npm.
    if src in CYBERSENTINEL_LOCAL_IPS and dest_port in {80, 443}:
        if any(token in sig for token in ["ET INFO", "USER-AGENT", "APT", "PACKAGE"]):
            return True

    # 5. Si destination externe connue et signature informative, ignorer.
    # On garde les attaques entrantes vers ai-learn, mais on filtre les sorties
    # de ai-learn vers Internet.
    if src in CYBERSENTINEL_LOCAL_IPS and dst and not dst.startswith("10."):
        if sig.startswith("ET INFO"):
            return True

    return False


def _is_duplicate(
    src_ip: str,
    dest_ip: str,
    signature_name: str,
    dest_port: Optional[int] = None,
) -> bool:
    """
    Déduplication temporelle côté backend.

    Même src/dest/signature/dest_port dans la fenêtre DEDUP_WINDOW_SECONDS
    => ignoré.

    Cela réduit les rafales Suricata sans supprimer l'historique utile sur
    une fenêtre plus longue.
    """
    key = (
        src_ip or "",
        dest_ip or "",
        signature_name or "",
        str(dest_port or ""),
    )

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

        logger.info(
            "PIPELINE_TRACE | START | Suricata watcher actif | eve_path=%s",
            self.eve_path,
        )

        await self._tail_eve_log()

    async def stop(self):
        self._running = False

        if self.redis:
            await self.redis.aclose()

        logger.info("Suricata watcher arrêté")
        logger.info("PIPELINE_TRACE | STOP | Suricata watcher arrêté")

    async def _tail_eve_log(self):
        while not self.eve_path.exists() and self._running:
            logger.warning("eve.json introuvable, attente... (%s)", self.eve_path)
            await asyncio.sleep(5)

        with open(self.eve_path, "r") as f:
            f.seek(0, 2)

            logger.info("eve.json ouvert — écoute des nouvelles alertes")

            logger.info(
                "PIPELINE_TRACE | 0 | eve.json ouvert | path=%s",
                self.eve_path,
            )

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
            logger.warning("PIPELINE_TRACE | X | ligne JSON invalide ignorée")
            return

        logger.info(
            "PIPELINE_TRACE | 1 | eve.json reçu | event_type=%s",
            event.get("event_type"),
        )

        if event.get("event_type") != "alert":
            return

        alert_data = event.get("alert", {})

        if not alert_data:
            logger.warning("PIPELINE_TRACE | X | event alert sans bloc alert ignoré")
            return

        signature_name = alert_data.get("signature", "Unknown")
        category = alert_data.get("category", "")

        src_ip = event.get("src_ip", "")
        dest_ip = event.get("dest_ip", "")
        dest_port = event.get("dest_port")

        logger.info(
            "PIPELINE_TRACE | 2 | alerte Suricata détectée | src=%s dest=%s signature=%s",
            src_ip,
            dest_ip,
            signature_name,
        )

        # ============================================================
        # Filtrage bruit AVANT LLM / MITRE / DB / Fusion
        # ============================================================
        if _is_noise_signature(
            signature=signature_name,
            category=category,
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
        ):
            logger.info(
                "🔇 Bruit Suricata ignoré : signature=%s category=%s src=%s dest=%s dport=%s",
                signature_name,
                category,
                src_ip,
                dest_ip,
                dest_port,
            )

            logger.info(
                "PIPELINE_TRACE | X | bruit Suricata ignoré | signature=%s category=%s",
                signature_name,
                category,
            )

            return

        # ============================================================
        # Déduplication temporelle
        # ============================================================
        if _is_duplicate(src_ip, dest_ip, signature_name, dest_port):
            logger.info(
                "🔁 Doublon ignoré : %s → %s:%s | %s",
                src_ip,
                dest_ip,
                dest_port,
                signature_name,
            )

            logger.info(
                "PIPELINE_TRACE | X | doublon ignoré | src=%s dest=%s dport=%s signature=%s",
                src_ip,
                dest_ip,
                dest_port,
                signature_name,
            )

            return

        alert = await self._build_alert(event, alert_data)

        if not alert:
            logger.error("PIPELINE_TRACE | X | construction Alert échouée")
            return

        logger.info(
            "PIPELINE_TRACE | 3 | Alert construite | severity=%s suricata_score=%.2f attack_type=%s asset=%s C=%.1f",
            alert.severity.value,
            alert.suricata_score or 0.0,
            alert.attack_type or "Unknown",
            alert.asset_name or alert.asset_ip or "Unknown",
            alert.asset_criticality or 5.0,
        )

        alert_id = await self._save_alert(alert)

        if alert_id is None:
            logger.error(
                "❌ Alerte non sauvegardée — src=%s sig=%s",
                alert.src_ip,
                alert.signature_name,
            )

            logger.error(
                "PIPELINE_TRACE | X | sauvegarde DB échouée | src=%s signature=%s",
                alert.src_ip,
                alert.signature_name,
            )

            return

        alert.id = alert_id

        logger.info(
            "PIPELINE_TRACE | 4 | Alert sauvegardée DB | alert_id=%s",
            alert.id,
        )

        logger.info(
            "PIPELINE_TRACE | 5 | Envoi vers M3 Fusion | alert_id=%s",
            alert.id,
        )

        await self.fusion_engine.process_suricata_alert(alert, event)

        logger.info(
            "✅ Alerte M1 traitée | id=%s | %s | %s → %s | asset=%s | C=%.1f | %s | attack_type=%s",
            alert.id,
            alert.severity.value,
            alert.src_ip,
            alert.dest_ip,
            alert.asset_name or alert.asset_ip or "Unknown",
            alert.asset_criticality or 5.0,
            alert.signature_name,
            alert.attack_type or "Unknown",
        )

        logger.info(
            "PIPELINE_TRACE | 12 | Fin pipeline M1→M3 | alert_id=%s",
            alert.id,
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

            logger.info(
                "PIPELINE_TRACE | 2.1 | MITRE extraction | signature_id=%s technique_metadata=%s",
                signature_id,
                technique_id,
            )

            if not technique_id:
                technique_id = self.mitre_engine.resolve_suricata_fallback(
                    signature_id,
                    category,
                )

            logger.info(
                "PIPELINE_TRACE | 2.2 | MITRE fallback/résolution | technique_id=%s category=%s",
                technique_id,
                category,
            )

            mitre_data = await self.mitre_engine.enrich_by_technique_id(technique_id)

            logger.info(
                "PIPELINE_TRACE | 2.3 | MITRE enrichi | technique=%s tactic=%s",
                mitre_data.get("technique_id"),
                mitre_data.get("tactic"),
            )

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

            # ============================================================
            # Asset Registry — résolution machine surveillée / asset réel
            # ============================================================
            agent_hostname = event.get("agent_hostname") or "ai-learn"
            agent_ip = event.get("agent_ip") or event.get("dest_ip") or ""

            resolver = AssetResolver()
            asset = await resolver.resolve(ip=agent_ip, hostname=agent_hostname)

            asset_name = asset.hostname if asset else agent_hostname
            asset_ip = asset.ip_address if asset else agent_ip
            asset_criticality = float(asset.criticality) if asset else 5.0

            logger.info(
                "PIPELINE_TRACE | 2.35 | Asset résolu | agent_hostname=%s agent_ip=%s asset_name=%s asset_ip=%s C=%.1f",
                agent_hostname,
                agent_ip,
                asset_name,
                asset_ip,
                asset_criticality,
            )

            attack_type = "Unknown"
            llm_confidence = 0.0
            llm_reasoning = ""

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
                    source="M1_SURICATA",
                )

                attack_type = classification.get("attack_type", "Unknown")
                llm_confidence = float(classification.get("confidence", 0.0) or 0.0)
                llm_reasoning = classification.get("reasoning", "")

                logger.info(
                    "🤖 LLM | %s → %s | conf=%.2f | %s",
                    signature_name,
                    attack_type,
                    llm_confidence,
                    llm_reasoning,
                )

                logger.info(
                    "PIPELINE_TRACE | 2.4 | LLM classification | signature=%s attack_type=%s confidence=%.2f",
                    signature_name,
                    attack_type,
                    llm_confidence,
                )

            except Exception as e:
                logger.warning("LLM classification ignorée: %s", e)

                logger.warning(
                    "PIPELINE_TRACE | 2.4 | LLM classification ignorée | error=%s",
                    e,
                )

            raw_payload = {
                **event,
                "llm_classification": {
                    "attack_type": attack_type,
                    "confidence": llm_confidence,
                    "reasoning": llm_reasoning,
                },
            }

            return Alert(
                source=AlertSource.M1_SURICATA,
                severity=severity,

                src_ip=event.get("src_ip", ""),
                dest_ip=event.get("dest_ip", ""),
                src_port=event.get("src_port"),
                dest_port=event.get("dest_port"),
                protocol=event.get("proto", "").upper(),

                asset_ip=asset_ip,
                asset_name=asset_name,
                asset_criticality=asset_criticality,

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

                raw_payload=raw_payload,
                detected_at=detected,
            )

        except Exception as e:
            logger.error("Erreur construction alerte: %s", e, exc_info=True)

            logger.error(
                "PIPELINE_TRACE | X | erreur construction Alert | error=%s",
                e,
            )

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

            logger.error(
                "PIPELINE_TRACE | X | erreur insertion PostgreSQL | error=%s",
                e,
            )

            return None