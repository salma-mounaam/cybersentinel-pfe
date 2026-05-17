# ============================================================
# M3 — Moteur de Fusion Hybride
# Confidence = 0.40*S + 0.30*M + 0.30*C
# Fenêtre temporelle 5 secondes par hôte source
# Corrélation M11 — HIDS/Wazuh sur fenêtre ±60 secondes
# ============================================================

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
from collections import defaultdict

import redis.asyncio as aioredis
from sqlalchemy import select, func, or_

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource, SeverityLevel
from app.services.ml_service import MLAnomalyEngine
from app.services.mitre_service import MitreEnrichmentEngine

logger = logging.getLogger(__name__)

W_S = 0.40
W_M = 0.30
W_C = 0.30

TEMPORAL_WINDOW = 5
HIDS_CORRELATION_WINDOW = 60

CONFIDENCE_LEVELS = [
    (0.90, SeverityLevel.CRITIQUE),
    (0.75, SeverityLevel.ELEVE),
    (0.50, SeverityLevel.MOYEN),
    (0.00, SeverityLevel.FAIBLE),
]

FUSION_CASES = {
    1: {"label": "Signature + ML + contexte fort", "confidence": 0.95},
    2: {"label": "Signature + ML", "confidence": 0.85},
    3: {"label": "Signature seule", "confidence": 0.70},
    4: {"label": "ML seul", "confidence": 0.60},
    5: {"label": "Bruit — ignoré", "confidence": 0.00},
}


class FusionEngine:
    def __init__(self):
        self.ml_engine = MLAnomalyEngine()
        self.mitre_engine = MitreEnrichmentEngine()
        self.redis: Optional[aioredis.Redis] = None
        self._temporal_window: Dict[str, list] = defaultdict(list)

    async def _get_redis(self) -> aioredis.Redis:
        if not self.redis:
            self.redis = await aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info("PIPELINE_TRACE | REDIS | connexion Redis initialisée")
        return self.redis

    # ========================================================
    # M11 — Corrélation HIDS / Wazuh
    # ========================================================
    async def _check_hids_correlation(
        self,
        asset_ip: str,
        timestamp: datetime,
    ) -> bool:
        """
        Vérifie si Wazuh a émis une alerte sur le même asset
        dans une fenêtre de ±60 secondes autour du timestamp.

        Version corrigée :
        - n'utilise pas Alert.asset_ip
        - n'utilise pas Alert.timestamp
        - utilise uniquement les colonnes existantes :
          src_ip, dest_ip, detected_at, created_at
        """
        if not asset_ip:
            return False

        try:
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            window = timedelta(seconds=HIDS_CORRELATION_WINDOW)
            start_time = timestamp - window
            end_time = timestamp + window

            async with AsyncSessionLocal() as db:
                result = await db.scalar(
                    select(func.count(Alert.id))
                    .where(Alert.source == AlertSource.M11_WAZUH)
                    .where(
                        or_(
                            Alert.src_ip == asset_ip,
                            Alert.dest_ip == asset_ip,
                        )
                    )
                    .where(
                        or_(
                            Alert.detected_at.between(start_time, end_time),
                            Alert.created_at.between(start_time, end_time),
                        )
                    )
                )

            confirmed = (result or 0) > 0

            logger.info(
                "M3 Fusion | Corrélation HIDS | asset_ip=%s window=%ss confirmed=%s count=%s",
                asset_ip,
                HIDS_CORRELATION_WINDOW,
                confirmed,
                result or 0,
            )

            return confirmed

        except Exception as exc:
            logger.warning(
                "M3 Fusion | Erreur corrélation HIDS | asset_ip=%s error=%s",
                asset_ip,
                exc,
            )
            return False

    async def process_suricata_alert(self, alert: Alert, raw_event: dict) -> Alert:
        try:
            logger.info(
                f"M3 Fusion | Début traitement Suricata | "
                f"alert_id={getattr(alert, 'id', None)} "
                f"src={getattr(alert, 'src_ip', None)} "
                f"dest={getattr(alert, 'dest_ip', None)} "
                f"signature={getattr(alert, 'signature_name', None)} "
                f"attack_type={getattr(alert, 'attack_type', None)}"
            )

            logger.info(
                "PIPELINE_TRACE | 6 | M3 reçu | alert_id=%s src=%s dest=%s signature=%s",
                getattr(alert, "id", None),
                getattr(alert, "src_ip", None),
                getattr(alert, "dest_ip", None),
                getattr(alert, "signature_name", None),
            )

            if alert.suricata_score is None or alert.suricata_score == 0:
                alert.suricata_score = 0.70
                logger.info(
                    f"M3 Fusion | suricata_score absent → forcé à 0.70 | "
                    f"alert_id={alert.id}"
                )

            logger.info(
                "PIPELINE_TRACE | 6.1 | Score Suricata prêt | alert_id=%s suricata_score=%.4f",
                alert.id,
                alert.suricata_score or 0.0,
            )

            ml_result = await self.ml_engine.score_event(raw_event)
            ml_score = ml_result["ensemble_score"] if ml_result else 0.0

            logger.info(
                "PIPELINE_TRACE | 7 | ML terminé | alert_id=%s ml_score=%.4f if=%s ae=%s ocsvm=%s is_anomaly=%s threshold=%s",
                alert.id,
                ml_score,
                ml_result.get("if_score") if ml_result else None,
                ml_result.get("ae_score") if ml_result else None,
                ml_result.get("ocsvm_score") if ml_result else None,
                ml_result.get("is_anomaly") if ml_result else None,
                ml_result.get("decision_threshold") if ml_result else None,
            )

            context_score = self._compute_context_score(
                alert.src_ip,
                alert.detected_at or datetime.now(timezone.utc),
            )

            logger.info(
                "PIPELINE_TRACE | 8 | Contexte calculé | alert_id=%s src=%s context_score=%.2f",
                alert.id,
                alert.src_ip,
                context_score,
            )

            fusion_case = self._determine_case(
                s_score=alert.suricata_score or 0.0,
                m_score=ml_score,
                c_score=context_score,
            )

            logger.info(
                "PIPELINE_TRACE | 8.1 | Cas fusion calculé | alert_id=%s S=%.4f M=%.4f C=%.4f case=%s label=%s",
                alert.id,
                alert.suricata_score or 0.0,
                ml_score,
                context_score,
                fusion_case,
                FUSION_CASES.get(fusion_case, {}).get("label", "Unknown"),
            )

            if fusion_case == 5:
                logger.info(
                    f"M3 Fusion | Cas 5 ignoré | "
                    f"alert_id={alert.id} "
                    f"S={(alert.suricata_score or 0.0):.4f} "
                    f"M={ml_score:.4f} "
                    f"C={context_score:.4f} "
                    f"src={alert.src_ip}"
                )

                logger.info(
                    "PIPELINE_TRACE | X | Cas 5 bruit ignoré | alert_id=%s S=%.4f M=%.4f C=%.4f",
                    alert.id,
                    alert.suricata_score or 0.0,
                    ml_score,
                    context_score,
                )

                return alert

            confidence = (
                W_S * (alert.suricata_score or 0.0)
                + W_M * ml_score
                + W_C * context_score
            )
            confidence = round(min(confidence, 1.0), 4)

            severity = self._confidence_to_severity(confidence)

            logger.info(
                "PIPELINE_TRACE | 9 | Fusion décidée | alert_id=%s case=%s confidence=%.4f severity=%s",
                alert.id,
                fusion_case,
                confidence,
                severity.value,
            )

            alert.ml_score = round(ml_score, 4)
            alert.confidence = confidence
            alert.fusion_case = fusion_case
            alert.severity = severity
            alert.source = AlertSource.M3_FUSION

            if ml_result:
                alert.if_score = ml_result.get("if_score")
                alert.ocsvm_score = ml_result.get("ocsvm_score")
                alert.ae_score = ml_result.get("ae_score")

            await self._update_alert(alert)

            logger.info(
                "PIPELINE_TRACE | 10 | DB mise à jour après fusion | alert_id=%s ml_score=%.4f confidence=%.4f case=%s",
                alert.id,
                alert.ml_score or 0.0,
                alert.confidence or 0.0,
                alert.fusion_case,
            )

            try:
                await self._publish_fused_alert(alert)

                logger.info(
                    "PIPELINE_TRACE | 10.1 | Redis channel:alerts publié | alert_id=%s",
                    alert.id,
                )

            except Exception:
                logger.exception(
                    "M3 Fusion | Redis channel:alerts échoué, mais incident continue"
                )
                logger.exception(
                    "PIPELINE_TRACE | X | Redis channel:alerts échoué | alert_id=%s",
                    alert.id,
                )

            await self._trigger_incident_creation(alert)

            logger.info(
                "PIPELINE_TRACE | 11 | Incident demandé | alert_id=%s severity=%s confidence=%.4f",
                alert.id,
                alert.severity.value,
                alert.confidence or 0.0,
            )

            logger.info(
                f"M3 Fusion | Cas {fusion_case} | "
                f"S={(alert.suricata_score or 0.0):.4f} "
                f"M={ml_score:.4f} "
                f"C={context_score:.4f} → "
                f"Confiance={confidence:.4f} | {severity.value} | "
                f"attack_type={alert.attack_type or 'Unknown'}"
            )

            return alert

        except Exception:
            logger.exception(
                f"M3 Fusion | CRASH process_suricata_alert | "
                f"alert_id={getattr(alert, 'id', None)} "
                f"src={getattr(alert, 'src_ip', None)} "
                f"dest={getattr(alert, 'dest_ip', None)}"
            )
            logger.exception(
                "PIPELINE_TRACE | X | CRASH M3 process_suricata_alert | alert_id=%s",
                getattr(alert, "id", None),
            )
            raise

    def _determine_case(self, s_score: float, m_score: float, c_score: float) -> int:
        has_signature = s_score >= 0.39
        has_ml = m_score >= 0.50

        if has_signature and has_ml and c_score >= 0.90:
            return 1
        elif has_signature and has_ml:
            return 2
        elif has_signature:
            return 3
        elif has_ml:
            return 4
        else:
            return 5

    def _compute_context_score(self, src_ip: str, timestamp: datetime) -> float:
        if not src_ip:
            return 0.0

        now = timestamp
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        window_start = now - timedelta(seconds=TEMPORAL_WINDOW)

        self._temporal_window[src_ip] = [
            t for t in self._temporal_window[src_ip]
            if t > window_start
        ]

        self._temporal_window[src_ip].append(now)

        count = len(self._temporal_window[src_ip])
        score = min((count - 1) * 0.30, 1.0)

        logger.info(
            "PIPELINE_TRACE | 8.0 | Fenêtre temporelle | src=%s count=%s score=%.2f",
            src_ip,
            count,
            score,
        )

        return round(score, 2)

    def _confidence_to_severity(self, confidence: float) -> SeverityLevel:
        for threshold, severity in CONFIDENCE_LEVELS:
            if confidence >= threshold:
                return severity
        return SeverityLevel.FAIBLE

    async def _update_alert(self, alert: Alert):
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(Alert).where(Alert.id == alert.id)
                )
                db_alert = result.scalar_one_or_none()

                if not db_alert:
                    logger.warning(
                        f"M3 Fusion | Alerte introuvable en DB | alert_id={alert.id}"
                    )
                    logger.warning(
                        "PIPELINE_TRACE | X | Alerte introuvable DB | alert_id=%s",
                        alert.id,
                    )
                    return

                db_alert.ml_score = alert.ml_score
                db_alert.confidence = alert.confidence
                db_alert.fusion_case = alert.fusion_case
                db_alert.severity = alert.severity
                db_alert.source = alert.source
                db_alert.if_score = alert.if_score
                db_alert.ocsvm_score = alert.ocsvm_score
                db_alert.ae_score = alert.ae_score
                db_alert.suricata_score = alert.suricata_score
                db_alert.attack_type = alert.attack_type

                await session.commit()

                logger.info(
                    f"M3 Fusion | Alerte mise à jour DB | "
                    f"alert_id={alert.id} attack_type={alert.attack_type}"
                )

        except Exception:
            logger.exception("M3 Fusion | Erreur mise à jour alerte fusionnée")
            logger.exception(
                "PIPELINE_TRACE | X | Erreur update DB fusion | alert_id=%s",
                getattr(alert, "id", None),
            )
            raise

    async def _publish_fused_alert(self, alert: Alert):
        try:
            r = await self._get_redis()

            payload = json.dumps(
                {
                    "id": alert.id,
                    "source": "M3_fusion",
                    "severity": alert.severity.value,
                    "src_ip": alert.src_ip,
                    "dest_ip": alert.dest_ip,
                    "signature_name": alert.signature_name,
                    "attack_type": alert.attack_type or "Unknown",
                    "fusion_case": alert.fusion_case,
                    "confidence": alert.confidence,
                    "ml_score": alert.ml_score,
                    "suricata_score": alert.suricata_score,
                    "technique_id": alert.technique_id,
                    "technique_name": alert.technique_name,
                    "tactic": alert.tactic,
                    "detected_at": alert.detected_at.isoformat()
                    if alert.detected_at
                    else None,
                },
                default=str,
            )

            await r.publish("channel:alerts", payload)

            logger.info(
                f"M3 Fusion | Alerte fusionnée publiée | "
                f"alert_id={alert.id} attack_type={alert.attack_type}"
            )

        except Exception:
            logger.exception(
                f"M3 Fusion | Erreur publication channel:alerts | alert_id={alert.id}"
            )
            raise

    async def _trigger_incident_creation(self, alert: Alert):
        try:
            r = await self._get_redis()

            alert_time = (
                getattr(alert, "detected_at", None)
                or datetime.now(timezone.utc)
            )

            if alert_time.tzinfo is None:
                alert_time = alert_time.replace(tzinfo=timezone.utc)

            asset_ip = (
                getattr(alert, "dest_ip", None)
                or getattr(alert, "src_ip", None)
                or ""
            )

            hids_confirmed = await self._check_hids_correlation(
                asset_ip=asset_ip,
                timestamp=alert_time,
            )

            payload = json.dumps(
                {
                    "alert_id": alert.id,
                    "severity": alert.severity.value,
                    "confidence": alert.confidence,
                    "technique_id": alert.technique_id,
                    "technique_name": alert.technique_name,
                    "tactic": alert.tactic,
                    "src_ip": alert.src_ip,
                    "dest_ip": alert.dest_ip,
                    "asset_ip": asset_ip,
                    "signature_name": alert.signature_name,
                    "attack_type": alert.attack_type or "Unknown",

                    # M11 — Corrélation HIDS/Wazuh
                    "hids_confirmed": hids_confirmed,

                    # Réutilisé dans le score R comme facteur E élevé
                    "dast_confirmed": hids_confirmed,
                },
                default=str,
            )

            await r.publish("channel:incident_requests", payload)

            logger.warning(
                f"M3 Fusion | Incident request publié | "
                f"Alert #{alert.id} | severity={alert.severity.value} | "
                f"attack_type={alert.attack_type or 'Unknown'} | "
                f"{alert.src_ip} → {alert.dest_ip} | "
                f"hids_confirmed={hids_confirmed}"
            )

        except Exception:
            logger.exception(
                f"M3 Fusion | Erreur publication channel:incident_requests | alert_id={alert.id}"
            )
            raise


# ============================================================
# Validation H2 — Réduction FPR
# ============================================================

class FPRValidator:
    @staticmethod
    def compute_fpr(y_true: list, y_pred: list) -> float:
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        return fp / (fp + tn + 1e-9)

    @staticmethod
    def validate_h2(fpr_signature: float, fpr_fusion: float) -> dict:
        reduction = (fpr_signature - fpr_fusion) / (fpr_signature + 1e-9)
        return {
            "fpr_signature": round(fpr_signature, 4),
            "fpr_fusion": round(fpr_fusion, 4),
            "reduction_pct": round(reduction * 100, 1),
            "h2_validated": reduction >= 0.30,
            "target": "30% minimum",
        }