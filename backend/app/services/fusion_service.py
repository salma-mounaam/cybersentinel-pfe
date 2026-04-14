# ============================================================
# M3 — Moteur de Fusion Hybride
# Confidence = 0.40*S + 0.30*M + 0.30*C
# Fenêtre temporelle 5 secondes par hôte source
# ============================================================

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
from collections import defaultdict

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource, SeverityLevel
from app.services.ml_service import MLAnomalyEngine
from app.services.mitre_service import MitreEnrichmentEngine

logger = logging.getLogger(__name__)

# Poids de la formule de confiance
W_S = 0.40  # Score signature Suricata
W_M = 0.30  # Score ML anomalie
W_C = 0.30  # Score contexte (corrélation temporelle)

# Fenêtre temporelle de corrélation (secondes)
TEMPORAL_WINDOW = 5

# Seuils de confiance → niveau
CONFIDENCE_LEVELS = [
    (0.90, SeverityLevel.CRITIQUE),
    (0.75, SeverityLevel.ELEVE),
    (0.50, SeverityLevel.MOYEN),
    (0.00, SeverityLevel.FAIBLE),
]

# Les 5 cas de fusion
FUSION_CASES = {
    1: {"label": "Signature + ML + même flux",    "confidence": 0.95},
    2: {"label": "Signature + ML + fenêtre 5s",   "confidence": 0.85},
    3: {"label": "Signature seule",                "confidence": 0.70},
    4: {"label": "ML seul",                        "confidence": 0.60},
    5: {"label": "Bruit — ignoré",                 "confidence": 0.00},
}


class FusionEngine:
    """
    Corrèle les alertes Suricata (M1) avec les scores ML (M2).
    Maintient une fenêtre temporelle par hôte source en mémoire.
    """

    def __init__(self):
        self.ml_engine    = MLAnomalyEngine()
        self.mitre_engine = MitreEnrichmentEngine()
        self.redis: Optional[aioredis.Redis] = None

        # Fenêtre temporelle : {src_ip: [timestamps des alertes récentes]}
        self._temporal_window: Dict[str, list] = defaultdict(list)

    async def _get_redis(self) -> aioredis.Redis:
        if not self.redis:
            self.redis = await aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis

    async def process_suricata_alert(
        self,
        alert: Alert,
        raw_event: dict
    ) -> Alert:
        """
        Point d'entrée principal de M3.
        Reçoit une alerte Suricata et calcule la confiance fusionnée.
        """
        # 1. Obtenir le score ML pour ce flux
        ml_result = await self.ml_engine.score_event(raw_event)
        ml_score = ml_result["ensemble_score"] if ml_result else 0.0

        # 2. Calculer le score de contexte (fenêtre temporelle)
        context_score = self._compute_context_score(
            alert.src_ip,
            alert.detected_at or datetime.now(timezone.utc)
        )

        # 3. Déterminer le cas de fusion (1-5)
        fusion_case = self._determine_case(
            s_score=alert.suricata_score,
            m_score=ml_score,
            c_score=context_score
        )

        # Cas 5 → bruit, on ignore
        if fusion_case == 5:
            logger.debug(f"Alerte ignorée (bruit) — {alert.src_ip}")
            return alert

        # 4. Calculer la confiance finale
        confidence = (
            W_S * alert.suricata_score +
            W_M * ml_score +
            W_C * context_score
        )
        confidence = round(min(confidence, 1.0), 4)

        # 5. Déterminer la sévérité selon la confiance
        severity = self._confidence_to_severity(confidence)

        # 6. Mettre à jour l'alerte
        alert.ml_score    = round(ml_score, 4)
        alert.confidence  = confidence
        alert.fusion_case = fusion_case
        alert.severity    = severity
        alert.source      = AlertSource.M3_FUSION

        if ml_result:
            alert.if_score    = ml_result.get("if_score")
            alert.ocsvm_score = ml_result.get("ocsvm_score")
            alert.ae_score    = ml_result.get("ae_score")

        # 7. Sauvegarder en base
        await self._update_alert(alert)

        # 8. Publier l'alerte fusionnée dans Redis
        await self._publish_fused_alert(alert)

        # 9. Si CRITIQUE → déclencher M7 (calcul score R)
        if severity == SeverityLevel.CRITIQUE:
            await self._trigger_incident_creation(alert)

        logger.info(
            f"M3 Fusion | Cas {fusion_case} | "
            f"S={alert.suricata_score:.2f} M={ml_score:.2f} "
            f"C={context_score:.2f} → "
            f"Confiance={confidence:.3f} | {severity.value}"
        )

        return alert

    def _determine_case(
        self,
        s_score: float,
        m_score: float,
        c_score: float
    ) -> int:
        """
        Détermine le cas de fusion (1-5) selon la logique du CDC.

        Cas 1 : Signature + ML élevé + même flux  → 0.95
        Cas 2 : Signature + ML élevé + fenêtre 5s → 0.85
        Cas 3 : Signature seule                    → 0.70
        Cas 4 : ML seul (pas de signature)         → 0.60
        Cas 5 : Bruit (ni signature ni ML)         → ignoré
        """
        has_signature = s_score >= 0.40
        has_ml        = m_score >= 0.50
        has_context   = c_score >= 0.60  # Fenêtre temporelle active

        if has_signature and has_ml and c_score >= 0.90:
            return 1  # Même flux confirmé par les deux
        elif has_signature and has_ml and has_context:
            return 2  # Fenêtre temporelle 5s
        elif has_signature and not has_ml:
            return 3  # Signature seule
        elif not has_signature and has_ml:
            return 4  # ML seul
        else:
            return 5  # Bruit

    def _compute_context_score(
        self,
        src_ip: str,
        timestamp: datetime
    ) -> float:
        """
        Score de corrélation contextuelle [0-1].
        Basé sur le nombre d'alertes récentes du même src_ip
        dans la fenêtre de 5 secondes.
        """
        if not src_ip:
            return 0.0

        now = timestamp
        window_start = now - timedelta(seconds=TEMPORAL_WINDOW)

        # Nettoyer les timestamps anciens
        self._temporal_window[src_ip] = [
            t for t in self._temporal_window[src_ip]
            if t > window_start
        ]

        # Ajouter le timestamp actuel
        self._temporal_window[src_ip].append(now)

        # Score basé sur le nombre d'événements dans la fenêtre
        count = len(self._temporal_window[src_ip])

        # 1 event = 0.0, 2 events = 0.3, 3 events = 0.6, 4+ = 0.9+
        score = min((count - 1) * 0.30, 1.0)
        return round(score, 2)

    def _confidence_to_severity(self, confidence: float) -> SeverityLevel:
        """Convertit un score de confiance en niveau de sévérité."""
        for threshold, severity in CONFIDENCE_LEVELS:
            if confidence >= threshold:
                return severity
        return SeverityLevel.FAIBLE

    async def _update_alert(self, alert: Alert):
        """Met à jour l'alerte fusionnée en PostgreSQL."""
        try:
            async with AsyncSessionLocal() as session:
                from sqlalchemy import select
                result = await session.execute(
                    select(Alert).where(Alert.id == alert.id)
                )
                db_alert = result.scalar_one_or_none()
                if db_alert:
                    db_alert.ml_score    = alert.ml_score
                    db_alert.confidence  = alert.confidence
                    db_alert.fusion_case = alert.fusion_case
                    db_alert.severity    = alert.severity
                    db_alert.source      = alert.source
                    db_alert.if_score    = alert.if_score
                    db_alert.ocsvm_score = alert.ocsvm_score
                    db_alert.ae_score    = alert.ae_score
                    await session.commit()
        except Exception as e:
            logger.error(f"Erreur mise à jour alerte fusionnée: {e}")

    async def _publish_fused_alert(self, alert: Alert):
        """Publie l'alerte fusionnée dans Redis → WebSocket M9."""
        r = await self._get_redis()
        payload = json.dumps({
            "id":             alert.id,
            "source":         "M3_fusion",
            "severity":       alert.severity.value,
            "src_ip":         alert.src_ip,
            "dest_ip":        alert.dest_ip,
            "signature_name": alert.signature_name,
            "fusion_case":    alert.fusion_case,
            "confidence":     alert.confidence,
            "ml_score":       alert.ml_score,
            "suricata_score": alert.suricata_score,
            "technique_id":   alert.technique_id,
            "tactic":         alert.tactic,
            "detected_at":    alert.detected_at.isoformat()
                              if alert.detected_at else None,
        })
        await r.publish("channel:alerts", payload)

    async def _trigger_incident_creation(self, alert: Alert):
        """
        Déclenche la création d'un incident CRITIQUE via M7.
        Publié dans un channel Redis dédié pour traitement asynchrone.
        """
        r = await self._get_redis()
        await r.publish("channel:incidents", json.dumps({
            "alert_id":     alert.id,
            "severity":     alert.severity.value,
            "confidence":   alert.confidence,
            "technique_id": alert.technique_id,
            "src_ip":       alert.src_ip,
            "asset_ip":     alert.dest_ip,
        }))
        logger.warning(
            f"🚨 CRITIQUE détecté → création incident | "
            f"Alert #{alert.id} | {alert.src_ip} → {alert.dest_ip}"
        )


# ============================================================
# Validation H2 — Réduction FPR
# ============================================================

class FPRValidator:
    """
    Mesure la réduction du FPR entre signature seule et fusion hybride.
    Utilisé pour valider H2 : FPR réduit >= 30%.
    """

    @staticmethod
    def compute_fpr(
        y_true: list,
        y_pred: list
    ) -> float:
        """
        Calcule le False Positive Rate.
        FPR = FP / (FP + TN)
        """
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        return fp / (fp + tn + 1e-9)

    @staticmethod
    def validate_h2(
        fpr_signature: float,
        fpr_fusion: float
    ) -> dict:
        """
        Valide H2 : la fusion réduit le FPR d'au moins 30%.
        """
        reduction = (fpr_signature - fpr_fusion) / (fpr_signature + 1e-9)
        return {
            "fpr_signature":  round(fpr_signature, 4),
            "fpr_fusion":     round(fpr_fusion, 4),
            "reduction_pct":  round(reduction * 100, 1),
            "h2_validated":   reduction >= 0.30,
            "target":         "30% minimum",
        }
