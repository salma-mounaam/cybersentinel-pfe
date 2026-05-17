# ============================================================
# M7 — Calcul Score de Risque R + Création Incidents
# R = w_a*A + w_v*V + w_e*E + w_c*C
# A = Anomalie IDS [0-10]
# V = CVSS Score [0-10]
# E = Exploitabilité confirmée [0 ou 10]
#     - DAST confirmé
#     - OU HIDS/Wazuh confirmé
# C = Criticité Asset [0-10]
#
# NOUVEAU :
#   [LLM] attack_type Llama intégré dans titre + description incident
#   [M11] hids_confirmed renforce score_e
#   [M12] AssetResolver récupère la criticité réelle depuis Asset Registry
# ============================================================

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import redis.asyncio as aioredis
from sqlalchemy import select

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, SeverityLevel
from app.models.incident import Incident, IncidentStatus
from app.models.sast_finding import SASTFinding
from app.services.mitre_service import MitreEnrichmentEngine
from app.services.asset_resolver import AssetResolver

logger = logging.getLogger(__name__)

# SLA par niveau de sévérité
SLA_MAP = {
    SeverityLevel.CRITIQUE: timedelta(hours=1),
    SeverityLevel.ELEVE: timedelta(hours=4),
    SeverityLevel.MOYEN: timedelta(hours=48),
    SeverityLevel.FAIBLE: timedelta(days=14),
}

# Fallback si aucun asset n'est trouvé en base
DEFAULT_ASSET_CRITICALITY = {
    "db-prod": 9.0,
    "api-gateway": 8.0,
    "admin": 9.5,
    "auth": 9.0,
    "web": 7.0,
    "dev": 4.0,
    "test": 3.0,
}

# Fallback IP -> criticité si aucun asset n'est trouvé en base
IP_CRITICALITY_MAP = {
    "10.0.0.5": 9.0,
    "10.0.0.10": 8.0,
    "10.0.0.20": 7.0,

    # CyberSentinel lab
    "10.16.2.150": 8.0,
    "10.16.2.157": 5.0,
}


class RiskScoringEngine:
    """
    Calcule le score de risque R pour chaque incident.
    Corrèle les alertes IDS + findings SAST + confirmation DAST/HIDS.
    """

    def __init__(self):
        self.mitre_engine = MitreEnrichmentEngine()
        self.asset_resolver = AssetResolver()
        self.redis: Optional[aioredis.Redis] = None

    async def _get_redis(self) -> aioredis.Redis:
        if not self.redis:
            self.redis = await aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
        return self.redis

    # ============================================================
    # Calcul du score R
    # ============================================================

    def compute_score_r(
        self,
        anomaly_score: float = 0.0,
        cvss_score: float = 0.0,
        dast_confirmed: bool = False,
        asset_criticality: float = 5.0,
    ) -> dict:
        """
        Calcule le score R et détermine le niveau de sévérité.

        Remarque :
        - dast_confirmed peut représenter une confirmation DAST
        - ou une confirmation HIDS/Wazuh transmise par M3
        """

        anomaly_score = max(0.0, min(float(anomaly_score), 10.0))
        cvss_score = max(0.0, min(float(cvss_score), 10.0))
        asset_criticality = max(0.0, min(float(asset_criticality), 10.0))

        e_score = 10.0 if dast_confirmed else 0.0

        w_a = settings.SCORE_R_WEIGHT_A
        w_v = settings.SCORE_R_WEIGHT_V
        w_e = settings.SCORE_R_WEIGHT_E
        w_c = settings.SCORE_R_WEIGHT_C

        r = (
            w_a * anomaly_score
            + w_v * cvss_score
            + w_e * e_score
            + w_c * asset_criticality
        )
        r = round(min(r, 10.0), 2)

        if r > 8.0:
            severity = SeverityLevel.CRITIQUE
        elif r >= 6.0:
            severity = SeverityLevel.ELEVE
        elif r >= 4.0:
            severity = SeverityLevel.MOYEN
        else:
            severity = SeverityLevel.FAIBLE

        return {
            "score_r": r,
            "score_a": round(anomaly_score, 2),
            "score_v": round(cvss_score, 2),
            "score_e": e_score,
            "score_c": round(asset_criticality, 2),
            "severity": severity.value,
            "formula": (
                f"R = {w_a}x{anomaly_score:.1f} + "
                f"{w_v}x{cvss_score:.1f} + "
                f"{w_e}x{e_score:.1f} + "
                f"{w_c}x{asset_criticality:.1f} = {r}"
            ),
        }

    async def get_asset_criticality(
        self,
        asset_ip: str = "",
        asset_name: str = "",
        fallback_src_ip: str = "",
    ) -> float:
        """
        Retourne la criticité d'un asset [0-10].

        Priorité :
        1. Asset Registry par IP/hostname
        2. Asset Registry par src_ip si dest_ip inconnu
        3. IP_CRITICALITY_MAP fallback
        4. DEFAULT_ASSET_CRITICALITY fallback par nom
        5. Valeur par défaut = 5.0
        """

        asset_ip = (asset_ip or "").strip()
        asset_name = (asset_name or "").strip()
        fallback_src_ip = (fallback_src_ip or "").strip()

        # 1. Chercher dans Asset Registry avec IP/hostname principal
        try:
            asset = await self.asset_resolver.resolve(
                ip=asset_ip,
                hostname=asset_name,
            )
            if asset:
                return max(0.0, min(float(asset.criticality), 10.0))
        except Exception as e:
            logger.warning("AssetResolver erreur sur asset principal: %s", e)

        # 2. Chercher dans Asset Registry avec src_ip
        try:
            if fallback_src_ip:
                asset = await self.asset_resolver.resolve(ip=fallback_src_ip)
                if asset:
                    return max(0.0, min(float(asset.criticality), 10.0))
        except Exception as e:
            logger.warning("AssetResolver erreur sur fallback_src_ip: %s", e)

        # 3. Fallback IP statique
        if asset_ip and asset_ip in IP_CRITICALITY_MAP:
            return IP_CRITICALITY_MAP[asset_ip]

        if fallback_src_ip and fallback_src_ip in IP_CRITICALITY_MAP:
            return IP_CRITICALITY_MAP[fallback_src_ip]

        # 4. Fallback par nom
        asset_lower = asset_name.lower()
        for keyword, criticality in DEFAULT_ASSET_CRITICALITY.items():
            if keyword in asset_lower:
                return criticality

        # 5. Défaut
        return 5.0

    # ============================================================
    # Création d'incidents corrélés
    # ============================================================

    async def create_incident_from_alert(self, alert: Alert) -> Optional[Incident]:
        """
        Crée un incident depuis une alerte IDS fusionnée M3.
        Cherche des findings SAST corrélés pour enrichir le score R.

        [LLM] attack_type intégré dans titre et description.
        [M11] hids_confirmed augmente score_e.
        [M12] criticité réelle depuis Asset Registry.
        """

        anomaly_score = max(0.0, min((alert.confidence or 0.0) * 10.0, 10.0))

        sast_findings = await self._find_related_sast(
            alert.dest_ip,
            alert.technique_id,
        )

        cvss_score = 0.0

        # Flags transmis par IncidentConsumer depuis Redis
        runtime_dast_confirmed = bool(
            getattr(alert, "_cybersentinel_dast_confirmed", False)
        )
        runtime_hids_confirmed = bool(
            getattr(alert, "_cybersentinel_hids_confirmed", False)
        )

        sast_dast_confirmed = False

        if sast_findings:
            cvss_score = max((f.cvss_score or 0.0) for f in sast_findings)
            sast_dast_confirmed = any(
                bool(getattr(f, "dast_confirmed", False))
                for f in sast_findings
            )
        else:
            mitre_data = await self.mitre_engine.enrich_by_technique_id(
                alert.technique_id or "T1190"
            )
            cvss_score = float(mitre_data.get("cvss_base", 5.0) or 5.0)

        # E = 10 si DAST confirme OU HIDS confirme
        exploit_confirmed = bool(
            runtime_dast_confirmed
            or runtime_hids_confirmed
            or sast_dast_confirmed
        )

        # M12 — Criticité réelle depuis Asset Registry
        # Priorité : dest_ip, puis src_ip si la machine surveillée est source
        asset_criticality = await self.get_asset_criticality(
            asset_ip=alert.dest_ip or "",
            asset_name=getattr(alert, "asset_name", "") or alert.dest_ip or "",
            fallback_src_ip=alert.src_ip or "",
        )

        score_result = self.compute_score_r(
            anomaly_score=anomaly_score,
            cvss_score=cvss_score,
            dast_confirmed=exploit_confirmed,
            asset_criticality=asset_criticality,
        )

        severity_enum = SeverityLevel(score_result["severity"])
        title = self._build_incident_title(alert, severity_enum)

        now = datetime.now(timezone.utc)
        sla_deadline = now + SLA_MAP.get(severity_enum, timedelta(days=14))

        incident = Incident(
            title=title,
            status=IncidentStatus.OPEN,
            severity=severity_enum,

            score_r=score_result["score_r"],
            score_a=score_result["score_a"],
            score_v=score_result["score_v"],
            score_e=score_result["score_e"],
            score_c=score_result["score_c"],

            alert_ids=[alert.id],
            sast_finding_ids=[f.id for f in sast_findings],
            dast_finding_ids=[],

            technique_id=alert.technique_id,
            technique_name=alert.technique_name,
            tactic=alert.tactic,
            apt_groups=alert.apt_groups or [],
            mitre_url=(
                f"https://attack.mitre.org/techniques/"
                f"{(alert.technique_id or 'T1190').replace('.', '/')}/"
            ),

            asset_ip=alert.dest_ip,
            asset_name=getattr(alert, "asset_name", None) or alert.dest_ip,
            asset_criticality=asset_criticality,
            sla_deadline=sla_deadline,
            description=self._build_description(
                alert=alert,
                score_result=score_result,
                sast_findings=sast_findings,
                hids_confirmed=runtime_hids_confirmed,
                dast_confirmed=bool(runtime_dast_confirmed or sast_dast_confirmed),
                exploit_confirmed=exploit_confirmed,
            ),
            detected_at=alert.detected_at or now,
        )

        async with AsyncSessionLocal() as db:
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        logger.info(
            "📋 Incident créé | #%s | R=%s | E=%s | C=%s | severity=%s | "
            "hids_confirmed=%s | dast_confirmed=%s | %s",
            incident.id,
            incident.score_r,
            incident.score_e,
            incident.score_c,
            incident.severity.value,
            runtime_hids_confirmed,
            bool(runtime_dast_confirmed or sast_dast_confirmed),
            title,
        )

        await self._notify_incident(incident)

        if incident.severity == SeverityLevel.CRITIQUE:
            await self._notify_critical(incident)

        return incident

    async def create_incident_from_sast(self, finding: SASTFinding) -> Optional[Incident]:
        """Crée un incident depuis un finding SAST critique."""
        if not finding.cvss_score or finding.cvss_score < 7.0:
            return None

        asset_criticality = await self.get_asset_criticality(
            asset_ip="",
            asset_name=finding.repo_name or "",
        )

        score_result = self.compute_score_r(
            anomaly_score=0.0,
            cvss_score=finding.cvss_score,
            dast_confirmed=bool(getattr(finding, "dast_confirmed", False)),
            asset_criticality=asset_criticality,
        )

        severity_enum = SeverityLevel(score_result["severity"])

        now = datetime.now(timezone.utc)
        sla_deadline = now + SLA_MAP.get(severity_enum, timedelta(days=14))

        incident = Incident(
            title=f"SAST: {finding.title} — {finding.file_path or 'repo'}",
            status=IncidentStatus.OPEN,
            severity=severity_enum,

            score_r=score_result["score_r"],
            score_a=0.0,
            score_v=score_result["score_v"],
            score_e=score_result["score_e"],
            score_c=score_result["score_c"],

            alert_ids=[],
            sast_finding_ids=[finding.id],
            dast_finding_ids=[],

            technique_id=finding.technique_id,
            technique_name=finding.technique_name,
            tactic=finding.tactic,
            apt_groups=[],
            mitre_url=(
                f"https://attack.mitre.org/techniques/"
                f"{(finding.technique_id or 'T1190').replace('.', '/')}/"
            ) if finding.technique_id else None,

            asset_ip=None,
            asset_name=finding.repo_name,
            asset_criticality=asset_criticality,
            sla_deadline=sla_deadline,
            description=(
                f"Incident créé depuis finding SAST.\n"
                f"Titre: {finding.title}\n"
                f"Repo: {finding.repo_name}\n"
                f"Fichier: {finding.file_path}\n"
                f"Ligne: {finding.line_number}\n"
                f"Score R: {score_result['score_r']}\n"
                f"Score E: {score_result['score_e']}\n"
                f"Score C: {score_result['score_c']}\n"
                f"Formule: {score_result['formula']}"
            ),
            detected_at=now,
        )

        async with AsyncSessionLocal() as db:
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        await self._notify_incident(incident)

        if incident.severity == SeverityLevel.CRITIQUE:
            await self._notify_critical(incident)

        return incident

    # ============================================================
    # Validation H4 — Pearson r >= 0.80
    # ============================================================

    @staticmethod
    def validate_h4(computed_scores: list, expert_scores: list) -> dict:
        """Valide H4 : corrélation score R vs évaluation experte."""
        import numpy as np

        if len(computed_scores) != len(expert_scores):
            return {"error": "Les listes doivent avoir la même taille"}

        if len(computed_scores) < 2:
            return {"error": "Pas assez de données minimum 2 incidents"}

        x = np.array(computed_scores, dtype=float)
        y = np.array(expert_scores, dtype=float)

        if np.std(x) == 0 or np.std(y) == 0:
            return {"error": "Impossible de calculer Pearson: variance nulle"}

        correlation = float(np.corrcoef(x, y)[0, 1])

        return {
            "pearson_r": round(correlation, 4),
            "h4_validated": correlation >= 0.80,
            "target": "Pearson r >= 0.80",
            "n_incidents": len(computed_scores),
            "mean_computed": round(float(np.mean(x)), 2),
            "mean_expert": round(float(np.mean(y)), 2),
        }

    # ============================================================
    # Helpers privés
    # ============================================================

    async def _find_related_sast(
        self,
        asset_ip: str,
        technique_id: Optional[str],
    ) -> List[SASTFinding]:
        """Cherche les findings SAST corrélés par technique MITRE."""
        if not technique_id:
            return []

        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SASTFinding)
                    .where(SASTFinding.technique_id == technique_id)
                    .order_by(SASTFinding.cvss_score.desc())
                    .limit(5)
                )
                return list(result.scalars().all())
        except Exception as e:
            logger.error("Erreur lookup SAST: %s", e, exc_info=True)
            return []

    def _build_incident_title(self, alert: Alert, severity: SeverityLevel) -> str:
        """
        [LLM] Construit un titre lisible avec attack_type Llama.
        Exemple : "BruteForce SSH — 10.16.2.157 → 10.16.2.150"
        """
        attack_label = (
            getattr(alert, "attack_type", None)
            or alert.technique_name
            or alert.technique_id
            or "Menace inconnue"
        )

        src = alert.src_ip or "IP inconnue"
        dst = alert.dest_ip or "asset inconnu"

        return f"{attack_label} — {src} → {dst}"

    def _build_description(
        self,
        alert: Alert,
        score_result: dict,
        sast_findings: list,
        hids_confirmed: bool = False,
        dast_confirmed: bool = False,
        exploit_confirmed: bool = False,
    ) -> str:
        """
        [LLM] Description enrichie avec attack_type et signature Suricata.
        [M11] Ajoute l'état de corrélation HIDS/Wazuh.
        """
        attack_type = getattr(alert, "attack_type", None) or "Unknown"

        lines = [
            f"Score R = {score_result['score_r']} ({score_result['severity']})",
            f"Formule : {score_result['formula']}",
            "",
            "Composants du score :",
            f"  - A Anomalie IDS : {score_result['score_a']}",
            f"  - V CVSS/MITRE/SAST : {score_result['score_v']}",
            f"  - E Exploitabilité confirmée : {score_result['score_e']}",
            f"  - C Criticité asset : {score_result['score_c']}",
            "",
            "Confirmations :",
            f"  - DAST confirmé : {dast_confirmed}",
            f"  - HIDS/Wazuh confirmé : {hids_confirmed}",
            f"  - Exploit confirmé : {exploit_confirmed}",
            "",
            f"Type d'attaque LLM : {attack_type}",
            f"Signature : {alert.signature_name}",
            "",
            f"Source principale : {alert.source.value if getattr(alert, 'source', None) else 'IDS'}",
            f"Technique MITRE : {alert.technique_id} — {alert.technique_name}",
            f"Tactique : {alert.tactic}",
            f"Flux : {alert.src_ip}:{alert.src_port} → {alert.dest_ip}:{alert.dest_port} ({alert.protocol})",
            f"Confiance fusion : {alert.confidence}",
        ]

        if sast_findings:
            lines.append("")
            lines.append(f"Findings SAST corrélés ({len(sast_findings)}) :")
            for f in sast_findings[:3]:
                tool_value = f.tool.value if getattr(f, "tool", None) else "unknown"
                lines.append(
                    f"  - {tool_value}: {f.title} "
                    f"(CVSS {f.cvss_score}, {f.file_path}:{f.line_number})"
                )

        return "\n".join(lines)

    async def _notify_incident(self, incident: Incident):
        """Publie l'incident dans Redis → WebSocket M9."""
        try:
            r = await self._get_redis()
            payload = json.dumps({
                "type": "incident",
                "id": incident.id,
                "title": incident.title,
                "status": incident.status.value if incident.status else None,
                "severity": incident.severity.value if incident.severity else None,
                "score_r": incident.score_r,
                "score_a": incident.score_a,
                "score_v": incident.score_v,
                "score_e": incident.score_e,
                "score_c": incident.score_c,
                "technique_id": incident.technique_id,
                "tactic": incident.tactic,
                "asset_ip": incident.asset_ip,
                "asset_name": incident.asset_name,
                "asset_criticality": incident.asset_criticality,
                "sla_deadline": incident.sla_deadline.isoformat() if incident.sla_deadline else None,
                "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
            })
            await r.publish("channel:incidents", payload)
        except Exception as e:
            logger.error("Erreur notification incident: %s", e, exc_info=True)

    async def _notify_critical(self, incident: Incident):
        """Notification spéciale pour les incidents CRITIQUES."""
        try:
            r = await self._get_redis()
            payload = json.dumps({
                "type": "CRITICAL_ALERT",
                "id": incident.id,
                "title": incident.title,
                "score_r": incident.score_r,
                "score_c": incident.score_c,
                "asset_ip": incident.asset_ip,
                "asset_name": incident.asset_name,
                "sla": "< 1 heure",
                "apt_groups": incident.apt_groups,
                "mitre_url": incident.mitre_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            await r.publish("channel:critical", payload)
            await r.setex(f"critical:{incident.id}", 86400, payload)

            logger.critical(
                "🚨 INCIDENT CRITIQUE #%s | R=%s | C=%s | %s | SLA < 1 heure",
                incident.id,
                incident.score_r,
                incident.score_c,
                incident.title,
            )
        except Exception as e:
            logger.error("Erreur notification critique: %s", e, exc_info=True)