# ============================================================
# backend/app/api/reports.py
#
# CyberSentinel — Rapports intelligents avec LLM / Ollama
#
# Endpoints :
#   POST /api/reports/analyze
#   GET  /api/reports/types
#
# Objectif :
#   Générer des rapports narratifs Markdown à partir des données :
#     - Alertes IDS
#     - Incidents corrélés
#     - Findings SAST
#     - Findings DAST si la table existe
#
# Le LLM ne détecte pas les vulnérabilités.
# Il explique et synthétise les données déjà produites par CyberSentinel.
# ============================================================

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal, Any

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

router = APIRouter()


# ============================================================
# Configuration Ollama
# ============================================================

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_URL = f"{OLLAMA_HOST.rstrip('/')}/api/generate"


# ============================================================
# Schémas
# ============================================================

ReportType = Literal[
    "security_summary",
    "incident_analysis",
    "sast_dast_summary",
    "executive_briefing",
]

ReportLanguage = Literal["fr", "en"]


class ReportAnalyzeRequest(BaseModel):
    report_type: ReportType = Field(
        default="security_summary",
        description="Type de rapport à générer",
    )
    incident_id: Optional[int] = Field(
        default=None,
        description="ID incident requis pour incident_analysis",
    )
    period_days: int = Field(
        default=7,
        ge=1,
        le=90,
        description="Fenêtre temporelle en jours",
    )
    language: ReportLanguage = Field(
        default="fr",
        description="Langue du rapport : fr ou en",
    )


class ReportAnalyzeResponse(BaseModel):
    success: bool
    report_type: str
    generated_at: str
    period_days: int
    incident_id: Optional[int] = None
    markdown: str
    stats: dict
    model: str


# ============================================================
# Helpers DB robustes
# ============================================================

async def _fetch_all_safe(db, query: str, params: Optional[dict] = None) -> list[dict]:
    """
    Exécute une requête SQL et retourne une liste de dicts.

    Si une table ou colonne n'existe pas encore dans ta version actuelle,
    le rapport continue avec les autres données.
    """
    try:
        result = await db.execute(text(query), params or {})
        rows = result.mappings().all()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.warning("Requête ignorée : %s | erreur=%s", query[:160], e)
        return []


async def _fetch_one_safe(db, query: str, params: Optional[dict] = None) -> Optional[dict]:
    """
    Exécute une requête SQL et retourne une seule ligne sous forme de dict.
    """
    try:
        result = await db.execute(text(query), params or {})
        row = result.mappings().first()
        return dict(row) if row else None
    except Exception as e:
        logger.warning("Requête ignorée : %s | erreur=%s", query[:160], e)
        return None


def _compact_json(data: Any, max_chars: int = 28000) -> str:
    """
    Compacte les données envoyées au LLM pour éviter un prompt trop long.
    """
    raw = json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        default=str,
    )

    if len(raw) <= max_chars:
        return raw

    return raw[:max_chars] + "\n... [CONTEXTE TRONQUÉ]"


# ============================================================
# Collecte des données
# ============================================================

async def _collect_security_context(period_days: int) -> dict:
    """
    Collecte globale sur la période :
      - alertes
      - incidents
      - SAST
      - DAST
      - agrégats
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=period_days)

    async with AsyncSessionLocal() as db:

        # --------------------------------------------------------
        # Alertes IDS récentes
        # --------------------------------------------------------
        alerts = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                timestamp,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                signature_name,
                category,
                severity,
                attack_type,
                ml_score,
                confidence,
                technique_id,
                technique_name
            FROM alerts
            WHERE timestamp >= :since
            ORDER BY timestamp DESC
            LIMIT 200
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Incidents récents
        # --------------------------------------------------------
        incidents = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                title,
                description,
                severity,
                status,
                score_r,
                score_a,
                score_v,
                score_e,
                score_c,
                technique_id,
                technique_name,
                tactic,
                asset_ip,
                asset_criticality,
                sla_deadline,
                created_at,
                updated_at
            FROM incidents
            WHERE created_at >= :since
            ORDER BY created_at DESC
            LIMIT 100
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Findings SAST récents
        # --------------------------------------------------------
        sast_findings = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                scan_id,
                tool,
                severity,
                title,
                description,
                file_path,
                line_number,
                cwe,
                owasp_category,
                cvss_score,
                dast_confirmed,
                created_at
            FROM sast_findings
            WHERE created_at >= :since
            ORDER BY created_at DESC
            LIMIT 150
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Findings DAST récents
        # Si la table n'existe pas, la requête retourne []
        # --------------------------------------------------------
        dast_findings = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                session_id,
                severity,
                title,
                description,
                url,
                method,
                param,
                cwe,
                created_at
            FROM dast_findings
            WHERE created_at >= :since
            ORDER BY created_at DESC
            LIMIT 150
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Agrégats alertes par sévérité
        # --------------------------------------------------------
        alerts_by_severity = await _fetch_all_safe(
            db,
            """
            SELECT severity, COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= :since
            GROUP BY severity
            ORDER BY count DESC
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Agrégats incidents par sévérité
        # --------------------------------------------------------
        incidents_by_severity = await _fetch_all_safe(
            db,
            """
            SELECT severity, COUNT(*) AS count
            FROM incidents
            WHERE created_at >= :since
            GROUP BY severity
            ORDER BY count DESC
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Incidents ouverts
        # --------------------------------------------------------
        open_incidents = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                title,
                severity,
                status,
                score_r,
                technique_id,
                technique_name,
                sla_deadline,
                created_at
            FROM incidents
            WHERE created_at >= :since
              AND LOWER(CAST(status AS TEXT)) NOT IN ('resolved', 'closed', 'resolu', 'résolu')
            ORDER BY score_r DESC NULLS LAST
            LIMIT 20
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # SLA dépassés
        # --------------------------------------------------------
        sla_overdue = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                title,
                severity,
                status,
                score_r,
                sla_deadline
            FROM incidents
            WHERE sla_deadline IS NOT NULL
              AND sla_deadline < :now
              AND LOWER(CAST(status AS TEXT)) NOT IN ('resolved', 'closed', 'resolu', 'résolu')
            ORDER BY sla_deadline ASC
            LIMIT 20
            """,
            {"now": now},
        )

        # --------------------------------------------------------
        # Top attack types
        # --------------------------------------------------------
        top_attack_types = await _fetch_all_safe(
            db,
            """
            SELECT attack_type, COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= :since
              AND attack_type IS NOT NULL
              AND attack_type != 'Unknown'
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 10
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Top MITRE depuis alertes
        # --------------------------------------------------------
        top_mitre = await _fetch_all_safe(
            db,
            """
            SELECT technique_id, technique_name, COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= :since
              AND technique_id IS NOT NULL
            GROUP BY technique_id, technique_name
            ORDER BY count DESC
            LIMIT 10
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # Fallback MITRE depuis incidents
        # --------------------------------------------------------
        if not top_mitre:
            top_mitre = await _fetch_all_safe(
                db,
                """
                SELECT technique_id, technique_name, COUNT(*) AS count
                FROM incidents
                WHERE created_at >= :since
                  AND technique_id IS NOT NULL
                GROUP BY technique_id, technique_name
                ORDER BY count DESC
                LIMIT 10
                """,
                {"since": since},
            )

        # --------------------------------------------------------
        # SAST par sévérité
        # --------------------------------------------------------
        sast_by_severity = await _fetch_all_safe(
            db,
            """
            SELECT severity, COUNT(*) AS count
            FROM sast_findings
            WHERE created_at >= :since
            GROUP BY severity
            ORDER BY count DESC
            """,
            {"since": since},
        )

        # --------------------------------------------------------
        # DAST confirmés dans SAST
        # --------------------------------------------------------
        dast_confirmed_sast = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                title,
                severity,
                cwe,
                file_path,
                line_number,
                cvss_score,
                created_at
            FROM sast_findings
            WHERE created_at >= :since
              AND dast_confirmed = 1
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT 50
            """,
            {"since": since},
        )

    return {
        "period": {
            "days": period_days,
            "from": since.isoformat(),
            "to": now.isoformat(),
        },
        "counts": {
            "alerts": len(alerts),
            "incidents": len(incidents),
            "open_incidents": len(open_incidents),
            "sla_overdue": len(sla_overdue),
            "sast_findings": len(sast_findings),
            "dast_findings": len(dast_findings),
            "dast_confirmed_sast": len(dast_confirmed_sast),
        },
        "alerts": alerts,
        "incidents": incidents,
        "open_incidents": open_incidents,
        "sla_overdue": sla_overdue,
        "sast_findings": sast_findings,
        "dast_findings": dast_findings,
        "dast_confirmed_sast": dast_confirmed_sast,
        "aggregates": {
            "alerts_by_severity": alerts_by_severity,
            "incidents_by_severity": incidents_by_severity,
            "sast_by_severity": sast_by_severity,
            "top_attack_types": top_attack_types,
            "top_mitre": top_mitre,
        },
    }


async def _collect_incident_context(incident_id: int, period_days: int) -> dict:
    """
    Collecte le contexte d'un incident spécifique.
    """
    base_context = await _collect_security_context(period_days)

    now = datetime.now(timezone.utc)
    since = now - timedelta(days=period_days)

    async with AsyncSessionLocal() as db:
        incident = await _fetch_one_safe(
            db,
            """
            SELECT
                id,
                title,
                description,
                severity,
                status,
                score_r,
                score_a,
                score_v,
                score_e,
                score_c,
                technique_id,
                technique_name,
                tactic,
                apt_groups,
                asset_ip,
                asset_criticality,
                sla_deadline,
                detected_at,
                created_at,
                updated_at
            FROM incidents
            WHERE id = :incident_id
            """,
            {"incident_id": incident_id},
        )

        if not incident:
            raise HTTPException(
                status_code=404,
                detail=f"Incident {incident_id} introuvable",
            )

        # Alertes potentiellement liées selon IP / technique / période
        related_alerts = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                timestamp,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                signature_name,
                category,
                severity,
                attack_type,
                ml_score,
                confidence,
                technique_id,
                technique_name
            FROM alerts
            WHERE timestamp >= :since
              AND (
                    technique_id = :technique_id
                    OR dest_ip = :asset_ip
                    OR src_ip = :asset_ip
                  )
            ORDER BY timestamp DESC
            LIMIT 80
            """,
            {
                "since": since,
                "technique_id": incident.get("technique_id"),
                "asset_ip": incident.get("asset_ip"),
            },
        )

        # Findings SAST récents potentiellement liés
        related_sast = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                scan_id,
                tool,
                severity,
                title,
                description,
                file_path,
                line_number,
                cwe,
                owasp_category,
                cvss_score,
                dast_confirmed,
                created_at
            FROM sast_findings
            WHERE created_at >= :since
            ORDER BY created_at DESC
            LIMIT 80
            """,
            {"since": since},
        )

        # Findings DAST récents potentiellement liés
        related_dast = await _fetch_all_safe(
            db,
            """
            SELECT
                id,
                session_id,
                severity,
                title,
                description,
                url,
                method,
                param,
                cwe,
                created_at
            FROM dast_findings
            WHERE created_at >= :since
            ORDER BY created_at DESC
            LIMIT 80
            """,
            {"since": since},
        )

    return {
        "selected_incident": incident,
        "related_alerts": related_alerts,
        "related_sast_findings": related_sast,
        "related_dast_findings": related_dast,
        "global_context": {
            "counts": base_context.get("counts"),
            "aggregates": base_context.get("aggregates"),
        },
    }


# ============================================================
# Prompts
# ============================================================

def _language_instruction(language: str) -> str:
    if language == "en":
        return "Write the report in English."
    return "Rédige le rapport en français."


def _build_security_summary_prompt(data: dict, language: str) -> str:
    return f"""
Tu es un analyste cybersécurité senior dans une plateforme Purple Team appelée CyberSentinel.

{_language_instruction(language)}

Tu dois générer une synthèse sécurité narrative en Markdown.

Règles :
- Ne crée aucune donnée inventée.
- Base-toi uniquement sur les données fournies.
- Si une information manque, indique qu'elle n'est pas disponible.
- Sois clair, professionnel et exploitable.
- Ne retourne que du Markdown.
- Pas de bloc de code.

Structure obligatoire :

# Synthèse sécurité CyberSentinel

## 1. Verdict global
Donne un verdict clair : CRITIQUE, ÉLEVÉ, MOYEN ou FAIBLE.

## 2. Niveau de menace actuel
Explique le niveau de menace selon les alertes, incidents, scores et vulnérabilités.

## 3. Alertes et incidents notables
Résume les événements les plus importants.

## 4. Techniques MITRE et types d'attaques
Analyse les techniques MITRE ou types d'attaques observés.

## 5. Vulnérabilités applicatives SAST/DAST
Explique les vulnérabilités code et web détectées.

## 6. Risques prioritaires
Liste les risques les plus importants.

## 7. Recommandations opérationnelles
Donne des actions concrètes et priorisées.

## 8. Conclusion
Conclusion courte.

Données CyberSentinel :
{_compact_json(data)}
"""


def _build_incident_analysis_prompt(data: dict, language: str) -> str:
    return f"""
Tu es un analyste SOC senior spécialisé en réponse à incident.

{_language_instruction(language)}

Tu dois générer un rapport Markdown d'analyse d'incident.

Règles :
- Ne crée aucune information non fournie.
- Explique les incertitudes.
- Fais une corrélation IDS / SAST / DAST si les données existent.
- Ne retourne que du Markdown.
- Pas de bloc de code.

Structure obligatoire :

# Rapport d'analyse d'incident

## 1. Résumé de l'incident
Présente l'incident, son niveau de gravité et son état.

## 2. Chronologie probable
Reconstitue la chaîne d'événements à partir des données disponibles.

## 3. Indicateurs observés
Mentionne les IP, ports, signatures, score ML, techniques MITRE si disponibles.

## 4. Corrélation IDS / SAST / DAST
Explique les relations possibles entre trafic réseau, vulnérabilités code et confirmations DAST.

## 5. Hypothèse d'attaque
Décris le scénario d'attaque le plus probable.

## 6. Impact potentiel
Explique les conséquences possibles.

## 7. Actions de confinement immédiates
Liste les actions urgentes.

## 8. Remédiation durable
Liste les corrections techniques et organisationnelles.

## 9. Décision analyste
Indique si c'est un vrai positif probable, un faux positif possible ou une analyse insuffisante.

Données CyberSentinel :
{_compact_json(data)}
"""


def _build_sast_dast_summary_prompt(data: dict, language: str) -> str:
    return f"""
Tu es un expert AppSec senior.

{_language_instruction(language)}

Tu dois générer un rapport Markdown centré sur les vulnérabilités applicatives détectées par SAST et DAST.

Règles :
- Le SAST détecte dans le code.
- Le DAST confirme ou observe depuis l'extérieur via l'application.
- Ne crée pas de vulnérabilités non présentes dans les données.
- Explique clairement l'impact, la cause probable et les corrections.
- Ne retourne que du Markdown.
- Pas de bloc de code.

Structure obligatoire :

# Rapport SAST / DAST CyberSentinel

## 1. Résumé AppSec
Synthèse du niveau de risque applicatif.

## 2. Vulnérabilités critiques
Liste les vulnérabilités les plus dangereuses.

## 3. Confirmations DAST
Explique les vulnérabilités SAST confirmées par DAST si disponibles.

## 4. Risques principaux
Explique les risques : injection, secrets exposés, mauvaise configuration, XSS, etc.

## 5. Priorisation de correction
Classe les corrections en P1, P2, P3.

## 6. Recommandations développeurs
Donne des conseils concrets pour l'équipe dev.

## 7. Conclusion
Conclusion courte.

Données CyberSentinel :
{_compact_json(data)}
"""


def _build_executive_briefing_prompt(data: dict, language: str) -> str:
    return f"""
Tu es un RSSI qui prépare un briefing pour la direction.

{_language_instruction(language)}

Génère un briefing exécutif Markdown de 200 mots maximum.

Règles :
- Public non technique.
- Pas de jargon inutile.
- Maximum 200 mots.
- Verdict clair avec une couleur :
  🟢 Stable
  🟡 À surveiller
  🟠 Risque élevé
  🔴 Critique
- Ne crée aucune donnée inventée.
- Ne retourne que du Markdown.

Structure obligatoire :

# Briefing exécutif CyberSentinel

## Posture sécurité
Une phrase avec le verdict.

## Constats principaux
3 bullet points maximum.

## Décisions prioritaires
3 actions maximum.

## Conclusion
Une phrase finale.

Données CyberSentinel :
{_compact_json(data, max_chars=16000)}
"""


def _build_prompt(req: ReportAnalyzeRequest, data: dict) -> str:
    if req.report_type == "security_summary":
        return _build_security_summary_prompt(data, req.language)

    if req.report_type == "incident_analysis":
        return _build_incident_analysis_prompt(data, req.language)

    if req.report_type == "sast_dast_summary":
        return _build_sast_dast_summary_prompt(data, req.language)

    if req.report_type == "executive_briefing":
        return _build_executive_briefing_prompt(data, req.language)

    raise ValueError(f"Type de rapport inconnu : {req.report_type}")


# ============================================================
# Appel Ollama
# ============================================================

async def _call_ollama(prompt: str, timeout: int = 180) -> str:
    """
    Appelle Ollama et retourne le Markdown généré.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.25,
            "top_p": 0.9,
            "num_predict": 1600,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                OLLAMA_URL,
                json=payload,
            )

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"Ollama erreur {response.status_code}: {response.text[:500]}",
            )

        data = response.json()
        markdown = str(data.get("response", "")).strip()

        if not markdown:
            raise HTTPException(
                status_code=502,
                detail="Ollama a retourné une réponse vide",
            )

        return markdown

    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail=f"Ollama inaccessible sur {OLLAMA_HOST}. Vérifie que Ollama tourne.",
        )

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Timeout Ollama pendant la génération du rapport",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.exception("Erreur appel Ollama reports: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Erreur génération LLM: {e}",
        )


# ============================================================
# Endpoints
# ============================================================

@router.post("/analyze", response_model=ReportAnalyzeResponse)
async def analyze_report(req: ReportAnalyzeRequest):
    """
    Génère un rapport narratif CyberSentinel via LLM.
    """

    logger.info(
        "Génération rapport LLM | type=%s | lang=%s | period=%s | incident_id=%s",
        req.report_type,
        req.language,
        req.period_days,
        req.incident_id,
    )

    generated_at = datetime.now(timezone.utc).isoformat()

    if req.report_type == "incident_analysis":
        if req.incident_id is None:
            raise HTTPException(
                status_code=400,
                detail="incident_id est obligatoire pour incident_analysis",
            )

        stats = await _collect_incident_context(
            incident_id=req.incident_id,
            period_days=req.period_days,
        )
    else:
        stats = await _collect_security_context(
            period_days=req.period_days,
        )

    prompt = _build_prompt(req, stats)

    timeout = 90 if req.report_type == "executive_briefing" else 180
    markdown = await _call_ollama(prompt, timeout=timeout)

    return ReportAnalyzeResponse(
        success=True,
        report_type=req.report_type,
        generated_at=generated_at,
        period_days=req.period_days,
        incident_id=req.incident_id,
        markdown=markdown,
        stats={
            "counts": stats.get("counts"),
            "aggregates": stats.get("aggregates"),
            "selected_incident": stats.get("selected_incident"),
        },
        model=OLLAMA_MODEL,
    )


@router.get("/types")
async def get_report_types():
    """
    Liste les types de rapports disponibles.
    """
    return {
        "types": [
            {
                "id": "security_summary",
                "label": "Synthèse sécurité",
                "description": "Vue globale : alertes, incidents, MITRE, SAST, DAST et recommandations.",
                "incident_id_required": False,
            },
            {
                "id": "incident_analysis",
                "label": "Analyse d'incident",
                "description": "Analyse détaillée d'un incident précis avec corrélation IDS / SAST / DAST.",
                "incident_id_required": True,
            },
            {
                "id": "sast_dast_summary",
                "label": "Rapport SAST / DAST",
                "description": "Synthèse AppSec des vulnérabilités code et web.",
                "incident_id_required": False,
            },
            {
                "id": "executive_briefing",
                "label": "Briefing exécutif",
                "description": "Résumé court et non technique pour la direction.",
                "incident_id_required": False,
            },
        ]
    }