# ============================================================
# M6 — API REST MITRE ATT&CK
# ============================================================

from fastapi import APIRouter, HTTPException
from app.services.mitre_service import (
    MitreEnrichmentEngine,
    LOCAL_ATTACK_DB,
    CWE_TO_MITRE
)

router = APIRouter()
engine = MitreEnrichmentEngine()


@router.get("/technique/{technique_id}")
async def get_technique(technique_id: str):
    """Détails complets d'une technique ATT&CK."""
    data = await engine.enrich_by_technique_id(technique_id)
    if not data:
        raise HTTPException(status_code=404, detail="Technique introuvable")
    return data


@router.get("/techniques")
async def list_techniques():
    """
    Liste toutes les techniques détectées dans CyberSentinel.
    Pour la matrice ATT&CK interactive M9.
    """
    from sqlalchemy import select, func
    from app.core.database import AsyncSessionLocal
    from app.models.alert import Alert

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(
                Alert.technique_id,
                Alert.technique_name,
                Alert.tactic,
                func.count(Alert.id).label("count")
            )
            .where(Alert.technique_id.isnot(None))
            .group_by(Alert.technique_id, Alert.technique_name, Alert.tactic)
            .order_by(func.count(Alert.id).desc())
        )
        rows = result.all()

    return {
        "techniques": [
            {
                "technique_id":   row.technique_id,
                "technique_name": row.technique_name,
                "tactic":         row.tactic,
                "count":          row.count,
                "mitre_url": f"https://attack.mitre.org/techniques/"
                             f"{row.technique_id.replace('.', '/')}/"
            }
            for row in rows
        ]
    }


@router.get("/matrix")
async def get_matrix_data():
    """
    Données formatées pour la matrice ATT&CK interactive M9.
    Retourne les techniques détectées avec leur fréquence et sévérité.
    """
    from sqlalchemy import select, func
    from app.core.database import AsyncSessionLocal
    from app.models.alert import Alert, SeverityLevel

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(
                Alert.technique_id,
                Alert.tactic,
                Alert.severity,
                func.count(Alert.id).label("count")
            )
            .where(Alert.technique_id.isnot(None))
            .group_by(
                Alert.technique_id,
                Alert.tactic,
                Alert.severity
            )
        )
        rows = result.all()

    # Construire la structure matrice
    matrix = {}
    for row in rows:
        tid = row.technique_id
        if tid not in matrix:
            matrix[tid] = {
                "technique_id": tid,
                "tactic":       row.tactic,
                "total_count":  0,
                "severities":   {}
            }
        matrix[tid]["total_count"] += row.count
        matrix[tid]["severities"][row.severity.value] = row.count

    return {
        "total_techniques": len(matrix),
        "matrix": list(matrix.values())
    }


@router.get("/cwe-mapping")
async def get_cwe_mapping():
    """Mapping CWE → technique MITRE pour la page SAST M9."""
    result = {}
    for cwe, tid in CWE_TO_MITRE.items():
        technique = LOCAL_ATTACK_DB.get(tid, {})
        result[cwe] = {
            "technique_id":   tid,
            "technique_name": technique.get("technique_name", tid),
            "tactic":         technique.get("tactic", "Unknown"),
        }
    return result


@router.post("/enrich")
async def enrich_alert(alert: dict):
    """
    Endpoint de test — enrichit manuellement une alerte.
    Body: {"source_module": "M1_suricata", "signature_id": 2012345, ...}
    """
    enriched = await engine.enrich_alert(alert)
    return enriched
