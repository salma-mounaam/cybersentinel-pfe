# ============================================================
# M7 — API REST Scoring (endpoints complémentaires)
# ============================================================

from fastapi import APIRouter
from app.core.config import settings
from app.services.scoring_service import RiskScoringEngine, DEFAULT_ASSET_CRITICALITY

router = APIRouter()
engine = RiskScoringEngine()


@router.get("/weights")
async def get_weights():
    """Retourne les pondérations actuelles du score R."""
    return {
        "w_a": settings.SCORE_R_WEIGHT_A,
        "w_v": settings.SCORE_R_WEIGHT_V,
        "w_e": settings.SCORE_R_WEIGHT_E,
        "w_c": settings.SCORE_R_WEIGHT_C,
        "formula": "R = w_a*A + w_v*V + w_e*E + w_c*C",
    }


@router.get("/sla")
async def get_sla_config():
    """Configuration SLA par niveau de sévérité."""
    return {
        "CRITIQUE": "< 1 heure",
        "ELEVE": "< 4 heures",
        "MOYEN": "< 48 heures",
        "FAIBLE": "prochain sprint",
    }


@router.get("/asset-criticality")
async def get_asset_criticality():
    """Table de criticité des assets (configurable Admin M9)."""
    return DEFAULT_ASSET_CRITICALITY