# ============================================================
# M3 — API REST Fusion
# ============================================================

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.models.alert import Alert, AlertSource
from app.services.fusion_service import FPRValidator

router = APIRouter()


@router.get("/stats")
async def get_fusion_stats(db: AsyncSession = Depends(get_db)):
    """
    Statistiques de fusion pour la page IDS Monitor M9.
    Inclut la répartition des cas 1-5 et le FPR estimé.
    """
    # Compter par cas de fusion
    cases = {}
    for case_num in range(1, 6):
        count = await db.scalar(
            select(func.count(Alert.id))
            .where(Alert.fusion_case == case_num)
        )
        cases[f"case_{case_num}"] = count or 0

    # Total alertes M3
    total_fusion = await db.scalar(
        select(func.count(Alert.id))
        .where(Alert.source == AlertSource.M3_FUSION)
    )

    # Total alertes M1 seul (avant fusion)
    total_suricata = await db.scalar(
        select(func.count(Alert.id))
        .where(Alert.source == AlertSource.M1_SURICATA)
    )

    # Cas 5 = bruit éliminé = réduction FPR
    noise_eliminated = cases.get("case_5", 0)
    fpr_reduction = round(
        noise_eliminated / max(total_suricata or 1, 1) * 100, 1
    )

    return {
        "total_fused":      total_fusion,
        "total_suricata":   total_suricata,
        "cases":            cases,
        "noise_eliminated": noise_eliminated,
        "estimated_fpr_reduction_pct": fpr_reduction,
        "h2_on_track":      fpr_reduction >= 30.0,
    }


@router.post("/validate-h2")
async def validate_h2(payload: dict):
    """
    Valide formellement H2 avec des données de test A/B.
    Body: {"fpr_signature": 0.45, "fpr_fusion": 0.28}
    """
    result = FPRValidator.validate_h2(
        fpr_signature=payload.get("fpr_signature", 0.45),
        fpr_fusion=payload.get("fpr_fusion", 0.28),
    )
    return result
