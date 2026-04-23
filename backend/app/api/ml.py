# ============================================================
# M2/M10 — API REST ML — Version corrigée
# Fix : _to_json_safe gère correctement les numpy arrays
# ============================================================

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pathlib import Path
from sqlalchemy import select, desc, update
import logging
import json
import shutil

router = APIRouter()
logger = logging.getLogger(__name__)


def _to_json_safe(obj):
    """
    Convertit récursivement les types numpy en types Python natifs
    pour permettre la sérialisation JSON/SQLAlchemy.
    Fix :
    - np.ndarray -> list
    - np.integer -> int
    - np.floating -> float
    - np.bool_ -> bool
    - obj.item() seulement pour les scalaires numpy de taille 1
    """
    import numpy as np

    if isinstance(obj, dict):
        return {str(k): _to_json_safe(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [_to_json_safe(v) for v in obj]

    if isinstance(obj, np.integer):
        return int(obj)

    if isinstance(obj, np.floating):
        return float(obj)

    if isinstance(obj, np.bool_):
        return bool(obj)

    if isinstance(obj, np.ndarray):
        return [_to_json_safe(v) for v in obj.tolist()]

    if hasattr(obj, "item") and hasattr(obj, "size") and obj.size == 1:
        return obj.item()

    return obj


@router.post("/train")
async def trigger_training(background_tasks: BackgroundTasks):
    """
    Lance la boucle adaptative M10 en tâche de fond.
    """
    background_tasks.add_task(_run_adaptive_loop)
    return {
        "status": "started",
        "message": "Boucle adaptative M10 lancée en arrière-plan. Consultez /api/ml/status pour suivre la progression."
    }


def _save_training_report(report: dict) -> Path:
    """
    Sauvegarde un rapport d'entraînement M10 dans data/models/.
    """
    model_dir = Path("data/models")
    model_dir.mkdir(parents=True, exist_ok=True)

    version = report.get("version", f"unknown_{Path().cwd().name}")
    report_path = model_dir / f"training_report_{version}.json"

    report_clean = _to_json_safe(report)

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_clean, f, indent=2, ensure_ascii=False, default=str)

    logger.info("Rapport M10 sauvegardé: %s", report_path)
    return report_path


@router.post("/train/sync")
async def trigger_training_sync():
    """
    Lance la boucle adaptative M10 en mode synchrone.
    Sauvegarde aussi un rapport JSON dans data/models/.
    """
    report = await _run_adaptive_loop_async()
    report_path = _save_training_report(report)

    report["report_file"] = report_path.name
    return report


@router.get("/status")
async def get_ml_status():
    """
    Statut des modèles ML actuellement chargés + statut M10.
    """
    from app.services.ml_service import MLAnomalyEngine, MODEL_BASE_PATH
    from app.services.ml_training import ModelRegistry

    engine = MLAnomalyEngine()
    registry = ModelRegistry()
    active = registry.get_active()
    history = registry.get_history(last_n=5)
    h3_status = registry.validate_h3()

    return {
        "models_loaded": bool(engine.is_ready()),
        "if_model": Path(f"{MODEL_BASE_PATH}/if_model.pkl").exists(),
        "ocsvm_model": Path(f"{MODEL_BASE_PATH}/ocsvm_model.pkl").exists(),
        "ae_model": Path(f"{MODEL_BASE_PATH}/ae_model_keras").exists(),
        "scaler": Path(f"{MODEL_BASE_PATH}/scaler.pkl").exists(),
        "active_version": active,
        "recent_versions": history,
        "h3_status": h3_status,
    }


@router.get("/loao-results")
async def get_loao_results():
    """
    Résultats de la dernière validation LOAO.
    On essaie d'abord depuis le registre M10, sinon fallback DB M2.
    """
    try:
        from app.services.ml_training import ModelRegistry

        registry = ModelRegistry()
        active = registry.get_active()

        if active:
            return {
                "version": active.get("version"),
                "metrics": active.get("metrics", {}),
                "is_active": active.get("is_active", False),
                "created_at": active.get("created_at"),
            }
    except Exception as e:
        logger.warning("Lecture registre M10 impossible: %s", e)

    from app.core.database import AsyncSessionLocal
    from app.models.ml_model import MLModelVersion

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(MLModelVersion)
            .order_by(desc(MLModelVersion.created_at))
            .limit(1)
        )
        model = result.scalar_one_or_none()

        if not model:
            return {"message": "Aucun modèle entraîné"}

        return {
            "version": model.version,
            "f1_mean": model.f1_mean,
            "recall_mean": model.recall_mean,
            "precision_mean": model.precision_mean,
            "fpr_mean": model.fpr_mean,
            "auc_roc_mean": model.auc_roc_mean,
            "metrics_by_type": model.metrics_by_type,
            "dataset_size": model.dataset_size,
            "is_active": model.is_active,
            "deployed_at": model.deployed_at,
        }


@router.get("/registry")
async def get_model_registry():
    """
    Historique complet des versions de modèles côté M10.
    """
    from app.services.ml_training import ModelRegistry

    registry = ModelRegistry()
    history = registry.get_history(last_n=20)
    active = registry.get_active()
    h3 = registry.validate_h3()

    return {
        "active_version": active["version"] if active else None,
        "total_versions": len(history),
        "versions": history,
        "h3_validation": h3,
    }


@router.post("/deploy/{version}")
async def deploy_version(version: str):
    """
    Déploie manuellement une version spécifique du registre M10.
    """
    from app.services.ml_training import AdaptiveMLLoop, ModelRegistry

    registry = ModelRegistry()
    target = registry.get_version(version)

    if not target:
        raise HTTPException(status_code=404, detail=f"Version introuvable: {version}")

    loop = AdaptiveMLLoop()
    result = loop._step_deploy(version)

    return {
        "success": result.get("success", False),
        "deployed_version": version,
        "model_path": result.get("model_path"),
    }


@router.post("/rollback")
async def manual_rollback():
    """
    Rollback manuel vers la version précédente active.
    """
    from app.services.ml_training import ModelRegistry
    from app.services.ml_service import MODEL_BASE_PATH, MLAnomalyEngine

    registry = ModelRegistry()
    history = registry.get_history(last_n=100)
    active = registry.get_active()

    if not active:
        raise HTTPException(status_code=400, detail="Aucune version active")

    if len(history) < 2:
        raise HTTPException(status_code=400, detail="Pas de version précédente disponible")

    active_version = active.get("version")
    active_index = None

    for i, item in enumerate(history):
        if item.get("version") == active_version:
            active_index = i
            break

    if active_index is None or active_index == 0:
        raise HTTPException(
            status_code=400,
            detail="Impossible de déterminer la version précédente"
        )

    prev_version = history[active_index - 1]
    prev_model_path = Path(prev_version.get("model_path", ""))

    if not prev_model_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Le dossier de la version précédente est introuvable"
        )

    model_base = Path(MODEL_BASE_PATH)

    for item in prev_model_path.iterdir():
        dest = model_base / item.name

        if item.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    registry.activate(prev_version["version"])

    try:
        engine = MLAnomalyEngine()
        engine.detector.load(str(model_base))
    except Exception as e:
        logger.warning("Reload mémoire après rollback échoué: %s", e)

    return {
        "success": True,
        "rolled_back_to": prev_version["version"],
        "previous_f1": prev_version.get("metrics", {}).get("f1_mean"),
    }


@router.get("/training-reports")
async def get_training_reports():
    """
    Liste les rapports de ré-entraînement M10.
    """
    model_dir = Path("data/models")
    reports = []

    for report_file in sorted(
        model_dir.glob("training_report_*.json"), reverse=True
    )[:10]:
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                report = json.load(f)

            reports.append({
                "file": report_file.name,
                "version": report.get("version"),
                "deployed": report.get("deployed"),
                "rolledback": report.get("rolledback"),
                "started_at": report.get("started_at"),
                "finished_at": report.get("finished_at"),
                "h3_status": report.get("h3_status"),
            })
        except Exception as e:
            logger.warning("Lecture rapport impossible %s: %s", report_file, e)

    return {"reports": reports}


@router.get("/h3-validation")
async def validate_h3():
    """
    Valide H3 : ΔF1 >= +0.10 entre v0 et vN.
    """
    from app.services.ml_training import ModelRegistry

    registry = ModelRegistry()
    return registry.validate_h3()


async def _run_adaptive_loop_async() -> dict:
    """
    Wrapper async pour la boucle adaptative M10.
    """
    import asyncio
    from app.services.ml_training import AdaptiveMLLoop

    loop = AdaptiveMLLoop()
    report = await asyncio.get_running_loop().run_in_executor(None, loop.run)
    return _to_json_safe(report)


async def _run_adaptive_loop():
    """
    Tâche de fond M10.
    Lance la boucle adaptative puis sauvegarde le rapport JSON.
    """
    report = await _run_adaptive_loop_async()
    _save_training_report(report)


async def _run_training():
    """
    Ancienne tâche M2 conservée pour compatibilité.
    """
    from datetime import datetime, timezone

    from app.ml.features.preprocessor import CICIDSPreprocessor
    from app.ml.models.ensemble import EnsembleAnomalyDetector
    from app.services.ml_service import MODEL_BASE_PATH
    from app.core.database import AsyncSessionLocal
    from app.models.ml_model import MLModelVersion

    logger.info("=== Début entraînement M2 ===")

    try:
        preprocessor = CICIDSPreprocessor()
        df = preprocessor.load_dataset()
        splits, X_benign = preprocessor.prepare_loao_splits(df)
        preprocessor.save_scaler(f"{MODEL_BASE_PATH}/scaler.pkl")

        detector = EnsembleAnomalyDetector()
        detector.fit(X_benign)

        loao_results = detector.run_loao_validation(splits)
        detector.save(MODEL_BASE_PATH)

        summary = loao_results.get("__summary__", {})

        metrics_by_type = _to_json_safe({
            k: v for k, v in loao_results.items()
            if k != "__summary__"
        })

        recall_mean = float(summary.get("mean_recall", 0.0) or 0.0)
        precision_mean = float(summary.get("mean_precision", 0.0) or 0.0)
        f1_mean = float(summary.get("mean_f1", 0.0) or 0.0)
        fpr_mean = float(summary.get("mean_fpr", 0.0) or 0.0)

        async with AsyncSessionLocal() as db:
            await db.execute(
                update(MLModelVersion).values(is_active=False)
            )

            model_version = MLModelVersion(
                version=f"v{int(datetime.now().timestamp())}",
                is_active=True,
                recall_mean=recall_mean,
                precision_mean=precision_mean,
                f1_mean=f1_mean,
                fpr_mean=fpr_mean,
                auc_roc_mean=0.0,
                dataset_size=int(len(X_benign)),
                dast_samples=0,
                metrics_by_type=metrics_by_type,
                model_path_if=f"{MODEL_BASE_PATH}/if_model.pkl",
                model_path_ocsvm=f"{MODEL_BASE_PATH}/ocsvm_model.pkl",
                model_path_ae=f"{MODEL_BASE_PATH}/ae_model",
                scaler_path=f"{MODEL_BASE_PATH}/scaler.pkl",
                deployed_at=datetime.now(timezone.utc),
                rollback_reason=None,
            )
            db.add(model_version)
            await db.commit()

        logger.info("=== Entraînement M2 terminé ✅ ===")

    except Exception as e:
        logger.exception("Erreur entraînement: %s", e)
        raise