# ============================================================
# M2 — Service ML temps réel
# Score une alerte Suricata via l'ensemble en < 50ms
# ============================================================

import numpy as np
import logging
from pathlib import Path
from typing import Optional

from app.ml.models.ensemble import EnsembleAnomalyDetector
from app.ml.features.extractor import extract_features_from_eve

logger = logging.getLogger(__name__)

MODEL_BASE_PATH = "data/models"


class MLAnomalyEngine:
    """
    Singleton chargé au démarrage de l'application.
    Fournit l'inférence ML en temps réel pour chaque alerte.
    """

    _instance = None
    _loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._loaded:
            self.detector = EnsembleAnomalyDetector()
            self._try_load_models()
            MLAnomalyEngine._loaded = True

    def _try_load_models(self):
        """Charge les modèles si disponibles, sinon log un avertissement."""
        models_exist = Path(f"{MODEL_BASE_PATH}/if_model.pkl").exists()
        if models_exist:
            try:
                self.detector.load(MODEL_BASE_PATH)
                logger.info("✅ Modèles ML chargés")
            except Exception as e:
                logger.warning(f"Impossible de charger les modèles ML: {e}")
        else:
            logger.warning(
                "Modèles ML non trouvés. "
                "Lancez le ré-entraînement : POST /api/ml/train"
            )

    async def score_event(self, event: dict) -> Optional[dict]:
        """
        Score un événement Eve JSON.
        Retourne None si les modèles ne sont pas chargés.
        """
        if not self._loaded:
            return None

        features = extract_features_from_eve(event)
        if features is None:
            return None

        try:
            result = self.detector.predict_single(features)
            return result
        except Exception as e:
            logger.error(f"Erreur scoring ML: {e}")
            return None

    def is_ready(self) -> bool:
        return Path(f"{MODEL_BASE_PATH}/if_model.pkl").exists()
