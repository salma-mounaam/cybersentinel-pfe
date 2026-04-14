# ============================================================
# M2 — Les 3 modèles d'anomalie
# Version corrigée et propre
# ============================================================

import numpy as np
import joblib
import logging
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from app.ml.features.extractor import FEATURE_DIM

logger = logging.getLogger(__name__)


class IsolationForestModel:

    def __init__(self, contamination: float = 0.08, n_estimators: int = 300):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=0.8,
            bootstrap=True,
            random_state=42,
            n_jobs=-1,
        )
        self._score_min = 0.0
        self._score_max = 1.0

    def fit(self, X_benign: np.ndarray) -> "IsolationForestModel":
        logger.info("IF entraînement sur %s flux BENIGN...", len(X_benign))
        self.model.fit(X_benign)

        raw = self.model.score_samples(X_benign)
        self._score_min = float(raw.min())
        self._score_max = float(raw.max())
        logger.info("IF bornes score : min=%.4f max=%.4f", self._score_min, self._score_max)
        return self

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        raw = self.model.score_samples(X)
        denom = (self._score_max - self._score_min) + 1e-9
        normalized = 1.0 - (raw - self._score_min) / denom
        return normalized.clip(0, 1)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        return (self.model.predict(X) == -1).astype(int)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "score_min": self._score_min,
            "score_max": self._score_max,
        }, path)

    def load(self, path: str):
        data = joblib.load(path)
        self.model = data["model"]
        self._score_min = data.get("score_min", 0.0)
        self._score_max = data.get("score_max", 1.0)
        return self


class OneClassSVMModel:

    def __init__(self, nu: float = 0.05, kernel: str = "rbf"):
        self.model = OneClassSVM(nu=nu, kernel=kernel, gamma="scale")
        self._score_min = 0.0
        self._score_max = 1.0

    def fit(self, X_benign: np.ndarray) -> "OneClassSVMModel":
        if len(X_benign) > 50000:
            rng = np.random.default_rng(42)
            idx = rng.choice(len(X_benign), 50000, replace=False)
            X_train = X_benign[idx]
            logger.info("OCSVM sous-échantillonnage 50K/%s", len(X_benign))
        else:
            X_train = X_benign

        logger.info("OCSVM entraînement sur %s flux BENIGN...", len(X_train))
        self.model.fit(X_train)

        raw = self.model.score_samples(X_train)
        self._score_min = float(raw.min())
        self._score_max = float(raw.max())
        logger.info("OCSVM bornes score : min=%.4f max=%.4f", self._score_min, self._score_max)
        return self

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        raw = self.model.score_samples(X)
        denom = (self._score_max - self._score_min) + 1e-9
        normalized = 1.0 - (raw - self._score_min) / denom
        return normalized.clip(0, 1)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        return (self.model.predict(X) == -1).astype(int)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "score_min": self._score_min,
            "score_max": self._score_max,
        }, path)

    def load(self, path: str):
        data = joblib.load(path)
        self.model = data["model"]
        self._score_min = data.get("score_min", 0.0)
        self._score_max = data.get("score_max", 1.0)
        return self


class AutoencoderModel:

    def __init__(self, input_dim: int = FEATURE_DIM, encoding_dim: int = 8):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model = None
        self.threshold = None

    def _build_model(self):
        import tensorflow as tf
        from tensorflow.keras import layers, Model

        inputs = tf.keras.Input(shape=(self.input_dim,))
        x = layers.Dense(16, activation="relu")(inputs)
        x = layers.Dense(self.encoding_dim, activation="relu")(x)
        x = layers.Dense(16, activation="relu")(x)
        outputs = layers.Dense(self.input_dim, activation="linear")(x)

        self.model = Model(inputs, outputs, name="autoencoder")
        self.model.compile(optimizer="adam", loss="mse")
        return self.model

    def fit(self, X_benign: np.ndarray, epochs: int = 20, batch_size: int = 512) -> "AutoencoderModel":
        self._build_model()
        logger.info("AE entraînement : %s flux, %s epochs...", len(X_benign), epochs)

        import tensorflow as tf
        self.model.fit(
            X_benign,
            X_benign,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.1,
            verbose=0,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(
                    patience=5,
                    restore_best_weights=True
                )
            ],
        )

        recon = self.model.predict(X_benign, verbose=0)
        errors = np.mean(np.power(X_benign - recon, 2), axis=1)
        self.threshold = float(np.mean(errors) + 1.5 * np.std(errors))
        logger.info("AE seuil reconstruction (1.5σ) : %.6f", self.threshold)
        return self

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        recon = self.model.predict(X, verbose=0)
        return np.mean(np.power(X - recon, 2), axis=1)

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        errors = self._reconstruction_errors(X)
        return (errors / (self.threshold + 1e-9)).clip(0, 1)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        return (self._reconstruction_errors(X) > self.threshold).astype(int)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.model.save(path + "_keras")
        joblib.dump({"threshold": self.threshold}, path + "_meta.pkl")

    def load(self, path: str):
        import tensorflow as tf
        self.model = tf.keras.models.load_model(path + "_keras")
        meta = joblib.load(path + "_meta.pkl")
        self.threshold = meta["threshold"]
        return self