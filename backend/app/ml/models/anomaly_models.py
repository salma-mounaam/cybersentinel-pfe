# ============================================================
# M2 — Les 3 modèles d'anomalie
# Version corrigée v2 :
#   - IF contamination 0.08 → 0.02
#   - AE architecture élargie + seuil 1.5σ → 2.5σ
#   - AE predict_score normalisé par percentile 99 (pas clip brutal)
#   - OCSVM nu réduit à 0.02
# ============================================================

import numpy as np
import joblib
import logging
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from app.ml.features.extractor import FEATURE_DIM, EFFECTIVE_FEATURE_DIM
from app.ml.features.preprocessor import EFFECTIVE_FEATURE_DIM

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Isolation Forest
# ─────────────────────────────────────────────

class IsolationForestModel:
    """
    Isolation Forest entraîné sur trafic BENIGN uniquement.

    Corrections v2 :
    - contamination 0.08 → 0.02  (on entraîne sur du BENIGN pur,
      pas besoin d'un taux élevé — cela réduisait artificiellement
      le recall en augmentant le FPR)
    - score normalisé par percentile 99 des scores BENIGN au lieu
      de min/max (plus robuste aux outliers extrêmes)
    """

    def __init__(self, contamination: float = 0.02, n_estimators: int = 300):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=0.8,
            bootstrap=True,
            random_state=42,
            n_jobs=-1,
        )
        self._p1 = 0.0    # percentile 1 des scores BENIGN  (scores bas = anomalie)
        self._p99 = 1.0   # percentile 99 des scores BENIGN (scores hauts = normal)

    def fit(self, X_benign: np.ndarray) -> "IsolationForestModel":
        logger.info("IF entraînement sur %s flux BENIGN...", len(X_benign))
        self.model.fit(X_benign)

        raw = self.model.score_samples(X_benign)   # plus bas = plus anormal
        self._p1  = float(np.percentile(raw, 1))
        self._p99 = float(np.percentile(raw, 99))
        logger.info("IF bornes score (p1=%.4f, p99=%.4f)", self._p1, self._p99)
        return self

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        """
        Anomaly score dans [0, 1] : 1 = très anormal, 0 = très normal.
        Normalisation par percentile robuste plutôt que min/max.
        """
        raw = self.model.score_samples(X)
        denom = (self._p99 - self._p1) + 1e-9
        # score bas → anomaly score élevé
        normalized = 1.0 - (raw - self._p1) / denom
        return normalized.clip(0.0, 1.0)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        return (self.model.predict(X) == -1).astype(int)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "p1":  self._p1,
            "p99": self._p99,
        }, path)
        logger.info("IF sauvegardé : %s", path)

    def load(self, path: str) -> "IsolationForestModel":
        data = joblib.load(path)
        self.model = data["model"]
        self._p1  = data.get("p1",  0.0)
        self._p99 = data.get("p99", 1.0)
        return self


# ─────────────────────────────────────────────
# One-Class SVM
# ─────────────────────────────────────────────

class OneClassSVMModel:
    """
    One-Class SVM entraîné sur trafic BENIGN uniquement.

    Corrections v2 :
    - nu 0.05 → 0.02  (cohérent avec la contamination IF)
    - normalisation du score par percentile 99 (même logique que IF)
    """

    def __init__(self, nu: float = 0.02, kernel: str = "rbf"):
        self.model = OneClassSVM(nu=nu, kernel=kernel, gamma="scale")
        self._p1  = 0.0
        self._p99 = 1.0

    def fit(self, X_benign: np.ndarray) -> "OneClassSVMModel":
        # OCSVM est lent sur grand volume → on cap à 50 000 flux
        if len(X_benign) > 50_000:
            rng = np.random.default_rng(42)
            idx = rng.choice(len(X_benign), 50_000, replace=False)
            X_train = X_benign[idx]
            logger.info("OCSVM sous-échantillonnage 50K/%s", len(X_benign))
        else:
            X_train = X_benign

        logger.info("OCSVM entraînement sur %s flux BENIGN...", len(X_train))
        self.model.fit(X_train)

        raw = self.model.score_samples(X_train)
        self._p1  = float(np.percentile(raw, 1))
        self._p99 = float(np.percentile(raw, 99))
        logger.info("OCSVM bornes score (p1=%.4f, p99=%.4f)", self._p1, self._p99)
        return self

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        raw = self.model.score_samples(X)
        denom = (self._p99 - self._p1) + 1e-9
        normalized = 1.0 - (raw - self._p1) / denom
        return normalized.clip(0.0, 1.0)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        return (self.model.predict(X) == -1).astype(int)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "p1":  self._p1,
            "p99": self._p99,
        }, path)
        logger.info("OCSVM sauvegardé : %s", path)

    def load(self, path: str) -> "OneClassSVMModel":
        data = joblib.load(path)
        self.model = data["model"]
        self._p1  = data.get("p1",  0.0)
        self._p99 = data.get("p99", 1.0)
        return self


# ─────────────────────────────────────────────
# Autoencoder
# ─────────────────────────────────────────────

class AutoencoderModel:
    """
    Autoencoder entraîné sur trafic BENIGN uniquement.

    Corrections v2 :
    - Architecture élargie : 33→64→32→16→32→64→33
      (l'ancienne 33→16→8→16→33 était trop compressée pour 33 features,
       le modèle avait du mal à reconstruire le BENIGN correctement)
    - Seuil reconstruction 1.5σ → 2.5σ
      (1.5σ trop bas → trop de BENIGN classé anomalie → FPR élevé)
    - predict_score normalisé par p99 des erreurs BENIGN
      (évite le clip brutal qui écrasait les scores intermédiaires)
    - Dropout ajouté pour régularisation
    - Epochs 20 → 50 avec patience EarlyStopping augmentée
    """

    def __init__(self, input_dim: int = EFFECTIVE_FEATURE_DIM, encoding_dim: int = 16):
        self.input_dim    = input_dim
        self.encoding_dim = encoding_dim
        self.model        = None
        self.threshold    = None      # seuil binaire (2.5σ)
        self._error_p99   = None      # p99 erreurs BENIGN pour normalisation score

    def _build_model(self):
        import tensorflow as tf
        from tensorflow.keras import layers, Model, regularizers

        inputs = tf.keras.Input(shape=(self.input_dim,))

        # Encodeur
        x = layers.Dense(
            64, activation="relu",
            kernel_regularizer=regularizers.l2(1e-4)
        )(inputs)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.1)(x)

        x = layers.Dense(
            32, activation="relu",
            kernel_regularizer=regularizers.l2(1e-4)
        )(x)
        x = layers.BatchNormalization()(x)

        # Bottleneck
        encoded = layers.Dense(self.encoding_dim, activation="relu")(x)

        # Décodeur
        x = layers.Dense(
            32, activation="relu",
            kernel_regularizer=regularizers.l2(1e-4)
        )(encoded)
        x = layers.BatchNormalization()(x)

        x = layers.Dense(
            64, activation="relu",
            kernel_regularizer=regularizers.l2(1e-4)
        )(x)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.1)(x)

        outputs = layers.Dense(self.input_dim, activation="linear")(x)

        self.model = Model(inputs, outputs, name="autoencoder_v2")
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
            loss="mse"
        )
        logger.info("AE architecture : %s→64→32→%s→32→64→%s",
                    self.input_dim, self.encoding_dim, self.input_dim)
        return self.model

    def fit(
        self,
        X_benign: np.ndarray,
        epochs: int = 50,
        batch_size: int = 512,
    ) -> "AutoencoderModel":
        import tensorflow as tf

        self._build_model()
        logger.info("AE entraînement : %s flux, %s epochs max...", len(X_benign), epochs)

        self.model.fit(
            X_benign, X_benign,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.1,
            verbose=0,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(
                    monitor="val_loss",
                    patience=8,
                    restore_best_weights=True,
                    min_delta=1e-5,
                ),
                tf.keras.callbacks.ReduceLROnPlateau(
                    monitor="val_loss",
                    factor=0.5,
                    patience=4,
                    verbose=0,
                ),
            ],
        )

        # Calcul du seuil sur les erreurs de reconstruction BENIGN
        recon  = self.model.predict(X_benign, verbose=0)
        errors = np.mean(np.power(X_benign - recon, 2), axis=1)

        # Seuil binaire : 2.5σ (plus conservateur que 1.5σ)
        self.threshold = float(np.mean(errors) + 2.5 * np.std(errors))

        # p99 pour la normalisation continue du score
        self._error_p99 = float(np.percentile(errors, 99))

        logger.info(
            "AE seuil (2.5σ)=%.6f | p99_error=%.6f",
            self.threshold, self._error_p99
        )
        return self

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        recon = self.model.predict(X, verbose=0)
        return np.mean(np.power(X - recon, 2), axis=1)

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        """
        Score continu [0, 1] normalisé par p99 des erreurs BENIGN.
        Évite le clip brutal de l'ancienne version (errors / threshold)
        qui écrasait tous les scores > seuil à 1.0.
        """
        errors = self._reconstruction_errors(X)
        p99 = self._error_p99 if self._error_p99 else (self.threshold + 1e-9)
        return (errors / (p99 + 1e-9)).clip(0.0, 1.0)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        return (self._reconstruction_errors(X) > self.threshold).astype(int)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.model.save(path + "_keras")
        joblib.dump({
            "threshold":   self.threshold,
            "error_p99":   self._error_p99,
            "input_dim":   self.input_dim,
            "encoding_dim": self.encoding_dim,
        }, path + "_meta.pkl")
        logger.info("AE sauvegardé : %s", path)

    def load(self, path: str) -> "AutoencoderModel":
        import tensorflow as tf
        self.model = tf.keras.models.load_model(path + "_keras")
        meta = joblib.load(path + "_meta.pkl")
        self.threshold    = meta["threshold"]
        self._error_p99   = meta.get("error_p99", self.threshold)
        self.input_dim    = meta.get("input_dim", FEATURE_DIM)
        self.encoding_dim = meta.get("encoding_dim", 16)
        return self