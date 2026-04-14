# ============================================================
# M2 — Modèle Ensemble + protocole LOAO
# Score = 0.35×IF + 0.35×AE + 0.30×OCSVM
# Version corrigée : recall attaque + précision/F1 mixtes
# ============================================================

import numpy as np
import logging
from typing import Dict, Tuple
from sklearn.metrics import recall_score, f1_score, precision_score, confusion_matrix

from app.ml.models.anomaly_models import (
    IsolationForestModel,
    OneClassSVMModel,
    AutoencoderModel,
)
from app.ml.features.extractor import FEATURE_DIM
from app.core.config import settings

logger = logging.getLogger(__name__)

W_IF = settings.ML_IF_WEIGHT
W_AE = settings.ML_AE_WEIGHT
W_OCSVM = settings.ML_OCSVM_WEIGHT


class EnsembleAnomalyDetector:

    def __init__(self):
        self.if_model = IsolationForestModel()
        self.ocsvm_model = OneClassSVMModel()
        self.ae_model = AutoencoderModel(input_dim=FEATURE_DIM)
        self.threshold = settings.ML_ANOMALY_THRESHOLD

    def fit(self, X_benign: np.ndarray) -> "EnsembleAnomalyDetector":
        logger.info("=== Entraînement Ensemble M2 ===")
        self.if_model.fit(X_benign)
        logger.info("✅ Isolation Forest entraîné")
        self.ocsvm_model.fit(X_benign)
        logger.info("✅ One-Class SVM entraîné")
        self.ae_model.fit(X_benign)
        logger.info("✅ Autoencoder entraîné")
        return self

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        if_scores = self.if_model.predict_score(X)
        ae_scores = self.ae_model.predict_score(X)
        ocsvm_scores = self.ocsvm_model.predict_score(X)
        return (W_IF * if_scores + W_AE * ae_scores + W_OCSVM * ocsvm_scores).clip(0, 1)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        vote_if = self.if_model.predict_label(X)
        vote_ae = self.ae_model.predict_label(X)
        vote_ocsvm = self.ocsvm_model.predict_label(X)
        return ((vote_if + vote_ae + vote_ocsvm) >= 2).astype(int)

    def predict_single(self, x: np.ndarray) -> dict:
        x = x.reshape(1, -1)

        if_score = float(self.if_model.predict_score(x)[0])
        ae_score = float(self.ae_model.predict_score(x)[0])
        ocsvm_score = float(self.ocsvm_model.predict_score(x)[0])

        vote_if = int(self.if_model.predict_label(x)[0])
        vote_ae = int(self.ae_model.predict_label(x)[0])
        vote_ocsvm = int(self.ocsvm_model.predict_label(x)[0])
        total_votes = vote_if + vote_ae + vote_ocsvm

        ensemble = float(W_IF * if_score + W_AE * ae_score + W_OCSVM * ocsvm_score)

        return {
            "if_score": round(if_score, 4),
            "ae_score": round(ae_score, 4),
            "ocsvm_score": round(ocsvm_score, 4),
            "ensemble_score": round(ensemble, 4),
            "votes": total_votes,
            "is_anomaly": bool(total_votes >= 2),
            "threshold": float(self.threshold),
        }

    def run_loao_validation(
        self,
        splits: Dict[str, Tuple[np.ndarray, np.ndarray]],
    ) -> dict:
        """
        LOAO corrigé :
        - train sur 90% BENIGN
        - holdout 10% BENIGN pour mesurer FPR
        - précision/F1 sur mélange BENIGN+attaque
        - recall utilisé pour H1 = recall attaque pure
        """
        logger.info("=== Protocole LOAO corrigé ===")
        results = {}
        recalls = []
        precisions = []
        f1s = []
        fprs = []

        rng = np.random.default_rng(42)

        for attack_type, (X_train, X_attack_test) in splits.items():
            logger.info("LOAO round : %s", attack_type)

            n_holdout = max(1, int(len(X_train) * 0.10))
            idx_holdout = rng.choice(len(X_train), n_holdout, replace=False)

            X_benign_holdout = X_train[idx_holdout]

            mask = np.ones(len(X_train), dtype=bool)
            mask[idx_holdout] = False
            X_train_90 = X_train[mask]

            temp = EnsembleAnomalyDetector()
            temp.fit(X_train_90)

            X_eval = np.vstack([X_benign_holdout, X_attack_test])
            y_eval = np.hstack([
                np.zeros(len(X_benign_holdout), dtype=int),
                np.ones(len(X_attack_test), dtype=int),
            ])

            y_pred = temp.predict_label(X_eval)

            # métriques mixtes
            precision = precision_score(y_eval, y_pred, zero_division=0)
            f1 = f1_score(y_eval, y_pred, zero_division=0)

            tn, fp, fn, tp = confusion_matrix(y_eval, y_pred, labels=[0, 1]).ravel()
            fpr = float(fp / max(fp + tn, 1))

            # recall attaque pure pour H1
            attack_preds = y_pred[len(X_benign_holdout):]
            attack_true = np.ones(len(X_attack_test), dtype=int)
            attack_recall = recall_score(attack_true, attack_preds, zero_division=0)
            n_detected = int(attack_preds.sum())

            results[attack_type] = {
                "recall": float(round(attack_recall, 4)),
                "precision": float(round(precision, 4)),
                "f1": float(round(f1, 4)),
                "fpr": float(round(fpr, 4)),
                "n_test_attack": int(len(X_attack_test)),
                "n_benign_holdout": int(len(X_benign_holdout)),
                "n_detected_attack": n_detected,
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn),
                "h1_passed": bool(attack_recall >= 0.70),
            }

            recalls.append(float(attack_recall))
            precisions.append(float(precision))
            f1s.append(float(f1))
            fprs.append(float(fpr))

            logger.info(
                "%s | Recall=%.3f Precision=%.3f F1=%.3f FPR=%.4f %s",
                attack_type,
                attack_recall,
                precision,
                f1,
                fpr,
                "✅ H1" if attack_recall >= 0.70 else "❌ H1",
            )

        mean_recall = float(np.mean(recalls)) if recalls else 0.0
        mean_precision = float(np.mean(precisions)) if precisions else 0.0
        mean_f1 = float(np.mean(f1s)) if f1s else 0.0
        mean_fpr = float(np.mean(fprs)) if fprs else 0.0

        results["__summary__"] = {
            "mean_recall": float(round(mean_recall, 4)),
            "mean_precision": float(round(mean_precision, 4)),
            "mean_f1": float(round(mean_f1, 4)),
            "mean_fpr": float(round(mean_fpr, 4)),
            "h1_validated": bool(mean_recall >= 0.70),
            "n_attack_types": int(len(splits)),
        }

        logger.info(
            "=== LOAO terminé | Recall=%.3f | Precision=%.3f | F1=%.3f | FPR=%.4f | H1=%s ===",
            mean_recall,
            mean_precision,
            mean_f1,
            mean_fpr,
            "✅ VALIDÉE" if mean_recall >= 0.70 else "❌ NON VALIDÉE",
        )
        return results

    def save(self, base_path: str = "data/models"):
        self.if_model.save(f"{base_path}/if_model.pkl")
        self.ocsvm_model.save(f"{base_path}/ocsvm_model.pkl")
        self.ae_model.save(f"{base_path}/ae_model")
        logger.info("Ensemble sauvegardé dans %s/", base_path)

    def load(self, base_path: str = "data/models"):
        self.if_model.load(f"{base_path}/if_model.pkl")
        self.ocsvm_model.load(f"{base_path}/ocsvm_model.pkl")
        self.ae_model.load(f"{base_path}/ae_model")
        logger.info("Ensemble chargé depuis %s/", base_path)
        return self