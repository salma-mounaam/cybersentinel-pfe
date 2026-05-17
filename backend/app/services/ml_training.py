# ============================================================
# M10 — Boucle Adaptative ML
# Celery Beat 02:00 → Dataset enrichi → Ré-entraînement →
# LOAO Validation → Auto-deploy si score composite↑ → Rollback sinon
# Valide H3 : ΔF1 >= +0.10 après 4 semaines
#
# Version corrigée v3 :
#   - PCAP DAST réellement convertis en features ML
#   - Fusion réelle : X_benign_cicids + X_dast_scaled
#   - _load_dast_captures() retourne maintenant X_dast
#   - Alignement automatique du nombre de features DAST avec le scaler
#   - Décision déploiement : score composite
#     score = Recall×0.50 + F1×0.30 − FPR×0.20
#   - Garde-fou absolu : FPR > 15% → refus
#   - recall_mean inclus dans les métriques enregistrées
# ============================================================

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np

from app.core.celery_app import celery_app
from app.ml.features.preprocessor import CICIDSPreprocessor
from app.ml.models.ensemble import EnsembleAnomalyDetector
from app.services.websocket_manager import ws_manager

logger = logging.getLogger(__name__)


# ============================================================
# Chemins
# ============================================================

MODEL_BASE = Path("data/models")
BACKUP_DIR = Path("data/models/backups")
PCAP_DIR = Path("data/dast_captures")
REGISTRY_PATH = Path("data/models/registry.json")


# ============================================================
# Registre local des modèles
# ============================================================

class ModelRegistry:
    """
    Registre local des versions de modèles.
    Garde l'historique de toutes les versions avec leurs métriques.
    """

    def __init__(self):
        REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not REGISTRY_PATH.exists():
            self._save({
                "versions": [],
                "active_version": None,
            })

    def _load(self) -> dict:
        if not REGISTRY_PATH.exists():
            return {
                "versions": [],
                "active_version": None,
            }

        try:
            with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Registry illisible, réinitialisation : %s", e)
            return {
                "versions": [],
                "active_version": None,
            }

    def _save(self, data: dict):
        REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def get_active(self) -> Optional[dict]:
        data = self._load()
        active_version = data.get("active_version")

        if not active_version:
            return None

        for version in data.get("versions", []):
            if version.get("version") == active_version:
                return version

        return None

    def get_version(self, version: str) -> Optional[dict]:
        data = self._load()

        for v in data.get("versions", []):
            if v.get("version") == version:
                return v

        return None

    def register(self, version: str, metrics: dict, model_path: str):
        data = self._load()

        entry = {
            "version": version,
            "metrics": metrics,
            "model_path": model_path,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": False,
        }

        data.setdefault("versions", []).append(entry)
        self._save(data)

        logger.info(
            "Version enregistrée: %s | Recall=%.4f | F1=%.4f | FPR=%.4f",
            version,
            float(metrics.get("recall_mean", 0.0) or 0.0),
            float(metrics.get("f1_mean", 0.0) or 0.0),
            float(metrics.get("fpr_mean", 0.0) or 0.0),
        )

    def activate(self, version: str):
        data = self._load()

        found = False

        for v in data.get("versions", []):
            is_target = v.get("version") == version
            v["is_active"] = is_target

            if is_target:
                found = True

        if not found:
            raise ValueError(f"Version introuvable dans le registre: {version}")

        data["active_version"] = version
        self._save(data)

        logger.info("Version activée: %s", version)

    def get_history(self, last_n: int = 10) -> list:
        data = self._load()
        versions = data.get("versions", [])

        return versions[-last_n:] if last_n > 0 else versions

    def validate_h3(self) -> dict:
        """
        Valide H3 : ΔF1 >= +0.10 entre v0 et version active.
        """
        data = self._load()
        versions = data.get("versions", [])

        if len(versions) < 2:
            return {
                "h3_validated": False,
                "message": "Pas assez de versions pour valider H3",
                "delta_f1": 0.0,
                "target": "ΔF1 >= +0.10 après 4 semaines",
            }

        v0 = versions[0]
        active = self.get_active() or versions[-1]

        f1_v0 = float(v0.get("metrics", {}).get("f1_mean", 0.0) or 0.0)
        f1_vn = float(active.get("metrics", {}).get("f1_mean", 0.0) or 0.0)

        delta = f1_vn - f1_v0

        return {
            "h3_validated": delta >= 0.10,
            "delta_f1": round(delta, 4),
            "f1_v0": round(f1_v0, 4),
            "f1_vN": round(f1_vn, 4),
            "version_v0": v0.get("version"),
            "version_vN": active.get("version"),
            "target": "ΔF1 >= +0.10 après 4 semaines",
        }


# ============================================================
# Boucle adaptative
# ============================================================

class AdaptiveMLLoop:
    """
    Implémente la boucle adaptative Purple Team.
    Exécutée par Celery Beat chaque nuit à 02:00.
    """

    def __init__(self):
        self.registry = ModelRegistry()
        self.preprocessor = CICIDSPreprocessor()

    def run(self) -> dict:
        start_time = datetime.now(timezone.utc)
        version = f"v_{int(start_time.timestamp())}"

        logger.info("=== M10 Boucle Adaptative — %s ===", version)

        report = {
            "version": version,
            "started_at": start_time.isoformat(),
            "steps": {},
            "deployed": False,
            "rolledback": False,
        }

        try:
            # Étape 1 — Collecte dataset enrichi
            step1 = self._step_collect_dataset()
            report["steps"]["1_dataset"] = step1

            X_benign = step1.get("X_benign")
            splits = step1.get("splits")

            if X_benign is None or len(X_benign) == 0:
                raise ValueError("Dataset BENIGN vide — ré-entraînement annulé")

            # Étape 2 — Entraînement
            step2 = self._step_train(X_benign, version)
            report["steps"]["2_train"] = step2

            # Étape 3 — Validation LOAO
            if splits:
                step3 = self._step_validate_loao(splits, version)
            else:
                step3 = {
                    "success": False,
                    "skipped": True,
                    "reason": "Splits LOAO non disponibles",
                    "metrics": {
                        "precision_mean": 0.0,
                        "recall_mean": 0.0,
                        "f1_mean": 0.0,
                        "fpr_mean": 1.0,
                        "h1_validated": False,
                        "by_attack": {},
                    },
                }

            report["steps"]["3_loao"] = step3

            # Étape 4 — Décision
            decision = self._step_deployment_decision(version, report["steps"])
            report["steps"]["4_decision"] = decision

            if decision.get("deploy"):
                step5 = self._step_deploy(version)
                report["steps"]["5_deploy"] = step5
                report["deployed"] = True
                self._notify_deployment(version, step3)
            else:
                step5 = self._step_rollback(
                    version,
                    decision.get("reason", "Performances insuffisantes"),
                )
                report["steps"]["5_rollback"] = step5
                report["rolledback"] = True
                self._notify_rollback(
                    version,
                    decision.get("reason", "Performances insuffisantes"),
                )

        except Exception as e:
            logger.exception("M10 erreur: %s", e)

            report["error"] = str(e)
            report["rolledback"] = True

            try:
                report["steps"]["5_rollback"] = self._step_rollback(version, str(e))
            except Exception as rollback_error:
                report["steps"]["5_rollback"] = {
                    "success": False,
                    "reason": f"Rollback échoué: {rollback_error}",
                }

        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["h3_status"] = self.registry.validate_h3()

        logger.info(
            "=== M10 terminé | deployed=%s | rolledback=%s ===",
            report["deployed"],
            report["rolledback"],
        )

        return report

    # ============================================================
    # Étape 1 — Collecte dataset enrichi
    # ============================================================

    def _step_collect_dataset(self) -> dict:
        """
        Collecte et fusionne le dataset CIC-IDS + captures DAST.

        Avant :
            les PCAP étaient seulement lus et comptés.

        Maintenant :
            PCAP DAST → features ML → normalisation scaler CICIDS
            → fusion avec X_benign_cicids.

        Le trafic DAST est ajouté au BENIGN car il représente le trafic
        applicatif observé pendant les scans ZAP dans ton environnement.
        """
        logger.info("Étape 1 — Collecte dataset enrichi CICIDS + DAST")

        # 1. Charger CIC-IDS
        df = self.preprocessor.load_dataset()

        if df is None or getattr(df, "empty", False):
            raise ValueError("Le dataset CIC-IDS est vide ou introuvable")

        # 2. Préparer les splits LOAO + BENIGN CICIDS
        splits, X_benign_cicids = self.preprocessor.prepare_loao_splits(df)

        if X_benign_cicids is None or len(X_benign_cicids) == 0:
            raise ValueError("X_benign_cicids est vide après préparation LOAO")

        X_benign_total = X_benign_cicids

        # 3. Charger et convertir les PCAP DAST
        dast_summary = self._load_dast_captures()
        X_dast = dast_summary.get("X_dast")

        # 4. Fusionner DAST si disponible
        if X_dast is not None and len(X_dast) > 0:
            try:
                X_dast = self._align_dast_features(X_dast)

                X_dast_scaled = self.preprocessor.scaler.transform(X_dast)
                X_dast_scaled = np.nan_to_num(
                    X_dast_scaled,
                    nan=0.0,
                    posinf=0.0,
                    neginf=0.0,
                )

                X_benign_total = np.vstack([
                    X_benign_cicids,
                    X_dast_scaled,
                ])

                logger.info(
                    "Dataset enrichi : CICIDS=%d + DAST=%d = %d flux BENIGN",
                    len(X_benign_cicids),
                    len(X_dast_scaled),
                    len(X_benign_total),
                )

            except Exception as e:
                logger.warning(
                    "Impossible de fusionner les features DAST : %s — "
                    "entraînement sur CICIDS seul",
                    e,
                )
                X_benign_total = X_benign_cicids
        else:
            logger.info(
                "Pas de captures DAST disponibles — entraînement sur CICIDS seul : %d flux",
                len(X_benign_cicids),
            )

        # 5. Sauvegarder le scaler
        MODEL_BASE.mkdir(parents=True, exist_ok=True)

        try:
            self.preprocessor.save_scaler(str(MODEL_BASE / "scaler.pkl"))
        except Exception as e:
            logger.warning("Impossible de sauvegarder le scaler : %s", e)

        return {
            "success": True,
            "dataset_rows": int(len(df)),
            "dataset_size": int(len(X_benign_total)),
            "cicids_size": int(len(X_benign_cicids)),
            "dast_samples": int(dast_summary.get("dast_samples", 0)),
            "pcap_files": int(dast_summary.get("pcap_files", 0)),
            "n_splits": int(len(splits)) if splits else 0,
            "X_benign": X_benign_total,
            "splits": splits,
        }

    def _load_dast_captures(self) -> dict:
        """
        Charge les captures PCAP DAST et les convertit en features ML.

        Retourne :
            {
                "pcap_files": nombre de fichiers PCAP,
                "dast_samples": nombre de flux convertis,
                "X_dast": np.ndarray ou None
            }
        """
        try:
            from app.services.dast_pcap_to_features import load_all_dast_pcaps
        except ImportError as e:
            logger.warning("Module dast_pcap_to_features indisponible : %s", e)
            return {
                "pcap_files": 0,
                "dast_samples": 0,
                "X_dast": None,
            }

        if not PCAP_DIR.exists():
            logger.info("Dossier PCAP absent : %s", PCAP_DIR)
            return {
                "pcap_files": 0,
                "dast_samples": 0,
                "X_dast": None,
            }

        pcap_files = sorted(PCAP_DIR.glob("*.pcap"))

        if not pcap_files:
            logger.info("Aucun fichier PCAP dans %s", PCAP_DIR)
            return {
                "pcap_files": 0,
                "dast_samples": 0,
                "X_dast": None,
            }

        try:
            X_dast = load_all_dast_pcaps(str(PCAP_DIR))
        except Exception as e:
            logger.warning("Erreur conversion PCAP DAST : %s", e)
            return {
                "pcap_files": len(pcap_files),
                "dast_samples": 0,
                "X_dast": None,
            }

        if X_dast is None or len(X_dast) == 0:
            logger.info(
                "PCAP trouvés mais aucun flux DAST exploitable : %d fichiers",
                len(pcap_files),
            )
            return {
                "pcap_files": len(pcap_files),
                "dast_samples": 0,
                "X_dast": None,
            }

        X_dast = np.asarray(X_dast, dtype=np.float32)
        X_dast = np.nan_to_num(
            X_dast,
            nan=0.0,
            posinf=0.0,
            neginf=0.0,
        )

        logger.info(
            "DAST captures : %d fichiers PCAP → %d flux convertis | shape=%s",
            len(pcap_files),
            len(X_dast),
            X_dast.shape,
        )

        return {
            "pcap_files": len(pcap_files),
            "dast_samples": int(len(X_dast)),
            "X_dast": X_dast,
        }

    def _align_dast_features(self, X_dast: np.ndarray) -> np.ndarray:
        """
        Aligne le nombre de features DAST avec le scaler CICIDS.

        Pourquoi :
            ton pipeline CICIDS peut attendre 29, 33 ou autre nombre
            de colonnes selon la version de extract_features/preprocessor.

        Cas gérés :
            - même nombre de colonnes : rien à faire
            - DAST a moins de colonnes : padding avec zéros
            - DAST a trop de colonnes : troncature
        """
        if X_dast is None or len(X_dast) == 0:
            return X_dast

        X_dast = np.asarray(X_dast, dtype=np.float32)
        X_dast = np.nan_to_num(
            X_dast,
            nan=0.0,
            posinf=0.0,
            neginf=0.0,
        )

        expected = getattr(self.preprocessor.scaler, "n_features_in_", None)

        if expected is None:
            logger.warning(
                "Scaler sans n_features_in_ — features DAST utilisées sans alignement | shape=%s",
                X_dast.shape,
            )
            return X_dast

        current = X_dast.shape[1]

        if current == expected:
            return X_dast

        if current < expected:
            missing = expected - current
            padding = np.zeros((X_dast.shape[0], missing), dtype=np.float32)

            X_fixed = np.hstack([
                X_dast,
                padding,
            ])

            logger.warning(
                "Features DAST paddées : %d → %d colonnes",
                current,
                expected,
            )

            return X_fixed

        X_fixed = X_dast[:, :expected]

        logger.warning(
            "Features DAST tronquées : %d → %d colonnes",
            current,
            expected,
        )

        return X_fixed

    # ============================================================
    # Étape 2 — Ré-entraînement
    # ============================================================

    def _step_train(self, X_benign: np.ndarray, version: str) -> dict:
        logger.info("Étape 2 — Entraînement sur %d flux BENIGN", len(X_benign))

        version_path = MODEL_BASE / version
        version_path.mkdir(parents=True, exist_ok=True)

        detector = EnsembleAnomalyDetector()
        detector.fit(X_benign)
        detector.save(str(version_path))

        scaler_src = MODEL_BASE / "scaler.pkl"
        scaler_dst = version_path / "scaler.pkl"

        if scaler_src.exists():
            shutil.copy2(str(scaler_src), str(scaler_dst))

        return {
            "success": True,
            "model_path": str(version_path),
            "dataset_size": int(len(X_benign)),
        }

    # ============================================================
    # Étape 3 — Validation LOAO
    # ============================================================

    def _step_validate_loao(self, splits: dict, version: str) -> dict:
        logger.info("Étape 3 — Validation LOAO")

        version_path = MODEL_BASE / version

        detector = EnsembleAnomalyDetector()
        detector.load(str(version_path))

        loao_results = detector.run_loao_validation(splits)
        summary = loao_results.get("__summary__", {})

        recall_mean = float(summary.get("mean_recall", 0.0) or 0.0)
        precision_mean = float(summary.get("mean_precision", recall_mean) or recall_mean)

        f1_mean = 0.0
        if precision_mean + recall_mean > 0:
            f1_mean = 2 * (precision_mean * recall_mean) / (
                precision_mean + recall_mean
            )

        # FPR mesuré sur le BENIGN complet du premier split.
        try:
            first_split = next(iter(splits.values()))
            X_benign_eval = first_split[0]

            benign_preds = np.array(
                detector.predict_label(X_benign_eval)
            ).astype(int)

            fpr_mean = float(benign_preds.sum()) / max(len(benign_preds), 1)
        except Exception as e:
            logger.warning("Calcul FPR impossible : %s", e)
            fpr_mean = 1.0

        metrics = {
            "precision_mean": round(precision_mean, 4),
            "recall_mean": round(recall_mean, 4),
            "f1_mean": round(float(f1_mean), 4),
            "fpr_mean": round(float(fpr_mean), 4),
            "h1_validated": recall_mean >= 0.70,
            "by_attack": {
                k: _clean_report(v)
                for k, v in loao_results.items()
                if k != "__summary__"
            },
        }

        self.registry.register(
            version=version,
            metrics=metrics,
            model_path=str(version_path),
        )

        return {
            "success": True,
            "metrics": metrics,
            "loao_results": _clean_report(loao_results),
        }

    # ============================================================
    # Étape 4 — Décision de déploiement
    # ============================================================

    def _step_deployment_decision(self, version: str, steps: dict) -> dict:
        logger.info("Étape 4 — Décision déploiement")

        loao_step = steps.get("3_loao", {})
        new_metrics = loao_step.get("metrics", {})

        new_f1 = float(new_metrics.get("f1_mean", 0.0) or 0.0)
        new_fpr = float(new_metrics.get("fpr_mean", 1.0) or 1.0)
        new_recall = float(new_metrics.get("recall_mean", new_f1) or new_f1)

        active = self.registry.get_active()

        if not active:
            return {
                "deploy": True,
                "reason": "Premier déploiement — pas de baseline",
                "new_f1": round(new_f1, 4),
                "new_fpr": round(new_fpr, 4),
                "new_recall": round(new_recall, 4),
            }

        current_f1 = float(active.get("metrics", {}).get("f1_mean", 0.0) or 0.0)
        current_fpr = float(active.get("metrics", {}).get("fpr_mean", 1.0) or 1.0)
        current_recall = float(
            active.get("metrics", {}).get("recall_mean", current_f1) or current_f1
        )

        # ── Score composite ─────────────────────────────────────
        # score = Recall×0.50 + F1×0.30 − FPR×0.20
        #
        # Garde-fou dur :
        #   FPR > 15% → refus absolu
        # ───────────────────────────────────────────────────────

        MAX_FPR = 0.15

        def composite(f1: float, fpr: float, recall: float) -> float:
            return recall * 0.50 + f1 * 0.30 - fpr * 0.20

        score_new = composite(new_f1, new_fpr, new_recall)
        score_old = composite(current_f1, current_fpr, current_recall)

        fpr_acceptable = new_fpr <= MAX_FPR
        score_improved = score_new > score_old + 0.01

        logger.info(
            "Score composite : old=%.4f → new=%.4f | "
            "Recall: %.4f→%.4f | F1: %.4f→%.4f | FPR: %.4f→%.4f",
            score_old,
            score_new,
            current_recall,
            new_recall,
            current_f1,
            new_f1,
            current_fpr,
            new_fpr,
        )

        if fpr_acceptable and score_improved:
            reason = (
                f"Score composite amélioré: {score_old:.4f} → {score_new:.4f} | "
                f"Recall: {current_recall:.4f} → {new_recall:.4f} | "
                f"F1: {current_f1:.4f} → {new_f1:.4f} | "
                f"FPR: {current_fpr:.4f} → {new_fpr:.4f}"
            )

            return {
                "deploy": True,
                "reason": reason,
                "current_f1": round(current_f1, 4),
                "new_f1": round(new_f1, 4),
                "current_fpr": round(current_fpr, 4),
                "new_fpr": round(new_fpr, 4),
                "current_recall": round(current_recall, 4),
                "new_recall": round(new_recall, 4),
                "f1_delta": round(new_f1 - current_f1, 4),
                "recall_delta": round(new_recall - current_recall, 4),
                "score_composite_delta": round(score_new - score_old, 4),
            }

        if not fpr_acceptable:
            reason = (
                f"FPR trop élevé: {new_fpr:.4f} > seuil max {MAX_FPR} — "
                f"refus absolu, trop de faux positifs en production"
            )
        else:
            reason = (
                f"Score composite insuffisant: {score_old:.4f} → {score_new:.4f} | "
                f"Recall: {current_recall:.4f} → {new_recall:.4f} | "
                f"F1: {current_f1:.4f} → {new_f1:.4f} | "
                f"FPR: {current_fpr:.4f} → {new_fpr:.4f}"
            )

        return {
            "deploy": False,
            "reason": reason,
            "current_f1": round(current_f1, 4),
            "new_f1": round(new_f1, 4),
            "current_fpr": round(current_fpr, 4),
            "new_fpr": round(new_fpr, 4),
            "current_recall": round(current_recall, 4),
            "new_recall": round(new_recall, 4),
        }

    # ============================================================
    # Étape 5a — Déploiement automatique
    # ============================================================

    def _step_deploy(self, version: str) -> dict:
        logger.info("Étape 5 — Déploiement %s", version)

        version_path = MODEL_BASE / version

        if not version_path.exists():
            raise FileNotFoundError(f"Dossier version introuvable: {version_path}")

        active = self.registry.get_active()

        # Backup de la version active
        if active and active.get("model_path"):
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)

            backup_path = BACKUP_DIR / f"backup_{active['version']}"
            src_path = Path(active["model_path"])

            if src_path.exists() and not backup_path.exists():
                shutil.copytree(
                    src_path,
                    backup_path,
                    dirs_exist_ok=True,
                )

        # Copie du nouveau modèle vers MODEL_BASE
        for item in version_path.iterdir():
            dest = MODEL_BASE / item.name

            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        self.registry.activate(version)

        # Reload en mémoire
        try:
            from app.services.ml_service import MLAnomalyEngine

            engine = MLAnomalyEngine()
            engine.detector.load(str(MODEL_BASE))

            logger.info("✅ Modèle %s chargé en mémoire", version)

        except Exception as e:
            logger.warning("Rechargement mémoire échoué: %s", e)

        return {
            "success": True,
            "version": version,
            "model_path": str(MODEL_BASE),
        }

    # ============================================================
    # Étape 5b — Rollback
    # ============================================================

    def _step_rollback(self, version: str, reason: str) -> dict:
        logger.warning("Rollback — %s rejeté: %s", version, reason)

        active = self.registry.get_active()
        version_path = MODEL_BASE / version

        if version_path.exists():
            shutil.rmtree(version_path, ignore_errors=True)

        return {
            "success": True,
            "rejected": version,
            "reason": reason,
            "active_version": active["version"] if active else None,
        }

    # ============================================================
    # Notifications WebSocket
    # ============================================================

    def _notify_deployment(self, version: str, loao_result: dict):
        metrics = loao_result.get("metrics", {})

        self._safe_broadcast({
            "type": "ML_DEPLOYED",
            "version": version,
            "f1_mean": metrics.get("f1_mean", 0),
            "recall": metrics.get("recall_mean", 0),
            "fpr": metrics.get("fpr_mean", 0),
            "message": f"Nouveau modèle {version} déployé automatiquement",
        })

    def _notify_rollback(self, version: str, reason: str):
        self._safe_broadcast({
            "type": "ML_ROLLBACK",
            "version": version,
            "reason": reason,
            "message": f"Ré-entraînement {version} rejeté — rollback",
        })

    def _safe_broadcast(self, message: dict):
        try:
            asyncio.run(ws_manager.broadcast(message, "all"))

        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()

                if loop.is_running():
                    loop.create_task(ws_manager.broadcast(message, "all"))
                else:
                    loop.run_until_complete(ws_manager.broadcast(message, "all"))

            except Exception:
                pass

        except Exception:
            pass


# ============================================================
# Tâche Celery
# ============================================================

@celery_app.task(name="app.services.ml_training.retrain_models")
def retrain_models():
    """
    Point d'entrée Celery pour la boucle adaptative M10.
    """
    logger.info("🔄 M10 Celery Beat déclenché à 02:00")

    adaptive_loop = AdaptiveMLLoop()
    report = adaptive_loop.run()

    report_path = MODEL_BASE / f"training_report_{report['version']}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report_clean = _clean_report(report)

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(
            report_clean,
            f,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    logger.info("Rapport M10 sauvegardé: %s", report_path)

    return report_clean


def _clean_report(obj):
    """
    Nettoyage récursif pour sérialisation JSON.
    """
    if isinstance(obj, dict):
        return {
            k: _clean_report(v)
            for k, v in obj.items()
        }

    if isinstance(obj, (list, tuple)):
        return [
            _clean_report(v)
            for v in obj
        ]

    if isinstance(obj, np.ndarray):
        return obj.tolist()

    if isinstance(obj, (np.float32, np.float64, np.floating)):
        return float(obj)

    if isinstance(obj, (np.int32, np.int64, np.integer)):
        return int(obj)

    return obj