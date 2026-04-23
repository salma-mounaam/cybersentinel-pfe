# ============================================================
# M2 — Préprocesseur CIC-IDS-2017
# Version corrigée v2 :
#   - Nettoyage NaN/Inf AVANT l'extraction des features
#   - Suppression des features redondantes identifiées :
#       subflow_fwd/bwd_bytes (= fwd/bwd_bytes_total)
#       flow_bytes_total (= fwd + bwd, combinaison linéaire)
#       bwd_pkt_ratio (= 1 - fwd_pkt_ratio)
#   - Logging enrichi (distribution labels, stats BENIGN)
#   - max_benign_samples remonté à 500 000 pour meilleure couverture
# ============================================================

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from pathlib import Path
import joblib
import logging

from app.ml.features.extractor import (
    extract_features_from_cicids,
    FEATURE_NAMES,
    EFFECTIVE_FEATURES,
    EFFECTIVE_FEATURE_DIM,
    REDUNDANT_FEATURES,
)

logger = logging.getLogger(__name__)

# ── Labels d'attaque CIC-IDS-2017 ──────────────────────────
ATTACK_TYPES = [
    "DoS slowloris",
    "DoS Slowhttptest",
    "DDoS",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
    "Web Attack - Sql Injection",
    "Infiltration",
    "Bot",
]

BENIGN_LABEL = "BENIGN"

# EFFECTIVE_FEATURES, EFFECTIVE_FEATURE_DIM, REDUNDANT_FEATURES
# sont importés directement depuis extractor.py (source unique de vérité)


def normalize_label(value: str) -> str:
    return (
        str(value)
        .strip()
        .lower()
        .replace("–", "-")
        .replace("—", "-")
        .replace("_", " ")
        .replace("  ", " ")
    )


class CICIDSPreprocessor:
    """
    Charge et prépare CIC-IDS-2017 pour le protocole LOAO.

    Ordre des opérations :
    1. Chargement CSV + concat
    2. Remplacement Inf → NaN, suppression lignes Label NaN
    3. Remplacement NaN numériques par médiane colonne (pas dropna global)
    4. Extraction 33 features → sélection des 29 effectives
    5. Fit RobustScaler sur BENIGN pur
    6. Construction splits LOAO
    """

    def __init__(
        self,
        data_dir: str = "data/raw",
        max_benign_samples: int = 500_000,
    ):
        self.data_dir          = Path(data_dir)
        self.scaler            = RobustScaler(quantile_range=(5, 95))
        self.max_benign_samples = max_benign_samples
        self.effective_features = EFFECTIVE_FEATURES

    # ──────────────────────────────────────────
    # Chargement dataset
    # ──────────────────────────────────────────

    def load_dataset(self) -> pd.DataFrame:
        csv_files = sorted(self.data_dir.glob("*.csv"))
        if not csv_files:
            logger.warning(
                "Aucun CSV trouvé dans %s — utilisation de données synthétiques.",
                self.data_dir,
            )
            return self._generate_synthetic_cicids_like_data()

        dfs = []
        for f in csv_files:
            logger.info("Chargement : %s", f.name)
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)

        df = pd.concat(dfs, ignore_index=True)
        logger.info("Dataset brut : %d lignes, %d colonnes", len(df), df.shape[1])

        # ── Nettoyage ─────────────────────────
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(subset=["Label"], inplace=True)

        # Imputation NaN numériques par médiane (préserve les lignes)
        num_cols = df.select_dtypes(include=[np.number]).columns
        df[num_cols] = df[num_cols].fillna(df[num_cols].median())

        df["__label_norm__"] = df["Label"].astype(str).apply(normalize_label)

        # Distribution labels
        dist = df["__label_norm__"].value_counts()
        logger.info("Distribution labels :\n%s", dist.to_string())

        return df

    # ──────────────────────────────────────────
    # Préparation splits LOAO
    # ──────────────────────────────────────────

    def prepare_loao_splits(self, df: pd.DataFrame):
        """
        Retourne :
            splits          : {attack_type: (X_benign_scaled, X_attack_scaled)}
            X_benign_scaled : vecteur BENIGN normalisé (pour entraînement global)
        """
        logger.info("Extraction des features (33 → %d effectives)...", EFFECTIVE_FEATURE_DIM)

        # Extraction vectorielle
        df = df.copy()
        df["__features__"] = df.apply(
            lambda row: self._extract_effective(row), axis=1
        )
        df = df.dropna(subset=["__features__"]).copy()
        logger.info("Lignes après extraction : %d", len(df))

        # ── BENIGN ────────────────────────────
        benign_mask = df["__label_norm__"] == normalize_label(BENIGN_LABEL)
        if benign_mask.sum() == 0:
            raise ValueError("Aucun trafic BENIGN trouvé dans le dataset.")

        X_benign = np.stack(df.loc[benign_mask, "__features__"].values)
        logger.info("Trafic BENIGN brut : %d flux", len(X_benign))

        # Stats BENIGN avant normalisation (utile pour debug)
        self._log_benign_stats(X_benign)

        # Sous-échantillonnage si nécessaire
        if len(X_benign) > self.max_benign_samples:
            rng = np.random.default_rng(42)
            idx = rng.choice(len(X_benign), self.max_benign_samples, replace=False)
            X_benign = X_benign[idx]
            logger.info("Sous-échantillonnage BENIGN : %d flux conservés", len(X_benign))

        # Fit scaler sur BENIGN pur uniquement
        self.scaler.fit(X_benign)
        X_benign_scaled = self.scaler.transform(X_benign)
        logger.info("RobustScaler fitté sur %d flux BENIGN", len(X_benign_scaled))

        # ── Splits par type d'attaque ─────────
        splits = {}
        for attack in ATTACK_TYPES:
            attack_norm = normalize_label(attack)
            attack_mask = df["__label_norm__"].str.contains(
                attack_norm, case=False, na=False, regex=False
            )
            n_attack = int(attack_mask.sum())

            if n_attack < 10:
                logger.warning("Pas assez de données pour '%s' (%d flux), ignoré.", attack, n_attack)
                continue

            X_attack = np.stack(df.loc[attack_mask, "__features__"].values)
            X_attack_scaled = self.scaler.transform(X_attack)

            splits[attack] = (X_benign_scaled, X_attack_scaled)
            logger.info(
                "Split LOAO '%-35s' | BENIGN=%d | Attack=%d",
                attack, len(X_benign_scaled), len(X_attack_scaled),
            )

        logger.info("Splits LOAO prêts : %d types d'attaque", len(splits))
        return splits, X_benign_scaled

    # ──────────────────────────────────────────
    # Extraction effective (sans redondances)
    # ──────────────────────────────────────────

    def _extract_effective(self, row: pd.Series):
        """
        Retourne directement les 29 features effectives.
        extract_features_from_cicids fait déjà la sélection en interne.
        """
        return extract_features_from_cicids(row)

    # ──────────────────────────────────────────
    # Logging stats BENIGN
    # ──────────────────────────────────────────

    def _log_benign_stats(self, X_benign: np.ndarray):
        """Log les features avec forte variance ou valeurs extrêmes."""
        stds = X_benign.std(axis=0)
        top5_std_idx = np.argsort(stds)[::-1][:5]
        logger.info("Top 5 features BENIGN par écart-type :")
        for i in top5_std_idx:
            fname = self.effective_features[i] if i < len(self.effective_features) else f"feat_{i}"
            logger.info(
                "  %-35s | mean=%.4f std=%.4f max=%.4f",
                fname, X_benign[:, i].mean(), stds[i], X_benign[:, i].max(),
            )

    # ──────────────────────────────────────────
    # Données synthétiques (fallback)
    # ──────────────────────────────────────────

    def _generate_synthetic_cicids_like_data(self) -> pd.DataFrame:
        logger.warning("Données synthétiques CIC-like (pour tests uniquement)")
        np.random.seed(42)
        n    = 10_000
        half = n // 2
        labels = [BENIGN_LABEL] * half + ["DoS slowloris"] * half

        df = pd.DataFrame({
            "Total Fwd Packets":             np.random.randint(1, 20,         size=n),
            "Total Backward Packets":        np.random.randint(1, 20,         size=n),
            "Total Length of Fwd Packets":   np.random.randint(100, 5000,     size=n),
            "Total Length of Bwd Packets":   np.random.randint(100, 5000,     size=n),
            "Flow Duration":                 np.random.randint(1_000, 5_000_000, size=n),
            "Destination Port":              np.random.choice([21, 22, 80, 443, 8080], size=n),
            "Flow Bytes/s":                  np.random.random(size=n) * 10_000,
            "Flow Packets/s":                np.random.random(size=n) * 1_000,
            "SYN Flag Count":                np.random.randint(0, 5,          size=n),
            "ACK Flag Count":                np.random.randint(0, 5,          size=n),
            "FIN Flag Count":                np.random.randint(0, 2,          size=n),
            "RST Flag Count":                np.random.randint(0, 2,          size=n),
            "Packet Length Mean":            np.random.random(size=n) * 1000,
            "Packet Length Std":             np.random.random(size=n) * 500,
            "Packet Length Max":             np.random.random(size=n) * 1500,
            "Flow IAT Mean":                 np.random.randint(1, 1_000_000,  size=n),
            "Flow IAT Std":                  np.random.randint(1, 1_000_000,  size=n),
            "Active Mean":                   np.random.randint(1, 1_000_000,  size=n),
            "Idle Mean":                     np.random.randint(1, 1_000_000,  size=n),
            "Down/Up Ratio":                 np.random.random(size=n) * 5,
            "Subflow Fwd Bytes":             np.random.randint(50, 4000,      size=n),
            "Subflow Bwd Bytes":             np.random.randint(50, 4000,      size=n),
            "Label":                         labels,
        })

        df["__label_norm__"] = df["Label"].astype(str).apply(normalize_label)
        return df

    # ──────────────────────────────────────────
    # Persistance scaler
    # ──────────────────────────────────────────

    def save_scaler(self, path: str = "data/models/scaler.pkl"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "scaler":             self.scaler,
            "effective_features": self.effective_features,
        }, path)
        logger.info("Scaler sauvegardé : %s", path)

    def load_scaler(self, path: str = "data/models/scaler.pkl"):
        data = joblib.load(path)
        self.scaler            = data["scaler"]
        self.effective_features = data.get("effective_features", EFFECTIVE_FEATURES)
        logger.info("Scaler chargé : %s", path)