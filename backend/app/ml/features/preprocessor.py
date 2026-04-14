# ============================================================
# M2 — Préprocesseur CIC-IDS-2017
# Charge le dataset, filtre le trafic BENIGN, normalise
# Version corrigée avec sous-échantillonnage BENIGN
# ============================================================

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from pathlib import Path
import joblib
import logging

from app.ml.features.extractor import extract_features_from_cicids, FEATURE_NAMES

logger = logging.getLogger(__name__)

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
    """

    def __init__(self, data_dir: str = "data/raw", max_benign_samples: int = 300000):
        self.data_dir = Path(data_dir)
        self.scaler = RobustScaler(quantile_range=(5, 95))
        self.max_benign_samples = max_benign_samples

    def load_dataset(self) -> pd.DataFrame:
        csv_files = list(self.data_dir.glob("*.csv"))
        if not csv_files:
            logger.warning(
                "Aucun CSV trouvé dans data/raw/. "
                "Téléchargez CIC-IDS-2017 et placez les CSV dans data/raw/"
            )
            return self._generate_synthetic_cicids_like_data()

        dfs = []
        for f in csv_files:
            logger.info("Chargement: %s", f.name)
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)

        df = pd.concat(dfs, ignore_index=True)
        logger.info("Dataset chargé: %s lignes", len(df))

        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(subset=["Label"], inplace=True)
        df["__label_norm__"] = df["Label"].astype(str).apply(normalize_label)

        return df

    def prepare_loao_splits(self, df: pd.DataFrame):
        """
        Prépare les splits LOAO :
        {attack_type: (X_benign_scaled, X_attack_scaled)}
        """
        splits = {}

        logger.info("Extraction des features...")
        df["features"] = df.apply(lambda row: extract_features_from_cicids(row), axis=1)
        df = df.dropna(subset=["features"]).copy()

        benign_mask = df["__label_norm__"] == normalize_label(BENIGN_LABEL)
        if benign_mask.sum() == 0:
            raise ValueError("Aucun trafic BENIGN trouvé dans le dataset.")

        X_benign = np.stack(df.loc[benign_mask, "features"].values)
        logger.info("Trafic BENIGN brut : %s flux", len(X_benign))

        if len(X_benign) > self.max_benign_samples:
            rng = np.random.default_rng(42)
            idx = rng.choice(len(X_benign), self.max_benign_samples, replace=False)
            X_benign = X_benign[idx]
            logger.info("Sous-échantillonnage BENIGN : %s flux conservés", len(X_benign))

        self.scaler.fit(X_benign)
        X_benign_scaled = self.scaler.transform(X_benign)
        logger.info("Trafic BENIGN final : %s flux", len(X_benign_scaled))

        for attack in ATTACK_TYPES:
            attack_norm = normalize_label(attack)
            attack_mask = df["__label_norm__"].str.contains(attack_norm, case=False, na=False)

            n_attack = int(attack_mask.sum())
            if n_attack < 10:
                logger.warning("Pas assez de données pour %s, ignoré", attack)
                continue

            X_attack = np.stack(df.loc[attack_mask, "features"].values)
            X_attack_scaled = self.scaler.transform(X_attack)

            splits[attack] = (X_benign_scaled, X_attack_scaled)
            logger.info(
                "Split LOAO '%s': train=%s, test=%s",
                attack,
                len(X_benign_scaled),
                len(X_attack_scaled),
            )

        return splits, X_benign_scaled

    def _generate_synthetic_cicids_like_data(self) -> pd.DataFrame:
        logger.warning("Utilisation de données synthétiques CIC-like (tests uniquement)")
        np.random.seed(42)
        n = 10000
        half = n // 2
        labels = [BENIGN_LABEL] * half + ["DoS slowloris"] * half

        df = pd.DataFrame({
            "Total Fwd Packets": np.random.randint(1, 20, size=n),
            "Total Backward Packets": np.random.randint(1, 20, size=n),
            "Total Length of Fwd Packets": np.random.randint(100, 5000, size=n),
            "Total Length of Bwd Packets": np.random.randint(100, 5000, size=n),
            "Flow Duration": np.random.randint(1_000, 5_000_000, size=n),
            "Destination Port": np.random.choice([21, 22, 80, 443, 8080, 3306], size=n),
            "Flow Bytes/s": np.random.random(size=n) * 10000,
            "Flow Packets/s": np.random.random(size=n) * 1000,
            "SYN Flag Count": np.random.randint(0, 5, size=n),
            "ACK Flag Count": np.random.randint(0, 5, size=n),
            "FIN Flag Count": np.random.randint(0, 2, size=n),
            "RST Flag Count": np.random.randint(0, 2, size=n),
            "Packet Length Mean": np.random.random(size=n) * 1000,
            "Packet Length Std": np.random.random(size=n) * 500,
            "Packet Length Max": np.random.random(size=n) * 1500,
            "Flow IAT Mean": np.random.randint(1, 1_000_000, size=n),
            "Flow IAT Std": np.random.randint(1, 1_000_000, size=n),
            "Active Mean": np.random.randint(1, 1_000_000, size=n),
            "Idle Mean": np.random.randint(1, 1_000_000, size=n),
            "Down/Up Ratio": np.random.random(size=n) * 5,
            "Subflow Fwd Bytes": np.random.randint(50, 4000, size=n),
            "Subflow Bwd Bytes": np.random.randint(50, 4000, size=n),
            "Label": labels,
        })

        df["__label_norm__"] = df["Label"].astype(str).apply(normalize_label)
        return df

    def save_scaler(self, path: str = "data/models/scaler.pkl"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, path)
        logger.info("Scaler sauvegardé: %s", path)

    def load_scaler(self, path: str = "data/models/scaler.pkl"):
        self.scaler = joblib.load(path)
        logger.info("Scaler chargé: %s", path)