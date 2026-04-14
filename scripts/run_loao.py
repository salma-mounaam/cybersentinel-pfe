#!/usr/bin/env python3
# ============================================================
# Script CI/CD — Validation LOAO complète
# Utilisé par nightly.yml GitHub Actions
# ============================================================

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def _clean_json(obj):
    if isinstance(obj, dict):
        return {k: _clean_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_json(v) for v in obj]
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, (np.float32, np.float64, np.floating)):
        return float(obj)
    if isinstance(obj, (np.int32, np.int64, np.integer)):
        return int(obj)
    return obj


def run_loao(data_dir: str, output: str):
    from app.ml.features.preprocessor import CICIDSPreprocessor
    from app.ml.models.ensemble import EnsembleAnomalyDetector

    preprocessor = CICIDSPreprocessor(data_dir=data_dir)
    df = preprocessor.load_dataset()

    if df is None or getattr(df, "empty", False):
        result = {
            "__summary__": {
                "mean_precision": 0.0,
                "mean_recall": 0.0,
                "mean_f1": 0.0,
                "h1_validated": False,
                "n_attack_types": 0,
                "message": "Dataset vide"
            }
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return False

    splits, X_benign = preprocessor.prepare_loao_splits(df)

    if X_benign is None or len(X_benign) == 0:
        result = {
            "__summary__": {
                "mean_precision": 0.0,
                "mean_recall": 0.0,
                "mean_f1": 0.0,
                "h1_validated": False,
                "n_attack_types": 0,
                "message": "Aucune donnée BENIGN disponible"
            }
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return False

    detector = EnsembleAnomalyDetector()
    detector.fit(X_benign)

    loao_results = detector.run_loao_validation(splits)
    summary = loao_results.get("__summary__", {})

    precision = float(summary.get("mean_precision", summary.get("mean_recall", 0.0)))
    recall = float(summary.get("mean_recall", 0.0))
    f1 = 0.0
    if precision + recall > 0:
        f1 = 2 * (precision * recall) / (precision + recall)

    loao_results["__summary__"]["mean_precision"] = round(precision, 4)
    loao_results["__summary__"]["mean_recall"] = round(recall, 4)
    loao_results["__summary__"]["mean_f1"] = round(f1, 4)
    loao_results["__summary__"]["h1_validated"] = recall >= 0.70

    clean = _clean_json(loao_results)

    with open(output, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2, ensure_ascii=False)

    print(f"\nLOAO Precision moyenne: {precision:.4f}")
    print(f"LOAO Recall moyen:    {recall:.4f}")
    print(f"LOAO F1 moyen:        {f1:.4f}")
    print(f"H1 {'VALIDÉE ✅' if recall >= 0.70 else 'NON VALIDÉE ❌'}")

    return recall >= 0.70


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="data/raw")
    parser.add_argument("--output", default="loao-results.json")
    args = parser.parse_args()

    success = run_loao(args.data_dir, args.output)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
