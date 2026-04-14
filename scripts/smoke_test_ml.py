#!/usr/bin/env python3
# ============================================================
# Script CI/CD — ML Smoke Test
# ============================================================

import argparse
import json
from pathlib import Path

import numpy as np


def run_smoke_test(model_path: str) -> dict:
    result = {
        "passed": True,
        "models_found": False,
        "if_ok": False,
        "ocsvm_ok": False,
        "ae_ok": False,
        "errors": [],
    }

    model_dir = Path(model_path)
    if_path = model_dir / "if_model.pkl"
    ocsvm_path = model_dir / "ocsvm_model.pkl"
    ae_keras = model_dir / "ae_model_keras"

    if not if_path.exists() and not ocsvm_path.exists() and not ae_keras.exists():
        result["passed"] = True
        result["message"] = "Aucun modèle trouvé — smoke test ignoré"
        return result

    result["models_found"] = True

    try:
        import joblib

        X_test = np.random.randn(100, 20)

        if if_path.exists():
            if_model = joblib.load(str(if_path))
            scores = if_model.score_samples(X_test)
            assert len(scores) == len(X_test)
            result["if_ok"] = True

        if ocsvm_path.exists():
            ocsvm = joblib.load(str(ocsvm_path))
            preds = ocsvm.predict(X_test)
            assert len(preds) == len(X_test)
            result["ocsvm_ok"] = True

        if ae_keras.exists():
            import tensorflow as tf
            ae = tf.keras.models.load_model(str(ae_keras))
            recon = ae.predict(X_test, verbose=0)
            assert recon.shape == X_test.shape
            result["ae_ok"] = True

    except Exception as e:
        result["passed"] = False
        result["errors"].append(str(e))

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", default="data/models")
    parser.add_argument("--output", default="ml-smoke-result.json")
    args = parser.parse_args()

    result = run_smoke_test(args.model_path)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()