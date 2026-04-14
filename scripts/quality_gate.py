#!/usr/bin/env python3
# ============================================================
# Script CI/CD — Quality Gate Decision (H5)
# ============================================================

import argparse
import json
from pathlib import Path


def parse_sarif_counts(sarif_path: str) -> dict:
    counts = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "total": 0,
    }

    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
    except Exception:
        return counts

    for run in sarif.get("runs", []):
        rules = {
            rule.get("id", ""): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule = rules.get(result.get("ruleId", ""), {})
            sev = "medium"

            tags = rule.get("properties", {}).get("tags", []) or []
            for tag in tags:
                tag_upper = str(tag).upper()
                if "CRITICAL" in tag_upper:
                    sev = "critical"
                    break
                if "HIGH" in tag_upper:
                    sev = "high"
                    break
                if "LOW" in tag_upper:
                    sev = "low"

            if sev == "medium":
                score = rule.get("properties", {}).get("security-severity")
                if score is not None:
                    try:
                        score = float(score)
                        if score >= 9.0:
                            sev = "critical"
                        elif score >= 7.0:
                            sev = "high"
                        elif score >= 4.0:
                            sev = "medium"
                        else:
                            sev = "low"
                    except Exception:
                        pass

            if sev == "medium":
                level = result.get("level", "warning")
                if level == "error":
                    sev = "high"
                elif level == "note":
                    sev = "low"

            counts[f"{sev}_count"] += 1
            counts["total"] += 1

    return counts


def load_gitleaks_count(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            return 0
        data = json.loads(content)
        return len(data) if isinstance(data, list) else 0
    except Exception:
        return 0


def load_ml_status(path: str | None) -> bool:
    if not path:
        return True
    p = Path(path)
    if not p.exists():
        return True
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return bool(data.get("passed", True))
    except Exception:
        return True


def evaluate_gate(semgrep_sarif: str, trivy_sarif: str, gitleaks_json: str, ml_smoke_json: str | None = None) -> dict:
    blockers = []
    warnings = []

    semgrep_data = parse_sarif_counts(semgrep_sarif)
    trivy_data = parse_sarif_counts(trivy_sarif)
    secrets_count = load_gitleaks_count(gitleaks_json)
    ml_ok = load_ml_status(ml_smoke_json)

    semgrep_ok = True
    trivy_ok = True
    gitleaks_ok = True

    if semgrep_data["critical_count"] >= 1:
        blockers.append(f"Semgrep: {semgrep_data['critical_count']} vulnérabilité(s) CRITIQUE(S)")
        semgrep_ok = False

    if semgrep_data["high_count"] > 5:
        blockers.append(f"Semgrep: {semgrep_data['high_count']} vulnérabilités ÉLEVÉES (seuil: 5)")
        semgrep_ok = False

    if semgrep_data["medium_count"] > 3:
        warnings.append(f"Semgrep: {semgrep_data['medium_count']} vulnérabilités MOYENNES")

    if trivy_data["critical_count"] >= 1:
        blockers.append(f"Trivy: {trivy_data['critical_count']} CVE(s) CRITIQUE(S)")
        trivy_ok = False

    if secrets_count >= 1:
        blockers.append(f"Gitleaks: {secrets_count} secret(s) exposé(s)")
        gitleaks_ok = False

    if not ml_ok:
        blockers.append("ML smoke test échoué")

    decision = "BLOCK" if blockers else "PASS"

    result = {
        "decision": decision,
        "blockers": blockers,
        "warnings": warnings,
        "semgrep_ok": semgrep_ok,
        "trivy_ok": trivy_ok,
        "gitleaks_ok": gitleaks_ok,
        "ml_ok": ml_ok,
        "semgrep_stats": semgrep_data,
        "trivy_stats": trivy_data,
        "secrets_count": secrets_count,
        "h5_validated": decision == "BLOCK" and len(blockers) > 0,
    }

    print("\n" + "=" * 60)
    print(f"QUALITY GATE : {decision}")
    if blockers:
        print("\nBLOCAGES :")
        for b in blockers:
            print(f"  ❌ {b}")
    if warnings:
        print("\nAVERTISSEMENTS :")
        for w in warnings:
            print(f"  ⚠️ {w}")
    print("=" * 60 + "\n")

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--semgrep-sarif", default="semgrep-results.sarif")
    parser.add_argument("--trivy-sarif", default="trivy-results.sarif")
    parser.add_argument("--gitleaks-json", default="gitleaks-report.json")
    parser.add_argument("--ml-smoke-json", default=None)
    parser.add_argument("--output", default="gate-result.json")
    args = parser.parse_args()

    result = evaluate_gate(
        semgrep_sarif=args.semgrep_sarif,
        trivy_sarif=args.trivy_sarif,
        gitleaks_json=args.gitleaks_json,
        ml_smoke_json=args.ml_smoke_json,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    main()