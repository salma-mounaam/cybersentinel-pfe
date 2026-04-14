#!/usr/bin/env python3
# ============================================================
# Script CI/CD — Parse SARIF et compte les sévérités
# ============================================================

import argparse
import json
import sys


def infer_severity(rule: dict, result: dict) -> str:
    properties = rule.get("properties", {})
    tags = properties.get("tags", []) or []
    level = result.get("level", "warning")

    for tag in tags:
        upper = str(tag).upper()
        if "CRITICAL" in upper:
            return "critical"
        if "HIGH" in upper:
            return "high"
        if "MEDIUM" in upper:
            return "medium"
        if "LOW" in upper:
            return "low"

    security_severity = properties.get("security-severity")
    if security_severity is not None:
        try:
            score = float(security_severity)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
        except Exception:
            pass

    if level == "error":
        return "high"
    if level == "warning":
        return "medium"
    return "low"


def parse_sarif(sarif_path: str, tool: str) -> dict:
    counts = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "total": 0,
        "tool": tool,
    }

    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"SARIF parse error: {e}", file=sys.stderr)
        return counts

    for run in sarif.get("runs", []):
        rules = {
            rule.get("id", ""): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            severity = infer_severity(rule, result)

            key = f"{severity}_count"
            if key in counts:
                counts[key] += 1
            counts["total"] += 1

    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    result = parse_sarif(args.input, args.tool)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()