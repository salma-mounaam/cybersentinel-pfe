// ============================================================
// lib/cyber.ts — Helpers communs pour aligner Overview + CodeScan
// ============================================================

export type UnifiedSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const SEVERITY_ALIASES: Record<string, UnifiedSeverity> = {
  // FR
  CRITIQUE: "CRITICAL",
  ELEVE: "HIGH",
  MOYEN: "MEDIUM",
  FAIBLE: "LOW",
  INFO: "INFO",

  // EN
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
};

export const SEVERITY_LABELS_FR: Record<UnifiedSeverity, string> = {
  CRITICAL: "CRITIQUE",
  HIGH: "ÉLEVÉ",
  MEDIUM: "MOYEN",
  LOW: "FAIBLE",
  INFO: "INFO",
};

export const SEVERITY_COLORS: Record<UnifiedSeverity, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f59e0b",
  MEDIUM: "#3b82f6",
  LOW: "#22c55e",
  INFO: "#94a3b8",
};

export function normalizeSeverity(value?: string): UnifiedSeverity {
  if (!value) return "INFO";
  return SEVERITY_ALIASES[value.toUpperCase()] || "INFO";
}

export function aggregateSeverityMap(
  input?: Record<string, number>
): Record<UnifiedSeverity, number> {
  const out: Record<UnifiedSeverity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  if (!input) return out;

  Object.entries(input).forEach(([key, value]) => {
    const sev = normalizeSeverity(key);
    out[sev] += Number(value || 0);
  });

  return out;
}

export function severityPieData(input?: Record<string, number>) {
  const agg = aggregateSeverityMap(input);

  return (Object.entries(agg) as [UnifiedSeverity, number][])
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({
      name,
      label: SEVERITY_LABELS_FR[name],
      value,
      color: SEVERITY_COLORS[name],
    }));
}

export function getSeverityBadgeValue(value?: string) {
  return SEVERITY_LABELS_FR[normalizeSeverity(value)];
}

export function formatConfidence(value?: number) {
  const v = Number(value || 0);
  return v.toFixed(2);
}

export function confidencePercent(value?: number) {
  return Math.round(Number(value || 0) * 100);
}