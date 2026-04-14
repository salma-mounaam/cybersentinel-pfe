// ============================================================
// components/common/index.tsx — Composants réutilisables
// ============================================================
import React from "react";

// ── KPI Card ─────────────────────────────────────────────────
interface KPIProps {
  label: string;
  value: string | number;
  color?: string;
  sub?: string;
}
export function KPICard({ label, value, color = "var(--cs-text)", sub }: KPIProps) {
  return (
    <div className="card" style={{ padding: "14px 16px" }}>
      <div style={{ fontSize: "10px", color: "var(--cs-text2)", marginBottom: "6px",
        fontFamily: "monospace", textTransform: "uppercase", letterSpacing: ".5px" }}>
        {label}
      </div>
      <div style={{ fontSize: "26px", fontWeight: 500, color, lineHeight: 1,
        fontFamily: "'IBM Plex Mono', monospace" }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: "10px", color: "var(--cs-text3)", marginTop: "4px" }}>{sub}</div>}
    </div>
  );
}

// ── Page Header ──────────────────────────────────────────────
interface PageHeaderProps {
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
}
export function PageHeader({ title, subtitle, right }: PageHeaderProps) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
      alignItems: "flex-start", marginBottom: "20px" }}>
      <div>
        <h1 style={{ fontSize: "18px", fontWeight: 500,
          fontFamily: "'IBM Plex Mono', monospace", letterSpacing: "-.5px" }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: "11px", color: "var(--cs-text2)", marginTop: "3px" }}>
            {subtitle}
          </p>
        )}
      </div>
      {right && <div>{right}</div>}
    </div>
  );
}

// ── Live Badge ───────────────────────────────────────────────
interface LiveBadgeProps {
  connected: boolean;
  label?: string;
}
export function LiveBadge({ connected, label }: LiveBadgeProps) {
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: "6px",
      padding: "4px 10px",
      background: connected ? "rgba(34,197,94,.1)" : "rgba(239,68,68,.1)",
      border: `0.5px solid ${connected ? "rgba(34,197,94,.3)" : "rgba(239,68,68,.3)"}`,
      borderRadius: "20px",
      fontSize: "11px",
      color: connected ? "var(--cs-green)" : "var(--cs-red)",
    }}>
      <span className={connected ? "dot-live" : "dot-offline"} />
      {label ?? (connected ? "Live" : "Déconnecté")}
    </div>
  );
}

// ── Severity Badge ───────────────────────────────────────────
export function SevBadge({ sev }: { sev: string }) {
  return <span className={`badge badge-${sev}`}>{sev}</span>;
}

// ── Score Bar ────────────────────────────────────────────────
interface ScoreBarProps {
  value: number;
  max?: number;
}
export function ScoreBar({ value, max = 10 }: ScoreBarProps) {
  const pct = Math.min((value / max) * 100, 100);
  const color = value >= 8 ? "var(--sev-critique)"
              : value >= 6 ? "var(--sev-eleve)"
              : value >= 4 ? "var(--sev-moyen)"
              : "var(--sev-faible)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <div className="progress-bar" style={{ flex: 1, minWidth: "50px" }}>
        <div className="progress-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ fontSize: "11px", fontFamily: "monospace", color, minWidth: "28px" }}>
        {value.toFixed(1)}
      </span>
    </div>
  );
}

// ── Loading ──────────────────────────────────────────────────
export function Loading({ text = "Chargement..." }: { text?: string }) {
  return (
    <div style={{ padding: "48px", textAlign: "center", color: "var(--cs-text2)",
      fontSize: "12px", fontFamily: "monospace" }}>
      {text}
    </div>
  );
}

// ── Empty ────────────────────────────────────────────────────
export function Empty({ text }: { text: string }) {
  return (
    <div style={{ padding: "48px", textAlign: "center", color: "var(--cs-text3)",
      fontSize: "12px" }}>
      {text}
    </div>
  );
}

// ── Section Title ─────────────────────────────────────────────
export function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      fontSize: "10px", fontFamily: "monospace", fontWeight: 500,
      color: "var(--cs-text2)", textTransform: "uppercase", letterSpacing: ".8px",
      marginBottom: "10px",
    }}>
      {children}
    </div>
  );
}