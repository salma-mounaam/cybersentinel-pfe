// ============================================================
// pages/Overview.tsx — Redesign SOC v3 (corrigé)
// Style dark cyber conservé + composants orientés analyste
// ============================================================

import React, { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useWebSocket } from "../hooks/useWebSocket";
import {
  alertsAPI,
  incidentsAPI,
  fusionAPI,
  mlAPI,
  sastAPI,
  dastAPI,
  cicdAPI,
} from "../services/api";
import {
  PageHeader,
  LiveBadge,
  SevBadge,
  Empty,
  Loading,
} from "../components/common";
import { confidencePercent, formatConfidence } from "../lib/cyber";

// ── Icônes ──────────────────────────────────────────────────
function IconScanCenter() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="2" y="3" width="12" height="10" rx="2" />
      <path d="M5 6h6" />
      <path d="M5 8h4" />
      <path d="M5 10h3" />
    </svg>
  );
}

function IconShield() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M8 1.5L2 4v4c0 3.3 2.5 5.7 6 6.5 3.5-.8 6-3.2 6-6.5V4L8 1.5z" />
    </svg>
  );
}

// ── Helpers ─────────────────────────────────────────────────
function severityColor(sev?: string) {
  const s = (sev || "").toUpperCase();
  if (s === "CRITICAL" || s === "CRITIQUE") return "var(--cs-red)";
  if (s === "HIGH" || s === "ELEVE" || s === "ÉLEVÉ" || s === "ELEVÉ")
    return "var(--cs-amber)";
  if (s === "MEDIUM" || s === "MOYEN") return "var(--cs-blue)";
  return "var(--cs-green)";
}

function scoreColor(score?: number) {
  const v = Number(score || 0);
  if (v >= 8) return "var(--cs-red)";
  if (v >= 6) return "var(--cs-amber)";
  if (v >= 4) return "var(--cs-blue)";
  return "var(--cs-green)";
}

function getSettledValue<T>(
  result: PromiseSettledResult<T>,
  fallback: T
): T {
  return result.status === "fulfilled" ? result.value : fallback;
}

// ── Boutons header ───────────────────────────────────────────
function HeaderButtons() {
  const navigate = useNavigate();

  const base: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    gap: "6px",
    padding: "5px 12px",
    borderRadius: "7px",
    fontSize: "12px",
    fontWeight: 500,
    fontFamily: "inherit",
    cursor: "pointer",
    transition: "all .15s",
  };

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
      <button
        onClick={() => navigate("/scan-code")}
        style={{
          ...base,
          background: "rgba(20,184,166,.12)",
          border: "0.5px solid rgba(20,184,166,.45)",
          color: "#5eead4",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = "rgba(20,184,166,.22)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = "rgba(20,184,166,.12)";
        }}
      >
        <IconScanCenter />
        Scan Center
      </button>

      <button
        onClick={() => navigate("/ids")}
        style={{
          ...base,
          background: "rgba(255,255,255,.04)",
          border: "0.5px solid rgba(255,255,255,.14)",
          color: "var(--cs-text2)",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = "rgba(255,255,255,.09)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = "rgba(255,255,255,.04)";
        }}
      >
        <IconShield />
        IDS Monitor
      </button>
    </div>
  );
}

// ── KPI card avec bordure latérale colorée ───────────────────
function ThreatKPI({
  label,
  value,
  sub,
  color,
}: {
  label: string;
  value: string | number;
  sub: string;
  color: string;
}) {
  return (
    <div
      className="card"
      style={{
        padding: "12px 14px",
        borderLeft: `3px solid ${color}`,
        borderRadius: "0 8px 8px 0",
      }}
    >
      <div
        style={{
          fontSize: "10px",
          color: "var(--cs-text2)",
          marginBottom: "6px",
          fontFamily: "monospace",
          textTransform: "uppercase",
          letterSpacing: ".4px",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: "26px",
          fontWeight: 600,
          color,
          fontFamily: "'IBM Plex Mono', monospace",
          lineHeight: 1,
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontSize: "11px",
          color: "var(--cs-text3)",
          marginTop: "5px",
        }}
      >
        {sub}
      </div>
    </div>
  );
}

// ── Ligne incident prioritaire ───────────────────────────────
function IncidentRow({
  incident,
  onClick,
}: {
  incident: any;
  onClick: (i: any) => void;
}) {
  const score = Number(incident.score_r ?? incident.scoreR ?? 0);
  const sev = (incident.severity || "").toUpperCase();

  return (
    <button
      onClick={() => onClick(incident)}
      style={{
        width: "100%",
        textAlign: "left",
        padding: "9px 0",
        borderBottom: "0.5px solid var(--cs-border)",
        background: "transparent",
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        gap: "10px",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = "rgba(255,255,255,0.03)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "transparent";
      }}
    >
      <div
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: severityColor(sev),
          flexShrink: 0,
        }}
      />

      <div
        style={{
          flex: 1,
          fontSize: "13px",
          fontWeight: 500,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {incident.title || "Incident"}
      </div>

      <span
        style={{
          display: "inline-flex",
          alignItems: "center",
          padding: "2px 7px",
          borderRadius: "5px",
          fontSize: "10px",
          fontWeight: 600,
          background: `${severityColor(sev)}22`,
          color: severityColor(sev),
          border: `0.5px solid ${severityColor(sev)}55`,
          flexShrink: 0,
        }}
      >
        {sev || "LOW"}
      </span>

      <span
        style={{
          fontSize: "12px",
          fontFamily: "monospace",
          color: scoreColor(score),
          flexShrink: 0,
        }}
      >
        R {score.toFixed(1)}
      </span>

      <span
        style={{
          fontSize: "10px",
          color: "var(--cs-text3)",
          flexShrink: 0,
          minWidth: "60px",
          textAlign: "right",
        }}
      >
        {incident.created_at
          ? new Date(incident.created_at).toLocaleTimeString("fr-FR", {
              hour: "2-digit",
              minute: "2-digit",
            })
          : "—"}
      </span>
    </button>
  );
}

// ── Carte attaquant ──────────────────────────────────────────
function AttackerCard({
  ip,
  type,
  detail,
  intensity,
  color,
}: {
  ip: string;
  type: string;
  detail: string;
  intensity: number;
  color: string;
}) {
  return (
    <div
      style={{
        background: "rgba(255,255,255,0.03)",
        border: "0.5px solid var(--cs-border)",
        borderRadius: "8px",
        padding: "10px 12px",
        display: "flex",
        alignItems: "center",
        gap: "10px",
      }}
    >
      <div
        style={{
          width: "32px",
          height: "32px",
          borderRadius: "8px",
          background: `${color}20`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          stroke={color}
          strokeWidth="1.5"
        >
          <circle cx="8" cy="8" r="6" />
          <path d="M8 5v3l2 2" />
        </svg>
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: "13px",
            fontWeight: 500,
            fontFamily: "monospace",
          }}
        >
          {ip}
        </div>
        <div
          style={{
            fontSize: "11px",
            color: "var(--cs-text3)",
            marginTop: "2px",
          }}
        >
          {detail}
        </div>
        <div
          style={{
            height: "3px",
            background: "var(--cs-border2)",
            borderRadius: "2px",
            marginTop: "5px",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${Math.max(0, Math.min(100, intensity))}%`,
              height: "100%",
              background: color,
              borderRadius: "2px",
            }}
          />
        </div>
      </div>

      <span
        style={{
          padding: "2px 8px",
          borderRadius: "5px",
          fontSize: "10px",
          fontWeight: 600,
          background: `${color}22`,
          color,
          border: `0.5px solid ${color}55`,
          flexShrink: 0,
        }}
      >
        {type}
      </span>
    </div>
  );
}

// ── État module ──────────────────────────────────────────────
function ModuleStatus({
  label,
  status,
  detail,
}: {
  label: string;
  status: "ok" | "warn" | "off";
  detail: string;
}) {
  const dot =
    status === "ok"
      ? "var(--cs-green)"
      : status === "warn"
      ? "var(--cs-amber)"
      : "var(--cs-text3)";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "6px",
        fontSize: "12px",
      }}
    >
      <div
        style={{
          width: "7px",
          height: "7px",
          borderRadius: "50%",
          background: dot,
          flexShrink: 0,
        }}
      />
      <span style={{ color: "var(--cs-text2)" }}>{label}</span>
      <span style={{ color: dot, fontSize: "11px" }}>{detail}</span>
    </div>
  );
}

// ── Composant principal ──────────────────────────────────────
export default function Overview() {
  const navigate = useNavigate();

  const [alertStats, setAlertStats] = useState<any>(null);
  const [incidentStats, setIncidentStats] = useState<any>(null);
  const [fusionStats, setFusionStats] = useState<any>(null);
  const [mlStatus, setMLStatus] = useState<any>(null);
  const [sastStats, setSastStats] = useState<any>(null);
  const [dastStatus, setDastStatus] = useState<any>(null);
  const [cicdRuns, setCicdRuns] = useState<any>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [recentIncidents, setRecentIncidents] = useState<any[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<any[]>([]);
  const [liveHistory, setLiveHistory] = useState<{ time: string; score: number }[]>([]);
  const [liveCount, setLiveCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [
        asRes,
        isRes,
        fsRes,
        msRes,
        ssRes,
        crRes,
        raRes,
        incRes,
        dStatusRes,
        dFindRes,
        dIsoRes,
      ] = await Promise.allSettled([
        alertsAPI.getStats(),
        incidentsAPI.getStats(),
        fusionAPI.getStats(),
        mlAPI.getStatus(),
        sastAPI.getStats(),
        cicdAPI.getRuns(),
        alertsAPI.getRecent(15),
        incidentsAPI.getAll({ limit: 6 }),
        dastAPI.getStatus(),
        dastAPI.getFindings(1),
        dastAPI.verifyIsolation(),
      ]);

      const as = getSettledValue(asRes, {});
      const is = getSettledValue(isRes, {});
      const fs = getSettledValue(fsRes, {});
      const ms = getSettledValue(msRes, {});
      const ss = getSettledValue(ssRes, {});
      const cr = getSettledValue(crRes, {});
      const ra = getSettledValue(raRes, { total: 0, alerts: [] });
      const inc = getSettledValue(incRes, { total: 0, incidents: [] });
      const dStatus = getSettledValue(dStatusRes, {});
      const dFind = getSettledValue(dFindRes, {});
      const dIso = getSettledValue(dIsoRes, {});

      setAlertStats(as);
      setIncidentStats(is);
      setFusionStats(fs);
      setMLStatus(ms);
      setSastStats(ss);
      setCicdRuns(cr);
      setRecentAlerts(ra?.alerts || []);
      setRecentIncidents(inc?.incidents || []);
      setDastStatus({
        ...dStatus,
        active:
          dStatus?.active ??
          dStatus?.running ??
          dStatus?.status === "running",
        isolation_ok: dIso?.ca09_passed ?? false,
        total_findings:
          dFind?.total_proofs ?? dFind?.total ?? dFind?.count ?? 0,
      });
    } catch (e) {
      console.error("Overview load error:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const t = setInterval(loadData, 30000);
    return () => clearInterval(t);
  }, [loadData]);

  const handleWS = useCallback((msg: any) => {
    if (msg._type === "connected") return;

    setLiveCount((c) => c + 1);

    if (msg.severity || msg.title || msg.signature_name) {
      setLiveAlerts((prev) => [msg, ...prev.slice(0, 9)]);
      setLiveHistory((prev) => [
        ...prev.slice(-19),
        {
          time: new Date().toLocaleTimeString("fr-FR", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          score: confidencePercent(msg.confidence || msg.ml_score || 0),
        },
      ]);
    }
  }, []);

  const { connected } = useWebSocket({
    channel: "alerts",
    onMessage: handleWS,
  });

  const openIncident = useCallback(
    (incident: any) => {
      if (!incident?.id) {
        navigate("/incidents");
        return;
      }

      navigate("/incidents", {
        state: { incidentId: incident.id },
      });
    },
    [navigate]
  );

  const handleAlertClick = useCallback(
    (alert: any) => {
      const incidentId = alert?.incident_id;

      if (incidentId) {
        navigate("/incidents", {
          state: { incidentId },
        });
        return;
      }

      navigate("/incidents");
    },
    [navigate]
  );

  const totalAlerts = alertStats?.total ?? 0;
  const criticalInc =
    incidentStats?.by_severity?.CRITICAL ??
    incidentStats?.by_severity?.critique ??
    0;
  const highInc =
    incidentStats?.by_severity?.HIGH ??
    incidentStats?.by_severity?.ELEVE ??
    incidentStats?.by_severity?.eleve ??
    0;
  const overdueSla = incidentStats?.overdue_sla ?? 0;
  const resolvedInc = incidentStats?.resolved_this_week ?? 0;

  const displayAlerts = liveAlerts.length > 0 ? liveAlerts : recentAlerts;
  const attackerSource = liveAlerts.length > 0 ? liveAlerts : recentAlerts;

  const suricataActive = connected || displayAlerts.length > 0;
  const mlActive = mlStatus?.models_loaded ?? false;
  const dastActive = Boolean(
    dastStatus?.active ??
    dastStatus?.running ??
    (dastStatus?.status === "running")
  );

  const tt = {
    background: "var(--cs-surface2)",
    border: "0.5px solid var(--cs-border2)",
    borderRadius: "6px",
    fontSize: "11px",
    color: "var(--cs-text)",
  };

  if (loading) {
    return <Loading text="Connexion au backend..." />;
  }

  return (
    <div>
      <PageHeader
        title="Overview"
        subtitle="CyberSentinel Purple Team — Vue d'ensemble temps réel"
        right={
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <HeaderButtons />
            <LiveBadge
              connected={connected}
              label={connected ? `Live · ${liveCount} events` : "Déconnecté"}
            />
          </div>
        }
      />

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "10px",
          marginBottom: "16px",
        }}
      >
        <ThreatKPI
          label="Menaces actives"
          value={criticalInc + highInc}
          sub={`${criticalInc} critiques · ${highInc} élevés`}
          color="var(--cs-red)"
        />
        <ThreatKPI
          label="SLA dépassés"
          value={overdueSla}
          sub="Incidents en retard"
          color={overdueSla > 0 ? "var(--cs-amber)" : "var(--cs-green)"}
        />
        <ThreatKPI
          label="Alertes aujourd'hui"
          value={totalAlerts}
          sub={`${sastStats?.total_findings ?? sastStats?.total ?? 0} findings SAST`}
          color="var(--cs-blue)"
        />
        <ThreatKPI
          label="Incidents résolus"
          value={resolvedInc ?? "—"}
          sub="Cette semaine"
          color="var(--cs-green)"
        />
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "12px",
          marginBottom: "16px",
        }}
      >
        <div className="card" style={{ padding: 0 }}>
          <div
            style={{
              padding: "12px 16px",
              borderBottom: "0.5px solid var(--cs-border)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                fontFamily: "monospace",
                textTransform: "uppercase",
                letterSpacing: ".5px",
                color: "var(--cs-text2)",
              }}
            >
              Incidents prioritaires
            </span>
            <span
              style={{
                fontSize: "10px",
                color: "var(--cs-blue)",
                cursor: "pointer",
                textDecoration: "underline",
              }}
              onClick={() => navigate("/incidents")}
            >
              Voir tous →
            </span>
          </div>

          <div style={{ padding: "0 14px" }}>
            {recentIncidents.length === 0 ? (
              <div style={{ padding: "24px 0", textAlign: "center" }}>
                <Empty text="Aucun incident récent" />
              </div>
            ) : (
              recentIncidents.map((inc: any) => (
                <IncidentRow key={inc.id} incident={inc} onClick={openIncident} />
              ))
            )}
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div className="card">
            <div
              style={{
                fontSize: "11px",
                color: "var(--cs-text2)",
                marginBottom: "10px",
                fontFamily: "monospace",
                textTransform: "uppercase",
                letterSpacing: ".5px",
              }}
            >
              Top attaquants
            </div>

            <div style={{ display: "grid", gap: "8px" }}>
              {attackerSource.length === 0 ? (
                <div
                  style={{
                    fontSize: "12px",
                    color: "var(--cs-text3)",
                    padding: "8px 0",
                  }}
                >
                  En attente d'alertes Suricata...
                </div>
              ) : (
                Array.from(
                  new Map(
                    attackerSource
                      .filter((a: any) => a?.src_ip)
                      .map((a: any) => [a.src_ip, a])
                  ).values()
                )
                  .slice(0, 3)
                  .map((a: any, i) => (
                    <AttackerCard
                      key={i}
                      ip={a.src_ip}
                      type={a.category || a.source || "ALERT"}
                      detail={a.signature_name || a.title || "Activité suspecte"}
                      intensity={Math.round(
                        confidencePercent(a.confidence || a.ml_score || 0.5)
                      )}
                      color={
                        i === 0
                          ? "var(--cs-red)"
                          : i === 1
                          ? "var(--cs-amber)"
                          : "var(--cs-blue)"
                      }
                    />
                  ))
              )}
            </div>
          </div>

          <div className="card">
            <div
              style={{
                fontSize: "11px",
                color: "var(--cs-text2)",
                marginBottom: "10px",
                fontFamily: "monospace",
                textTransform: "uppercase",
                letterSpacing: ".5px",
              }}
            >
              État des modules
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "8px",
              }}
            >
              <ModuleStatus
                label="M1 Suricata"
                status={suricataActive ? "ok" : "off"}
                detail={suricataActive ? "actif" : "inactif"}
              />
              <ModuleStatus
                label="M2 ML"
                status={mlActive ? "ok" : "warn"}
                detail={mlActive ? "actif" : "chargement"}
              />
              <ModuleStatus
                label="M3 Fusion"
                status="ok"
                detail={`${fusionStats?.total_fused ?? 0} fusionnées`}
              />
              <ModuleStatus
                label="M4 SAST"
                status="ok"
                detail={`${sastStats?.total_findings ?? sastStats?.total ?? 0} findings`}
              />
              <ModuleStatus
                label="M5 DAST"
                status={dastActive ? "ok" : "warn"}
                detail={dastActive ? "actif" : "inactif"}
              />
              <ModuleStatus
                label="M8 CI/CD"
                status="ok"
                detail={`${
                  cicdRuns?.blocked ?? cicdRuns?.blocked_runs ?? 0
                } bloqués`}
              />
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: "16px" }}>
        <div
          style={{
            fontSize: "11px",
            color: "var(--cs-text2)",
            marginBottom: "10px",
            fontFamily: "monospace",
            textTransform: "uppercase",
            letterSpacing: ".5px",
          }}
        >
          Scores ML live (WebSocket)
        </div>

        {liveHistory.length === 0 ? (
          <div
            style={{
              height: 100,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "var(--cs-text3)",
              fontSize: "11px",
            }}
          >
            En attente d'alertes...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={100}>
            <AreaChart data={liveHistory}>
              <defs>
                <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>

              <XAxis
                dataKey="time"
                tick={{ fontSize: 9, fill: "var(--cs-text3)" }}
                tickLine={false}
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fontSize: 9, fill: "var(--cs-text3)" }}
                tickLine={false}
                width={28}
              />
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="var(--cs-border)"
              />
              <Tooltip contentStyle={tt} />
              <Area
                type="monotone"
                dataKey="score"
                stroke="#3b82f6"
                fill="url(#grad)"
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div
          style={{
            padding: "12px 16px",
            borderBottom: "0.5px solid var(--cs-border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span
            style={{
              fontSize: "11px",
              fontFamily: "monospace",
              textTransform: "uppercase",
              letterSpacing: ".5px",
              color: "var(--cs-text2)",
            }}
          >
            Alertes récentes
          </span>

          <span style={{ fontSize: "10px", color: "var(--cs-text3)" }}>
            {liveAlerts.length > 0
              ? `${liveAlerts.length} en live`
              : `${recentAlerts.length} depuis Redis`}
            {" · "}
            <span
              style={{
                color: "var(--cs-blue)",
                cursor: "pointer",
                textDecoration: "underline",
              }}
              onClick={() => navigate("/incidents")}
            >
              Voir tous les incidents →
            </span>
          </span>
        </div>

        <table className="cs-table">
          <thead>
            <tr>
              <th>Sévérité</th>
              <th>Signature</th>
              <th>Src IP</th>
              <th>Dest IP</th>
              <th>Détection</th>
              <th>Confiance</th>
              <th>MITRE</th>
              <th>Heure</th>
            </tr>
          </thead>

          <tbody>
            {displayAlerts.length === 0 ? (
              <tr>
                <td
                  colSpan={8}
                  style={{
                    padding: "32px",
                    textAlign: "center",
                    color: "var(--cs-text3)",
                  }}
                >
                  En attente d'alertes Suricata...
                </td>
              </tr>
            ) : (
              displayAlerts.map((a: any, i) => (
                <tr
                  key={i}
                  onClick={() => handleAlertClick(a)}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "rgba(255,255,255,0.04)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "";
                  }}
                  title="Voir dans Incidents"
                >
                  <td>
                    <SevBadge sev={a.severity} />
                  </td>

                  <td
                    style={{
                      maxWidth: "180px",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontSize: "11px",
                    }}
                  >
                    {a.signature_name || a.title || "—"}
                  </td>

                  <td className="font-mono" style={{ fontSize: "11px" }}>
                    {a.src_ip || "—"}
                  </td>

                  <td className="font-mono" style={{ fontSize: "11px" }}>
                    {a.dest_ip || "—"}
                  </td>

                  <td style={{ fontSize: "10px", color: "var(--cs-text2)" }}>
                    {a.fusion_case
                      ? `Fusion Cas ${a.fusion_case}`
                      : a.source || "—"}
                  </td>

                  <td>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                      }}
                    >
                      <div
                        style={{
                          width: "40px",
                          height: "3px",
                          background: "var(--cs-border2)",
                          borderRadius: "2px",
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            height: "100%",
                            borderRadius: "2px",
                            background: "var(--cs-blue)",
                            width: `${
                              confidencePercent(a.confidence || a.ml_score || 0)
                            }%`,
                          }}
                        />
                      </div>

                      <span
                        className="font-mono"
                        style={{
                          fontSize: "10px",
                          color: "var(--cs-text2)",
                        }}
                      >
                        {formatConfidence(a.confidence || a.ml_score || 0)}
                      </span>
                    </div>
                  </td>

                  <td
                    className="font-mono"
                    style={{ fontSize: "10px", color: "var(--cs-blue)" }}
                  >
                    {a.technique_id || "—"}
                  </td>

                  <td style={{ fontSize: "10px", color: "var(--cs-text3)" }}>
                    {a.detected_at
                      ? new Date(a.detected_at).toLocaleTimeString("fr-FR")
                      : "—"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}