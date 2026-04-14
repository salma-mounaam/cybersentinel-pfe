// ============================================================
// pages/Overview.tsx — Dashboard principal
// Aligné avec Scan Center : M4 SAST + M5 DAST + M8 CI/CD
// ============================================================

import React, { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
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
  KPICard,
  PageHeader,
  LiveBadge,
  SevBadge,
  Empty,
  Loading,
} from "../components/common";
import {
  severityPieData,
  aggregateSeverityMap,
  confidencePercent,
  formatConfidence,
} from "../lib/cyber";

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

function HeaderButtons() {
  const navigate = useNavigate();

  const baseBtn: React.CSSProperties = {
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
          ...baseBtn,
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
          ...baseBtn,
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

function MiniStatusCard({
  title,
  value,
  sub,
  color,
}: {
  title: string;
  value: string | number;
  sub: string;
  color: string;
}) {
  return (
    <div className="card" style={{ padding: "12px 14px" }}>
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
        {title}
      </div>
      <div
        style={{
          fontSize: "22px",
          fontWeight: 600,
          color,
          fontFamily: "'IBM Plex Mono', monospace",
        }}
      >
        {value}
      </div>
      <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginTop: "4px" }}>
        {sub}
      </div>
    </div>
  );
}

export default function Overview() {
  const [alertStats, setAlertStats] = useState<any>(null);
  const [incidentStats, setIncidentStats] = useState<any>(null);
  const [fusionStats, setFusionStats] = useState<any>(null);
  const [mlStatus, setMLStatus] = useState<any>(null);

  const [sastStats, setSastStats] = useState<any>(null);
  const [dastStatus, setDastStatus] = useState<any>(null);
  const [cicdRuns, setCicdRuns] = useState<any>(null);

  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<any[]>([]);
  const [liveHistory, setLiveHistory] = useState<{ time: string; score: number }[]>([]);
  const [liveCount, setLiveCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [as, is, fs, ms, ss, cr, ra] = await Promise.all([
        alertsAPI.getStats(),
        incidentsAPI.getStats(),
        fusionAPI.getStats(),
        mlAPI.getStatus(),
        sastAPI.getStats(),
        cicdAPI.getRuns(),
        alertsAPI.getRecent(15),
      ]);

      const [dastStatusRaw, dastFindings, dastIso] = await Promise.all([
        dastAPI.getStatus(),
        dastAPI.getFindings(1),
        dastAPI.verifyIsolation(),
      ]);

      const dastEnriched = {
        ...dastStatusRaw,
        total_scans: 0,
        isolation_ok: dastIso?.ca09_passed ?? false,
        total_findings: dastFindings?.total_proofs ?? 0,
      };

      setAlertStats(as);
      setIncidentStats(is);
      setFusionStats(fs);
      setMLStatus(ms);
      setSastStats(ss);
      setDastStatus(dastEnriched);
      setCicdRuns(cr);
      setRecentAlerts(ra.alerts || []);
    } catch (e) {
      console.error("Overview load error:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
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

  const { connected } = useWebSocket({ channel: "alerts", onMessage: handleWS });

  const alertSeverityAgg = aggregateSeverityMap(alertStats?.by_severity);
  const incidentSeverityAgg = aggregateSeverityMap(incidentStats?.by_severity);

  const pieData = severityPieData(alertStats?.by_severity);
  const incPieData = severityPieData(incidentStats?.by_severity);

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
          marginBottom: "20px",
        }}
      >
        <KPICard
          label="Alertes totales"
          value={alertStats?.total ?? "—"}
          color="var(--cs-blue)"
          sub={`${alertSeverityAgg.CRITICAL} critiques`}
        />
        <KPICard
          label="Incidents ouverts"
          value={incidentStats?.total ?? "—"}
          color={incidentSeverityAgg.CRITICAL > 0 ? "var(--cs-red)" : "var(--cs-text)"}
          sub={`Score R moyen : ${incidentStats?.avg_score_r ?? "—"}`}
        />
        <KPICard
          label="FPR réduit"
          value={`${fusionStats?.estimated_fpr_reduction_pct ?? 0}%`}
          color={fusionStats?.h2_on_track ? "var(--cs-green)" : "var(--cs-amber)"}
          sub={`${fusionStats?.noise_eliminated ?? 0} bruits éliminés`}
        />
        <KPICard
          label="Modèles ML"
          value={mlStatus?.models_loaded ? "Actifs" : "En attente"}
          color={mlStatus?.models_loaded ? "var(--cs-green)" : "var(--cs-text2)"}
          sub={mlStatus?.active_version?.version ?? "Pas d'entraînement"}
        />
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: "10px",
          marginBottom: "18px",
        }}
      >
        <MiniStatusCard
          title="M4 · SAST"
          value={sastStats?.total_findings ?? sastStats?.total ?? 0}
          sub={`${sastStats?.critical ?? sastStats?.by_severity?.CRITICAL ?? 0} critiques · ${
            sastStats?.secrets ?? sastStats?.by_tool?.gitleaks ?? 0
          } secrets`}
          color="var(--cs-blue)"
        />
        <MiniStatusCard
          title="M5 · DAST"
          value={dastStatus?.active ? "Active" : "Inactive"}
          sub={`Sandbox ${dastStatus?.isolation_ok ? "isolée" : "à vérifier"} · ${
            dastStatus?.total_findings ?? 0
          } preuves`}
          color="var(--cs-red)"
        />
        <MiniStatusCard
          title="M8 · CI/CD"
          value={cicdRuns?.total ?? 0}
          sub={`${cicdRuns?.blocked ?? 0} bloqués · block rate ${cicdRuns?.block_rate ?? 0}%`}
          color="var(--cs-teal)"
        />
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: "12px",
          marginBottom: "16px",
        }}
      >
        <div className="card">
          <div
            style={{
              fontSize: "11px",
              color: "var(--cs-text2)",
              marginBottom: "12px",
              fontFamily: "monospace",
              textTransform: "uppercase",
              letterSpacing: ".5px",
            }}
          >
            Alertes par sévérité
          </div>

          {pieData.length === 0 ? (
            <Empty text="Aucune alerte" />
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={70}
                  dataKey="value"
                  paddingAngle={3}
                >
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--cs-surface2)",
                    border: "0.5px solid var(--cs-border2)",
                    borderRadius: "6px",
                    fontSize: "11px",
                    color: "var(--cs-text)",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}

          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "8px" }}>
            {pieData.map((d, i) => (
              <div
                key={i}
                style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px" }}
              >
                <span
                  style={{
                    width: "7px",
                    height: "7px",
                    borderRadius: "50%",
                    background: d.color,
                    display: "inline-block",
                  }}
                />
                <span style={{ color: "var(--cs-text2)" }}>
                  {d.label} ({d.value})
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div
            style={{
              fontSize: "11px",
              color: "var(--cs-text2)",
              marginBottom: "12px",
              fontFamily: "monospace",
              textTransform: "uppercase",
              letterSpacing: ".5px",
            }}
          >
            Incidents par sévérité
          </div>

          {incPieData.length === 0 ? (
            <Empty text="Aucun incident" />
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie
                  data={incPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={70}
                  dataKey="value"
                  paddingAngle={3}
                >
                  {incPieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--cs-surface2)",
                    border: "0.5px solid var(--cs-border2)",
                    borderRadius: "6px",
                    fontSize: "11px",
                    color: "var(--cs-text)",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}

          <div style={{ fontSize: "10px", color: "var(--cs-text2)", marginTop: "8px" }}>
            SLA dépassés :{" "}
            <span
              style={{
                color: incidentStats?.overdue_sla > 0 ? "var(--cs-red)" : "var(--cs-green)",
              }}
            >
              {incidentStats?.overdue_sla ?? 0}
            </span>
          </div>
        </div>

        <div className="card">
          <div
            style={{
              fontSize: "11px",
              color: "var(--cs-text2)",
              marginBottom: "12px",
              fontFamily: "monospace",
              textTransform: "uppercase",
              letterSpacing: ".5px",
            }}
          >
            Scores live (WebSocket)
          </div>

          {liveHistory.length === 0 ? (
            <div
              style={{
                height: 160,
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
            <ResponsiveContainer width="100%" height={160}>
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
                  width={30}
                />
                <CartesianGrid strokeDasharray="3 3" stroke="var(--cs-border)" />
                <Tooltip
                  contentStyle={{
                    background: "var(--cs-surface2)",
                    border: "0.5px solid var(--cs-border2)",
                    borderRadius: "6px",
                    fontSize: "11px",
                    color: "var(--cs-text)",
                  }}
                />
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
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(5, 1fr)",
          gap: "8px",
          marginBottom: "16px",
        }}
      >
        {[
          { label: "Cas 1 — Sig+ML+Flux", key: "case_1", color: "var(--cs-green)" },
          { label: "Cas 2 — Sig+ML+5s", key: "case_2", color: "var(--cs-teal)" },
          { label: "Cas 3 — Sig seule", key: "case_3", color: "var(--cs-blue)" },
          { label: "Cas 4 — ML seul", key: "case_4", color: "var(--cs-purple)" },
          { label: "Cas 5 — Bruit ignoré", key: "case_5", color: "var(--cs-text3)" },
        ].map((c, i) => (
          <div key={i} className="card" style={{ padding: "10px 12px", textAlign: "center" }}>
            <div
              style={{
                fontSize: "9px",
                color: "var(--cs-text2)",
                marginBottom: "4px",
                fontFamily: "monospace",
                textTransform: "uppercase",
                letterSpacing: ".3px",
              }}
            >
              {c.label}
            </div>
            <div
              style={{
                fontSize: "22px",
                fontWeight: 500,
                color: c.color,
                fontFamily: "'IBM Plex Mono', monospace",
              }}
            >
              {fusionStats?.cases?.[c.key] ?? 0}
            </div>
          </div>
        ))}
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
            {liveAlerts.length > 0 ? `${liveAlerts.length} en live` : `${recentAlerts.length} depuis Redis`}
          </span>
        </div>

        <table className="cs-table">
          <thead>
            <tr>
              <th>Sévérité</th>
              <th>Signature</th>
              <th>Src IP</th>
              <th>Dest IP</th>
              <th>Fusion</th>
              <th>Confiance</th>
              <th>MITRE</th>
              <th>Heure</th>
            </tr>
          </thead>
          <tbody>
            {(liveAlerts.length > 0 ? liveAlerts : recentAlerts).length === 0 ? (
              <tr>
                <td colSpan={8} style={{ padding: "32px", textAlign: "center", color: "var(--cs-text3)" }}>
                  En attente d'alertes Suricata...
                </td>
              </tr>
            ) : (
              (liveAlerts.length > 0 ? liveAlerts : recentAlerts).map((a: any, i) => (
                <tr key={i}>
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
                    {a.fusion_case ? `Cas ${a.fusion_case}` : "—"}
                  </td>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
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
                            width: `${confidencePercent(a.confidence || a.ml_score || 0)}%`,
                          }}
                        />
                      </div>
                      <span
                        className="font-mono"
                        style={{ fontSize: "10px", color: "var(--cs-text2)" }}
                      >
                        {formatConfidence(a.confidence || a.ml_score || 0)}
                      </span>
                    </div>
                  </td>
                  <td className="font-mono" style={{ fontSize: "10px", color: "var(--cs-blue)" }}>
                    {a.technique_id || "—"}
                  </td>
                  <td style={{ fontSize: "10px", color: "var(--cs-text3)" }}>
                    {a.detected_at ? new Date(a.detected_at).toLocaleTimeString("fr-FR") : "—"}
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