// ============================================================
// pages/HIDSMonitor.tsx
// M11 — HIDS / Wazuh Monitor
// ============================================================

import { useEffect, useMemo, useState } from "react";
import {
  Shield,
  Server,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Terminal,
  Radio,
  Clock,
  Link2,
} from "lucide-react";

import { hidsAPI } from "../services/api";

type Severity = "CRITIQUE" | "ELEVE" | "MOYEN" | "FAIBLE" | string;

type HidsStats = {
  success: boolean;
  source: string;
  total_alerts: number;
  by_severity: { severity: Severity; count: number }[];
  top_rules: { signature_name: string; count: number }[];
  top_categories: { category: string; count: number }[];
  top_ip_pairs: { src_ip: string; dest_ip: string; count: number }[];
};

type HidsAlert = {
  id: number;
  source: string;
  severity: Severity;
  src_ip: string;
  dest_ip: string;
  signature_id?: number;
  signature_name?: string;
  category?: string;
  confidence?: number;
  created_at?: string;
  detected_at?: string;
  timestamp?: string;
};

type AgentStatus = {
  success: boolean;
  agent: string;
  id?: string;
  ip?: string;
  status?: string;
  online?: boolean;
  raw?: any;
};

const severityClass: Record<string, string> = {
  CRITIQUE: "bg-red-100 text-red-700 border-red-200",
  ELEVE: "bg-orange-100 text-orange-700 border-orange-200",
  MOYEN: "bg-yellow-100 text-yellow-700 border-yellow-200",
  FAIBLE: "bg-green-100 text-green-700 border-green-200",
};

function getSeverityClass(severity?: string) {
  return severityClass[severity || ""] || "bg-gray-100 text-gray-700 border-gray-200";
}

function formatDate(value?: string) {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return value;
  }
}

export function HIDSMonitor() {
  const [stats, setStats] = useState<HidsStats | null>(null);
  const [alerts, setAlerts] = useState<HidsAlert[]>([]);
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    try {
      setLoading(true);
      setError(null);

      const [statsRes, alertsRes, agentRes] = await Promise.all([
        hidsAPI.getStats(),
        hidsAPI.getAlerts(30),
        hidsAPI.getAgentStatus(),
      ]);

      setStats(statsRes);
      setAlerts(alertsRes?.items || []);
      setAgent(agentRes);
      setLastRefresh(new Date());
    } catch (err: any) {
      console.error("Erreur chargement HIDS:", err);
      setError(err?.message || "Erreur chargement HIDS");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();

    const interval = setInterval(() => {
      loadData();
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  const severityCounts = useMemo(() => {
    const map: Record<string, number> = {};
    stats?.by_severity?.forEach((item) => {
      map[item.severity] = item.count;
    });
    return map;
  }, [stats]);

  const correlations = useMemo(() => {
    return (stats?.top_ip_pairs || []).filter(
      (item) =>
        item.src_ip &&
        item.dest_ip &&
        item.src_ip !== "0.0.0.0" &&
        item.dest_ip !== "0.0.0.0" &&
        item.src_ip !== item.dest_ip
    );
  }, [stats]);

  return (
    <div className="min-h-screen bg-slate-50 p-6">
      <div className="mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="flex flex-col gap-4 rounded-2xl border bg-white p-6 shadow-sm md:flex-row md:items-center md:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="rounded-2xl bg-slate-900 p-3 text-white">
                <Shield className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-slate-900">
                  HIDS Monitor
                </h1>
                <p className="text-sm text-slate-500">
                  Surveillance Wazuh agents, alertes hôte et corrélation NIDS + HIDS
                </p>
              </div>
            </div>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 rounded-xl border bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50 disabled:opacity-60"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Rafraîchir
          </button>
        </div>

        {error && (
          <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
            {error}
          </div>
        )}

        {/* Agent status */}
        <div className="grid gap-4 md:grid-cols-4">
          <div className="rounded-2xl border bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-500">Agent Wazuh</p>
                <h2 className="mt-1 text-xl font-bold text-slate-900">
                  {agent?.agent || "ai-learn"}
                </h2>
              </div>

              {agent?.online ? (
                <CheckCircle2 className="h-8 w-8 text-green-600" />
              ) : (
                <XCircle className="h-8 w-8 text-red-600" />
              )}
            </div>

            <div className="mt-4">
              <span
                className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${
                  agent?.online
                    ? "border-green-200 bg-green-50 text-green-700"
                    : "border-red-200 bg-red-50 text-red-700"
                }`}
              >
                <Radio className="h-3 w-3" />
                {agent?.status || "unknown"}
              </span>
            </div>
          </div>

          <KpiCard
            icon={<Activity className="h-5 w-5" />}
            label="Total alertes HIDS"
            value={stats?.total_alerts ?? 0}
          />

          <KpiCard
            icon={<AlertTriangle className="h-5 w-5" />}
            label="Alertes élevées"
            value={severityCounts["ELEVE"] || 0}
          />

          <KpiCard
            icon={<Terminal className="h-5 w-5" />}
            label="Alertes critiques"
            value={severityCounts["CRITIQUE"] || 0}
          />
        </div>

        {/* Middle section */}
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Top rules */}
          <div className="rounded-2xl border bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-slate-700" />
              <h2 className="text-lg font-semibold text-slate-900">
                Top règles Wazuh
              </h2>
            </div>

            <div className="space-y-3">
              {(stats?.top_rules || []).slice(0, 8).map((rule, index) => (
                <div
                  key={`${rule.signature_name}-${index}`}
                  className="rounded-xl border bg-slate-50 p-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <p className="line-clamp-2 text-sm font-medium text-slate-800">
                      {rule.signature_name}
                    </p>
                    <span className="rounded-full bg-slate-900 px-2 py-1 text-xs font-semibold text-white">
                      {rule.count}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Correlations */}
          <div className="rounded-2xl border bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <Link2 className="h-5 w-5 text-slate-700" />
              <h2 className="text-lg font-semibold text-slate-900">
                Corrélations NIDS + HIDS
              </h2>
            </div>

            <div className="space-y-3">
              {correlations.length === 0 && (
                <p className="text-sm text-slate-500">
                  Aucune corrélation IP significative pour le moment.
                </p>
              )}

              {correlations.slice(0, 8).map((item, index) => (
                <div
                  key={`${item.src_ip}-${item.dest_ip}-${index}`}
                  className="rounded-xl border bg-slate-50 p-4"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-slate-900">
                        {item.src_ip} → {item.dest_ip}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        Même flux observé côté hôte / fenêtre de corrélation 60s
                      </p>
                    </div>
                    <span className="rounded-full bg-blue-100 px-3 py-1 text-xs font-semibold text-blue-700">
                      {item.count} événements
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Alerts table */}
        <div className="rounded-2xl border bg-white shadow-sm">
          <div className="flex items-center justify-between border-b p-6">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-slate-700" />
              <h2 className="text-lg font-semibold text-slate-900">
                Alertes Wazuh récentes
              </h2>
            </div>

            {lastRefresh && (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Clock className="h-4 w-4" />
                Dernière mise à jour : {lastRefresh.toLocaleTimeString("fr-FR")}
              </div>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50">
                <tr>
                  <Th>ID</Th>
                  <Th>Sévérité</Th>
                  <Th>Source</Th>
                  <Th>Destination</Th>
                  <Th>Règle</Th>
                  <Th>Catégorie</Th>
                  <Th>Date</Th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-100 bg-white">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-50">
                    <Td>#{alert.id}</Td>
                    <Td>
                      <span
                        className={`inline-flex rounded-full border px-2 py-1 text-xs font-semibold ${getSeverityClass(
                          alert.severity
                        )}`}
                      >
                        {alert.severity}
                      </span>
                    </Td>
                    <Td>{alert.src_ip || "-"}</Td>
                    <Td>{alert.dest_ip || "-"}</Td>
                    <Td>
                      <div className="max-w-md">
                        <p className="line-clamp-2 text-sm font-medium text-slate-800">
                          {alert.signature_name || "-"}
                        </p>
                        {alert.signature_id && (
                          <p className="mt-1 text-xs text-slate-400">
                            SID {alert.signature_id}
                          </p>
                        )}
                      </div>
                    </Td>
                    <Td>{alert.category || "-"}</Td>
                    <Td>{formatDate(alert.detected_at || alert.created_at)}</Td>
                  </tr>
                ))}

                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-sm text-slate-500">
                      Aucune alerte Wazuh trouvée.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function KpiCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-2xl border bg-white p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="rounded-xl bg-slate-100 p-3 text-slate-700">
          {icon}
        </div>
      </div>
      <p className="mt-4 text-sm text-slate-500">{label}</p>
      <h3 className="mt-1 text-2xl font-bold text-slate-900">{value}</h3>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
      {children}
    </th>
  );
}

function Td({ children }: { children: React.ReactNode }) {
  return (
    <td className="whitespace-nowrap px-4 py-4 text-sm text-slate-700">
      {children}
    </td>
  );
}

export default HIDSMonitor;
