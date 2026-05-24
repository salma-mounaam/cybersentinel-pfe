// ============================================================
// pages/HIDSMonitor.tsx
// M11 — HIDS / Wazuh Monitor
//
// Objectif :
//   - Afficher toutes les machines depuis /api/agents/status
//   - Afficher les logs HIDS/Wazuh par machine
//   - Éviter de mélanger les logs de vuln-assesment avec ai-learn
//   - Filtre : Tous / ai-learn / vuln-assesment
// ============================================================

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
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
  Cpu,
  ListFilter,
} from "lucide-react";

import { hidsAPI, assetsAPI } from "../services/api";

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

type Severity = "CRITIQUE" | "ELEVE" | "MOYEN" | "FAIBLE" | string;

type HidsStats = {
  success?: boolean;
  source?: string;
  total_alerts?: number;
  by_severity?: { severity: Severity; count: number }[];
  top_rules?: { signature_name: string; count: number }[];
  top_categories?: { category: string; count: number }[];
  top_ip_pairs?: { src_ip: string; dest_ip: string; count: number }[];
};

type HidsAlert = {
  id: number;
  source?: string;
  severity: Severity;
  src_ip?: string;
  dest_ip?: string;
  signature_id?: number;
  signature_name?: string;
  category?: string;
  confidence?: number;
  ml_score?: number;
  created_at?: string;
  detected_at?: string;
  timestamp?: string;

  // Champs recommandés côté backend pour logs propres par machine
  asset_ip?: string | null;
  asset_name?: string | null;
  agent_ip?: string | null;
  agent_hostname?: string | null;
  raw_payload?: any;
};

type AgentStatus = {
  success?: boolean;
  agent?: string;
  id?: string;
  ip?: string;
  status?: string;
  online?: boolean;
  raw?: any;
};

type MonitoredMachine = {
  id: number;
  hostname: string;
  ip_address: string;
  environment: string;
  criticality: number;
  owner?: string | null;
  agent_status: "active" | "offline" | "unknown" | string;
  last_heartbeat?: string | null;
  suricata_status?: string | null;
  wazuh_status?: string | null;
  wazuh_agent_id?: string | null;
  tags?: string[];
};

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

const severityClass: Record<string, string> = {
  CRITIQUE: "bg-red-100 text-red-700 border-red-200",
  ELEVE: "bg-orange-100 text-orange-700 border-orange-200",
  MOYEN: "bg-yellow-100 text-yellow-700 border-yellow-200",
  FAIBLE: "bg-green-100 text-green-700 border-green-200",
};

function getSeverityClass(severity?: string) {
  return (
    severityClass[severity || ""] ||
    "bg-gray-100 text-gray-700 border-gray-200"
  );
}

function formatDate(value?: string | null) {
  if (!value) return "—";

  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return value;
  }
}

function criticalityColor(c: number): string {
  if (c >= 8) return "font-bold text-red-600";
  if (c >= 5) return "font-bold text-orange-500";
  return "font-bold text-green-600";
}

function agentBadgeClass(status: string): string {
  if (status === "active") return "border-green-200 bg-green-50 text-green-700";
  if (status === "offline") return "border-red-200 bg-red-50 text-red-700";
  return "border-yellow-200 bg-yellow-50 text-yellow-700";
}

function agentIcon(status: string): string {
  if (status === "active") return "✅";
  if (status === "offline") return "❌";
  return "⚠️";
}

function serviceBadge(status?: string | null) {
  if (!status) {
    return <span className="text-slate-400">—</span>;
  }

  return (
    <span
      className={`rounded-full border px-2 py-1 text-xs font-medium ${
        status === "active"
          ? "border-green-200 bg-green-50 text-green-700"
          : "border-slate-200 bg-slate-50 text-slate-500"
      }`}
    >
      {status}
    </span>
  );
}

function getRawValue(raw: any, keys: string[]): any {
  for (const key of keys) {
    const parts = key.split(".");
    let current = raw;

    for (const part of parts) {
      if (!current || typeof current !== "object") {
        current = undefined;
        break;
      }
      current = current[part];
    }

    if (current !== undefined && current !== null && current !== "") {
      return current;
    }
  }

  return undefined;
}

/**
 * Filtrage propre par machine.
 *
 * Priorité :
 * 1. agent_ip / agent_hostname : vrai propriétaire du log Wazuh
 * 2. asset_ip / asset_name : asset enrichi
 * 3. fallback HIDS :
 *    - src_ip == machine.ip_address
 *    - ou src_ip == 127.0.0.1 ET dest_ip == machine.ip_address
 *
 * Important :
 * On ne fait PAS simplement dest_ip == machine.ip_address,
 * sinon tous les logs 10.16.2.157 → 10.16.2.150 apparaissent comme logs de ai-learn.
 */
function alertBelongsToMachine(alert: HidsAlert, machine: MonitoredMachine) {
  const raw = alert.raw_payload || {};
  const ip = machine.ip_address;
  const hostname = machine.hostname;

  const agentIp =
    alert.agent_ip ||
    getRawValue(raw, [
      "agent_ip",
      "agent.ip",
      "agent.ip_address",
      "manager.ip",
      "host.ip",
    ]);

  const agentHostname =
    alert.agent_hostname ||
    getRawValue(raw, [
      "agent_hostname",
      "agent.hostname",
      "agent.name",
      "hostname",
      "host.hostname",
      "host.name",
    ]);

  if (agentIp || agentHostname) {
    return agentIp === ip || agentHostname === hostname;
  }

  const assetIp =
    alert.asset_ip ||
    getRawValue(raw, ["asset_ip", "asset.ip", "asset.ip_address"]);

  const assetName =
    alert.asset_name ||
    getRawValue(raw, ["asset_name", "asset.hostname", "asset.name"]);

  if (assetIp || assetName) {
    return assetIp === ip || assetName === hostname;
  }

  const src = alert.src_ip || getRawValue(raw, ["src_ip", "source.ip"]);
  const dst = alert.dest_ip || getRawValue(raw, ["dest_ip", "destination.ip"]);

  if (src === ip) return true;

  if ((src === "127.0.0.1" || src === "::1") && dst === ip) {
    return true;
  }

  return false;
}

// ─────────────────────────────────────────────────────────────
// Composant principal
// ─────────────────────────────────────────────────────────────

export function HIDSMonitor() {
  const [stats, setStats] = useState<HidsStats | null>(null);
  const [alerts, setAlerts] = useState<HidsAlert[]>([]);
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [machines, setMachines] = useState<MonitoredMachine[]>([]);
  const [machineSummary, setMachineSummary] = useState({
    total: 0,
    active: 0,
    offline: 0,
    unknown: 0,
  });

  const [selectedMachineIp, setSelectedMachineIp] = useState<string>("all");

  async function loadData() {
    try {
      setLoading(true);
      setError(null);

      const [statsRes, alertsRes, agentRes, agentsStatusRes] =
        await Promise.all([
          hidsAPI.getStats(),
          hidsAPI.getAlerts(100),
          hidsAPI.getAgentStatus(),
          assetsAPI.getStatus(),
        ]);

      setStats(statsRes || null);

      const loadedAlerts =
        alertsRes?.items ||
        alertsRes?.alerts ||
        alertsRes?.data ||
        [];

      setAlerts(Array.isArray(loadedAlerts) ? loadedAlerts : []);
      setAgent(agentRes || null);

      const loadedMachines = agentsStatusRes?.agents || [];

      setMachines(Array.isArray(loadedMachines) ? loadedMachines : []);

      setMachineSummary(
        agentsStatusRes?.summary || {
          total: loadedMachines.length || 0,
          active: loadedMachines.filter((m: MonitoredMachine) => m.agent_status === "active").length || 0,
          offline: loadedMachines.filter((m: MonitoredMachine) => m.agent_status === "offline").length || 0,
          unknown: loadedMachines.filter((m: MonitoredMachine) => m.agent_status === "unknown").length || 0,
        }
      );

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

    const interval = setInterval(loadData, 15_000);
    return () => clearInterval(interval);
  }, []);

  const severityCounts = useMemo(() => {
    const map: Record<string, number> = {};

    stats?.by_severity?.forEach((item) => {
      map[item.severity] = item.count;
    });

    return map;
  }, [stats]);

  const correlations = useMemo(
    () =>
      (stats?.top_ip_pairs || []).filter(
        (item) =>
          item.src_ip &&
          item.dest_ip &&
          item.src_ip !== "0.0.0.0" &&
          item.dest_ip !== "0.0.0.0" &&
          item.src_ip !== item.dest_ip
      ),
    [stats]
  );

  const selectedMachine = useMemo(() => {
    if (selectedMachineIp === "all") return null;

    return machines.find((m) => m.ip_address === selectedMachineIp) || null;
  }, [machines, selectedMachineIp]);

  const alertsByMachine = useMemo(() => {
    if (selectedMachineIp === "all") return alerts;

    const machine = machines.find((m) => m.ip_address === selectedMachineIp);

    if (!machine) return [];

    return alerts.filter((alert) => alertBelongsToMachine(alert, machine));
  }, [alerts, machines, selectedMachineIp]);

  const machineLogCounts = useMemo(() => {
    const counts: Record<string, number> = {};

    for (const machine of machines) {
      counts[machine.ip_address] = alerts.filter((alert) =>
        alertBelongsToMachine(alert, machine)
      ).length;
    }

    return counts;
  }, [alerts, machines]);

  return (
    <div className="min-h-screen bg-slate-50 p-6">
      <div className="mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="flex flex-col gap-4 rounded-2xl border bg-white p-6 shadow-sm md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-2xl bg-slate-900 p-3 text-white">
              <Shield className="h-6 w-6" />
            </div>

            <div>
              <h1 className="text-2xl font-bold text-slate-900">
                HIDS Monitor
              </h1>
              <p className="text-sm text-slate-500">
                Surveillance Wazuh agents, alertes hôte et corrélation NIDS +
                HIDS
              </p>
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

        {/* KPIs */}
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

        {/* Machines surveillées */}
        <div className="rounded-2xl border bg-white p-6 shadow-sm">
          <div className="mb-4 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <Cpu className="h-5 w-5 text-slate-700" />
                <h2 className="text-lg font-bold text-slate-900">
                  Machines surveillées
                </h2>
              </div>

              <p className="mt-1 text-sm text-slate-500">
                Statut heartbeat, Suricata, Wazuh et logs associés à chaque
                asset.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-sm text-slate-500">
              <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1">
                Total :{" "}
                <strong className="text-slate-900">
                  {machineSummary.total}
                </strong>
              </span>

              <span className="rounded-full border border-green-200 bg-green-50 px-3 py-1 text-green-700">
                Actifs : <strong>{machineSummary.active}</strong>
              </span>

              <span className="rounded-full border border-red-200 bg-red-50 px-3 py-1 text-red-700">
                Hors ligne : <strong>{machineSummary.offline}</strong>
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b bg-slate-50">
                  <Th>Machine</Th>
                  <Th>IP</Th>
                  <Th>Env</Th>
                  <Th>Criticité</Th>
                  <Th>Agent</Th>
                  <Th>Suricata</Th>
                  <Th>Wazuh</Th>
                  <Th>Dernier heartbeat</Th>
                  <Th>Logs</Th>
                </tr>
              </thead>

              <tbody>
                {machines.map((m) => (
                  <tr key={m.id} className="border-b hover:bg-slate-50">
                    <Td>
                      <div>
                        <p className="font-semibold text-slate-900">
                          {m.hostname}
                        </p>
                        <p className="text-xs text-slate-400">
                          {m.owner || "—"}
                        </p>
                      </div>
                    </Td>

                    <Td>
                      <span className="font-mono text-xs text-slate-600">
                        {m.ip_address}
                      </span>
                    </Td>

                    <Td>
                      <span className="rounded-full border bg-slate-50 px-2 py-1 text-xs">
                        {m.environment || "unknown"}
                      </span>
                    </Td>

                    <Td>
                      <span className={criticalityColor(Number(m.criticality))}>
                        {m.criticality}/10
                      </span>
                    </Td>

                    <Td>
                      <span
                        className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-xs font-semibold ${agentBadgeClass(
                          m.agent_status
                        )}`}
                      >
                        {agentIcon(m.agent_status)} {m.agent_status}
                      </span>
                    </Td>

                    <Td>{serviceBadge(m.suricata_status)}</Td>
                    <Td>{serviceBadge(m.wazuh_status)}</Td>

                    <Td>
                      <span className="text-xs text-slate-500">
                        {formatDate(m.last_heartbeat || undefined)}
                      </span>
                    </Td>

                    <Td>
                      <button
                        onClick={() => setSelectedMachineIp(m.ip_address)}
                        className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                          selectedMachineIp === m.ip_address
                            ? "border-blue-700 bg-blue-600 text-white"
                            : "border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100"
                        }`}
                      >
                        {machineLogCounts[m.ip_address] || 0} logs
                      </button>
                    </Td>
                  </tr>
                ))}

                {machines.length === 0 && (
                  <tr>
                    <td
                      colSpan={9}
                      className="p-8 text-center text-sm text-slate-500"
                    >
                      Aucune machine surveillée. Vérifier GET
                      /api/agents/status.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top règles + Corrélations */}
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="rounded-2xl border bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-slate-700" />
              <h2 className="text-lg font-semibold text-slate-900">
                Top règles Wazuh
              </h2>
            </div>

            <div className="space-y-3">
              {(stats?.top_rules || []).slice(0, 8).map((rule, i) => (
                <div
                  key={`${rule.signature_name}-${i}`}
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

              {(stats?.top_rules || []).length === 0 && (
                <p className="text-sm text-slate-500">
                  Aucune règle déclenchée.
                </p>
              )}
            </div>
          </div>

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

              {correlations.slice(0, 8).map((item, i) => (
                <div
                  key={`${item.src_ip}-${item.dest_ip}-${i}`}
                  className="rounded-xl border bg-slate-50 p-4"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-slate-900">
                        {item.src_ip} → {item.dest_ip}
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        Même flux observé côté hôte / fenêtre 60s
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

        {/* Table alertes Wazuh récentes */}
        <div className="rounded-2xl border bg-white shadow-sm">
          <div className="flex flex-col gap-4 border-b p-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-slate-700" />

              <div>
                <h2 className="text-lg font-semibold text-slate-900">
                  Alertes Wazuh récentes
                </h2>

                <p className="text-sm text-slate-500">
                  {selectedMachine
                    ? `Logs filtrés pour ${selectedMachine.hostname} / ${selectedMachine.ip_address}`
                    : "Tous les logs HIDS/Wazuh"}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => setSelectedMachineIp("all")}
                className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs font-semibold ${
                  selectedMachineIp === "all"
                    ? "border-slate-900 bg-slate-900 text-white"
                    : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                }`}
              >
                <ListFilter className="h-3 w-3" />
                Tous
              </button>

              {machines.map((m) => (
                <button
                  key={m.id}
                  onClick={() => setSelectedMachineIp(m.ip_address)}
                  className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                    selectedMachineIp === m.ip_address
                      ? "border-blue-700 bg-blue-600 text-white"
                      : "border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100"
                  }`}
                >
                  {m.hostname}
                </button>
              ))}

              {lastRefresh && (
                <div className="ml-2 flex items-center gap-2 text-xs text-slate-500">
                  <Clock className="h-4 w-4" />
                  Mise à jour : {lastRefresh.toLocaleTimeString("fr-FR")}
                </div>
              )}
            </div>
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
                {alertsByMachine.map((alert) => (
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

                    <Td>{alert.src_ip || "—"}</Td>
                    <Td>{alert.dest_ip || "—"}</Td>

                    <Td>
                      <div className="max-w-md">
                        <p className="line-clamp-2 text-sm font-medium text-slate-800">
                          {alert.signature_name || "—"}
                        </p>

                        {alert.signature_id && (
                          <p className="mt-1 text-xs text-slate-400">
                            SID {alert.signature_id}
                          </p>
                        )}
                      </div>
                    </Td>

                    <Td>{alert.category || "—"}</Td>
                    <Td>{formatDate(alert.detected_at || alert.created_at)}</Td>
                  </tr>
                ))}

                {alertsByMachine.length === 0 && (
                  <tr>
                    <td
                      colSpan={7}
                      className="p-8 text-center text-sm text-slate-500"
                    >
                      Aucune alerte Wazuh trouvée pour ce filtre.
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

// ─────────────────────────────────────────────────────────────
// Sous-composants
// ─────────────────────────────────────────────────────────────

function KpiCard({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
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

function Th({ children }: { children: ReactNode }) {
  return (
    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
      {children}
    </th>
  );
}

function Td({ children }: { children: ReactNode }) {
  return (
    <td className="whitespace-nowrap px-4 py-4 text-sm text-slate-700">
      {children}
    </td>
  );
}

export default HIDSMonitor;