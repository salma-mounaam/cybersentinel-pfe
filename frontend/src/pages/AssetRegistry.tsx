// ============================================================
// M12 — Asset Registry
// Supervision multi-machine + heartbeat agents
// ============================================================

import { useEffect, useMemo, useState } from "react";
import {
  Server,
  Activity,
  AlertTriangle,
  ShieldCheck,
  RefreshCw,
  Wifi,
  WifiOff,
  Clock,
  Database,
} from "lucide-react";

import { assetsAPI } from "../services/api";

type AgentStatus = "active" | "offline" | "unknown";

type Asset = {
  id: number;
  hostname: string;
  ip_address: string;
  environment: string;
  criticality: number;
  owner?: string | null;
  agent_status: AgentStatus;
  last_heartbeat?: string | null;
  suricata_status?: string | null;
  wazuh_status?: string | null;
  wazuh_agent_id?: string | null;
  tags?: string[];
  created_at?: string | null;
  updated_at?: string | null;
};

type AgentsStatusResponse = {
  summary?: {
    total: number;
    active: number;
    offline: number;
    unknown: number;
  };
  agents: Asset[];
};

function statusLabel(status?: AgentStatus) {
  if (status === "active") return "Actif";
  if (status === "offline") return "Hors ligne";
  return "Inconnu";
}

function statusClass(status?: AgentStatus) {
  if (status === "active") {
    return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  }

  if (status === "offline") {
    return "bg-red-500/10 text-red-400 border-red-500/30";
  }

  return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
}

function criticalityClass(value: number) {
  if (value >= 9) return "text-red-400";
  if (value >= 7) return "text-orange-400";
  if (value >= 4) return "text-yellow-400";
  return "text-emerald-400";
}

function formatDate(value?: string | null) {
  if (!value) return "—";

  try {
    return new Date(value).toLocaleString("fr-FR", {
      dateStyle: "short",
      timeStyle: "medium",
    });
  } catch {
    return value;
  }
}

export function AssetRegistry() {
  const [agents, setAgents] = useState<Asset[]>([]);
  const [summary, setSummary] = useState({
    total: 0,
    active: 0,
    offline: 0,
    unknown: 0,
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      setLoading(true);
      setError("");

      const res: AgentsStatusResponse = await assetsAPI.getStatus();

      const list = res.agents || [];

      setAgents(list);
      setSummary(
        res.summary || {
          total: list.length,
          active: list.filter((a) => a.agent_status === "active").length,
          offline: list.filter((a) => a.agent_status === "offline").length,
          unknown: list.filter((a) => a.agent_status === "unknown").length,
        }
      );
    } catch (e: any) {
      setError(e?.message || "Erreur chargement Asset Registry");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();

    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const criticalAssets = useMemo(() => {
    return agents.filter((a) => Number(a.criticality || 0) >= 8).length;
  }, [agents]);

  const monitoredWithSecurity = useMemo(() => {
    return agents.filter(
      (a) => a.suricata_status === "active" || a.wazuh_status === "active"
    ).length;
  }, [agents]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/20">
              <Server className="w-6 h-6 text-cyan-400" />
            </div>

            <div>
              <h1 className="text-2xl font-bold">Asset Registry</h1>
              <p className="text-sm text-slate-400">
                Supervision des machines surveillées, agents heartbeat et criticité métier.
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 text-cyan-300 transition disabled:opacity-60"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Actualiser
        </button>
      </div>

      {error && (
        <div className="rounded-2xl border border-red-500/30 bg-red-500/10 text-red-300 px-4 py-3">
          {error}
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Machines totales</p>
              <p className="text-3xl font-bold mt-2">{summary.total}</p>
            </div>
            <Database className="w-8 h-8 text-cyan-400" />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Agents actifs</p>
              <p className="text-3xl font-bold mt-2 text-emerald-400">
                {summary.active}
              </p>
            </div>
            <Wifi className="w-8 h-8 text-emerald-400" />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Hors ligne</p>
              <p className="text-3xl font-bold mt-2 text-red-400">
                {summary.offline}
              </p>
            </div>
            <WifiOff className="w-8 h-8 text-red-400" />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Assets critiques</p>
              <p className="text-3xl font-bold mt-2 text-orange-400">
                {criticalAssets}
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-400" />
          </div>
        </div>
      </div>

      {/* Résumé sécurité */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center gap-3 mb-2">
          <ShieldCheck className="w-5 h-5 text-cyan-400" />
          <h2 className="font-semibold">Couverture sécurité</h2>
        </div>

        <p className="text-sm text-slate-400">
          {monitoredWithSecurity} machine(s) ont au moins un service de sécurité actif
          déclaré par heartbeat : Suricata ou Wazuh.
        </p>
      </div>

      {/* Tableau */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="font-semibold">Machines surveillées</h2>
            <p className="text-sm text-slate-400">
              Statut calculé selon le dernier heartbeat reçu.
            </p>
          </div>

          <div className="text-sm text-slate-400">
            Unknown : {summary.unknown}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-950/60 text-slate-400">
              <tr>
                <th className="text-left px-5 py-3 font-medium">Hostname</th>
                <th className="text-left px-5 py-3 font-medium">IP</th>
                <th className="text-left px-5 py-3 font-medium">Env</th>
                <th className="text-left px-5 py-3 font-medium">Criticité</th>
                <th className="text-left px-5 py-3 font-medium">Agent</th>
                <th className="text-left px-5 py-3 font-medium">Suricata</th>
                <th className="text-left px-5 py-3 font-medium">Wazuh</th>
                <th className="text-left px-5 py-3 font-medium">Dernier heartbeat</th>
                <th className="text-left px-5 py-3 font-medium">Tags</th>
              </tr>
            </thead>

            <tbody>
              {agents.map((asset) => (
                <tr
                  key={asset.id}
                  className="border-t border-slate-800 hover:bg-slate-800/40 transition"
                >
                  <td className="px-5 py-4">
                    <div className="font-medium text-slate-100">
                      {asset.hostname}
                    </div>
                    <div className="text-xs text-slate-500">
                      {asset.owner || "Owner inconnu"}
                    </div>
                  </td>

                  <td className="px-5 py-4 text-slate-300">
                    {asset.ip_address}
                  </td>

                  <td className="px-5 py-4">
                    <span className="px-2 py-1 rounded-lg bg-slate-800 text-slate-300 border border-slate-700">
                      {asset.environment || "unknown"}
                    </span>
                  </td>

                  <td className="px-5 py-4">
                    <span
                      className={`font-bold ${criticalityClass(
                        Number(asset.criticality || 0)
                      )}`}
                    >
                      C={asset.criticality}
                    </span>
                  </td>

                  <td className="px-5 py-4">
                    <span
                      className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-lg border ${statusClass(
                        asset.agent_status
                      )}`}
                    >
                      {asset.agent_status === "active" ? (
                        <Wifi className="w-3.5 h-3.5" />
                      ) : asset.agent_status === "offline" ? (
                        <WifiOff className="w-3.5 h-3.5" />
                      ) : (
                        <Clock className="w-3.5 h-3.5" />
                      )}

                      {statusLabel(asset.agent_status)}
                    </span>
                  </td>

                  <td className="px-5 py-4">
                    <span className="text-slate-300">
                      {asset.suricata_status || "—"}
                    </span>
                  </td>

                  <td className="px-5 py-4">
                    <span className="text-slate-300">
                      {asset.wazuh_status || "—"}
                    </span>
                  </td>

                  <td className="px-5 py-4 text-slate-400">
                    {formatDate(asset.last_heartbeat)}
                  </td>

                  <td className="px-5 py-4">
                    <div className="flex flex-wrap gap-1">
                      {(asset.tags || []).slice(0, 3).map((tag) => (
                        <span
                          key={tag}
                          className="px-2 py-0.5 rounded-md bg-slate-800 text-xs text-slate-300 border border-slate-700"
                        >
                          {tag}
                        </span>
                      ))}

                      {(!asset.tags || asset.tags.length === 0) && (
                        <span className="text-slate-500">—</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}

              {agents.length === 0 && !loading && (
                <tr>
                  <td colSpan={9} className="px-5 py-10 text-center text-slate-400">
                    Aucun asset trouvé.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {loading && (
        <div className="text-sm text-slate-500 flex items-center gap-2">
          <RefreshCw className="w-4 h-4 animate-spin" />
          Chargement...
        </div>
      )}
    </div>
  );
}
export default AssetRegistry;
