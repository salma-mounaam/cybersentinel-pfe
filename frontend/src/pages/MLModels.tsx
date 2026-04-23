// ============================================================
// pages/MLModels.tsx — M2 / M10
// Version compatible sans shadcn dialog
// ============================================================
import React, { useEffect, useMemo, useState } from "react";
import {
  BrainCircuit,
  Play,
  RotateCcw,
  CheckCircle2,
  Loader2,
  TrendingUp,
  AlertTriangle,
  Database,
  Clock,
  Activity,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { cn } from "../lib/utils";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { mlAPI } from "../services/api";

// ── Types ─────────────────────────────────────────────────────
type ModelStatus = {
  models_loaded?: boolean;
  if_model?: boolean;
  ocsvm_model?: boolean;
  ae_model?: boolean;
  scaler?: boolean;
  active_version?: {
    version?: string;
    metrics?: VersionMetrics;
  } | null;
};

type VersionMetrics = {
  precision_mean?: number;
  recall_mean?: number;
  f1_mean?: number;
  fpr_mean?: number;
  h1_validated?: boolean;
};

type VersionItem = {
  version: string;
  created_at?: string;
  is_active?: boolean;
  metrics?: VersionMetrics;
};

type RegistryResponse = {
  versions?: VersionItem[];
  active_version?: string | null;
};

type H3Response = {
  h3_validated?: boolean;
  delta_f1?: number;
  f1_v0?: number;
  f1_vN?: number;
  message?: string;
};

type TrainResponse = {
  deployed?: boolean;
  version?: string;
  steps?: Record<string, any>;
  message?: string;
};

// ── Helpers ───────────────────────────────────────────────────
function pct(value?: number, digits = 0) {
  return `${(((value || 0) * 100) as number).toFixed(digits)}%`;
}

function safeNumber(value: unknown, fallback = 0) {
  return typeof value === "number" && !Number.isNaN(value) ? value : fallback;
}

function shortVersion(version?: string | null, size = 10) {
  if (!version) return "—";
  return version.slice(-size);
}

function metricColor(type: "f1" | "recall" | "precision" | "fpr", value?: number) {
  const v = safeNumber(value);

  if (type === "fpr") {
    if (v > 0.1) return "text-red-400";
    if (v > 0.05) return "text-orange-400";
    return "text-green-400";
  }

  if (v >= 0.85) return "text-green-400";
  if (v >= 0.7) return "text-violet-400";
  if (v >= 0.5) return "text-amber-400";
  return "text-red-400";
}

// ── ModelCard ─────────────────────────────────────────────────
function ModelCard({
  name,
  version,
  f1,
  recall,
  precision,
  fpr,
  isAvailable,
  isActive,
  onDeploy,
  onRollback,
}: {
  name: string;
  version: string;
  f1: number;
  recall: number;
  precision: number;
  fpr: number;
  isAvailable: boolean;
  isActive: boolean;
  onDeploy: () => void;
  onRollback: () => void;
}) {
  return (
    <Card className="bg-card/50 border-cyber-border hover:border-violet-500/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                "p-2 rounded-lg",
                isAvailable ? "bg-green-500/10" : "bg-muted/20"
              )}
            >
              <BrainCircuit
                size={18}
                className={cn(
                  isAvailable ? "text-green-400" : "text-muted-foreground"
                )}
              />
            </div>

            <div>
              <h4 className="font-medium text-sm">{name}</h4>
              <p className="text-xs text-muted-foreground">v{version}</p>
            </div>
          </div>

          <div className="flex flex-col items-end gap-1">
            <Badge
              variant="secondary"
              className={cn(
                isAvailable
                  ? "bg-green-500/10 text-green-400"
                  : "bg-muted/20 text-muted-foreground"
              )}
            >
              {isAvailable ? "loaded" : "unloaded"}
            </Badge>

            <Badge
              variant="secondary"
              className={cn(
                isActive
                  ? "bg-violet-500/10 text-violet-400"
                  : "bg-muted/20 text-muted-foreground"
              )}
            >
              {isActive && <CheckCircle2 size={10} className="mr-1" />}
              {isActive ? "active" : "standby"}
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-2 mb-4">
          {[
            { label: "F1", value: pct(f1), color: metricColor("f1", f1) },
            { label: "Recall", value: pct(recall), color: metricColor("recall", recall) },
            {
              label: "Precision",
              value: pct(precision),
              color: metricColor("precision", precision),
            },
            { label: "FPR", value: pct(fpr, 1), color: metricColor("fpr", fpr) },
          ].map((m) => (
            <div key={m.label} className="text-center p-2 rounded bg-card/80">
              <p className={cn("text-lg font-bold font-mono", m.color)}>{m.value}</p>
              <p className="text-[9px] text-muted-foreground">{m.label}</p>
            </div>
          ))}
        </div>

        <div className="flex gap-2">
          {!isActive && (
            <Button
              size="sm"
              className="flex-1 bg-green-600 hover:bg-green-700"
              onClick={onDeploy}
            >
              <Play size={14} className="mr-1" />
              Déployer
            </Button>
          )}

          {isActive && (
            <Button size="sm" variant="outline" className="flex-1" onClick={onRollback}>
              <RotateCcw size={14} className="mr-1" />
              Rollback
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Composant principal ───────────────────────────────────────
export function MLModels() {
  const [status, setStatus] = useState<ModelStatus | null>(null);
  const [registry, setRegistry] = useState<RegistryResponse | null>(null);
  const [h3, setH3] = useState<H3Response | null>(null);

  const [training, setTraining] = useState(false);
  const [trainMsg, setTrainMsg] = useState("");
  const [trainSuccess, setTrainSuccess] = useState(false);

  const [deployTarget, setDeployTarget] = useState<string | null>(null);
  const [showDeploy, setShowDeploy] = useState(false);

  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  const load = async () => {
    try {
      const [s, r, h] = await Promise.all([
        mlAPI.getStatus(),
        mlAPI.getRegistry(),
        mlAPI.getH3(),
      ]);

      setStatus(s || null);
      setRegistry(r || null);
      setH3(h || null);
    } catch (e) {
      console.error("Erreur chargement ML:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const versions = useMemo<VersionItem[]>(() => {
    if (!Array.isArray(registry?.versions)) return [];
    return registry?.versions ?? [];
  }, [registry]);

  const activeVersionString =
    registry?.active_version ||
    status?.active_version?.version ||
    versions.find((v) => v.is_active)?.version ||
    null;

  const activeVersionObject =
    versions.find((v) => v.version === activeVersionString) ||
    versions.find((v) => v.is_active) ||
    null;

  const activeMetrics: VersionMetrics =
    activeVersionObject?.metrics ||
    status?.active_version?.metrics ||
    {};

  const triggerTrain = async () => {
    setTraining(true);
    setTrainSuccess(false);
    setTrainMsg("Entraînement en cours... (IF + OCSVM + Autoencoder)");

    try {
      const r: TrainResponse = await mlAPI.trainSync();

      const deployed = !!r?.deployed;
      const rollbackReason =
        r?.steps?.["5_rollback"]?.reason ||
        r?.message ||
        "Déploiement annulé car les performances sont insuffisantes";

      setTrainSuccess(deployed);
      setTrainMsg(
        deployed
          ? `Modèle ${r.version || "nouveau"} déployé avec succès`
          : `Rollback — ${rollbackReason}`
      );

      await load();
    } catch (e: any) {
      setTrainSuccess(false);
      setTrainMsg(`Erreur : ${e?.message || "échec de l'entraînement"}`);
    } finally {
      setTraining(false);
    }
  };

  const handleRollback = async () => {
    try {
      setActionLoading(true);
      await mlAPI.rollback();
      setTrainMsg("Rollback effectué avec succès");
      setTrainSuccess(true);
      await load();
    } catch (e: any) {
      setTrainMsg(`Erreur rollback : ${e?.message || "action impossible"}`);
      setTrainSuccess(false);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeploy = (version: string) => {
    if (!version) return;
    setDeployTarget(version);
    setShowDeploy(true);
  };

  const confirmDeploy = async () => {
    if (!deployTarget) return;

    try {
      setActionLoading(true);
      await mlAPI.deployVersion(deployTarget);
      setTrainMsg(`Version ${shortVersion(deployTarget)} déployée avec succès`);
      setTrainSuccess(true);
      await load();
    } catch (e: any) {
      setTrainMsg(`Erreur déploiement : ${e?.message || "action impossible"}`);
      setTrainSuccess(false);
    } finally {
      setShowDeploy(false);
      setDeployTarget(null);
      setActionLoading(false);
    }
  };

  const chartData = [...versions]
    .reverse()
    .slice(-8)
    .map((v) => ({
      ver: shortVersion(v.version, 6),
      f1: parseFloat(safeNumber(v.metrics?.f1_mean).toFixed(3)),
      recall: parseFloat(safeNumber(v.metrics?.recall_mean).toFixed(3)),
      fpr: parseFloat(safeNumber(v.metrics?.fpr_mean).toFixed(3)),
    }));

  const models = [
    {
      name: "Isolation Forest",
      key: "if_model",
      version: shortVersion(activeVersionString, 4),
      precision: safeNumber(activeMetrics?.precision_mean, 0.76),
      isActive: !!status?.if_model,
    },
    {
      name: "One-Class SVM",
      key: "ocsvm_model",
      version: shortVersion(activeVersionString, 4),
      precision: safeNumber(activeMetrics?.precision_mean, 0.7),
      isActive: !!status?.ocsvm_model,
    },
    {
      name: "Autoencoder",
      key: "ae_model",
      version: shortVersion(activeVersionString, 4),
      precision: safeNumber(activeMetrics?.precision_mean, 0.73),
      isActive: !!status?.ae_model,
    },
  ];

  const deployedVersion = versions.find((v) => v.version === deployTarget);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold">ML Models</h1>
          <p className="text-sm text-muted-foreground">
            M2 / M10 · Isolation Forest · One-Class SVM · Autoencoder · Boucle adaptative
          </p>
        </div>

        <Button
          className="gap-2 bg-violet-600 hover:bg-violet-700"
          onClick={triggerTrain}
          disabled={training || actionLoading}
        >
          {training ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              Entraînement...
            </>
          ) : (
            <>
              <BrainCircuit size={16} />
              Lancer ré-entraînement M10
            </>
          )}
        </Button>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-violet-500/10">
              <Database size={18} className="text-violet-400" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Versions</p>
              <p className="text-xl font-bold">{versions.length}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10">
              <CheckCircle2 size={18} className="text-green-400" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Version active</p>
              <p className="text-sm font-bold font-mono">{shortVersion(activeVersionString)}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10">
              <Activity size={18} className="text-blue-400" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">F1 actif</p>
              <p className="text-xl font-bold">{pct(activeMetrics?.f1_mean)}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/10">
              <Clock size={18} className="text-amber-400" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">FPR actif</p>
              <p className="text-xl font-bold">{pct(activeMetrics?.fpr_mean, 1)}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* H3 banner */}
      {h3 && (
        <Card
          className={cn(
            "border",
            h3.h3_validated
              ? "border-green-500/40 bg-green-500/5"
              : "border-amber-500/40 bg-amber-500/5"
          )}
        >
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <span className="text-lg">{h3.h3_validated ? "✓" : "⏳"}</span>
              <div>
                <p
                  className={cn(
                    "text-sm font-medium",
                    h3.h3_validated ? "text-green-400" : "text-amber-400"
                  )}
                >
                  H3 — ΔF1 ≥ +0.10 après 4 semaines
                  {h3.h3_validated ? " — VALIDÉE" : " — En cours"}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {h3.delta_f1 !== undefined
                    ? `ΔF1 = ${h3.delta_f1 >= 0 ? "+" : ""}${h3.delta_f1} · v0: ${
                        h3.f1_v0 ?? "—"
                      } → vN: ${h3.f1_vN ?? "—"} · Cible : +0.10`
                    : h3.message || "Pas assez de versions pour calculer ΔF1"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Message action */}
      {trainMsg && (
        <Card
          className={cn(
            "border",
            trainSuccess
              ? "border-green-500/30 bg-green-500/8"
              : "border-amber-500/30 bg-amber-500/8"
          )}
        >
          <CardContent className="p-3">
            <div className="flex items-center gap-2 text-sm">
              {trainSuccess ? (
                <CheckCircle2 size={14} className="text-green-400 shrink-0" />
              ) : (
                <AlertTriangle size={14} className="text-amber-400 shrink-0" />
              )}
              <span className={trainSuccess ? "text-green-400" : "text-amber-400"}>
                {trainMsg}
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Model cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {models.map((m) => (
          <ModelCard
            key={m.key}
            name={m.name}
            version={m.version}
            f1={safeNumber(activeMetrics?.f1_mean, 0.74)}
            recall={safeNumber(activeMetrics?.recall_mean, 0.72)}
            precision={m.precision}
            fpr={safeNumber(activeMetrics?.fpr_mean, 0.08)}
            isAvailable={!!status?.models_loaded}
            isActive={m.isActive}
            onDeploy={() => handleDeploy(activeVersionString || "")}
            onRollback={handleRollback}
          />
        ))}
      </div>

      {/* Chart */}
      <Card className="bg-card/50 border-cyber-border">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <TrendingUp size={16} className="text-violet-400" />
            Évolution des performances
            <Badge variant="secondary" className="text-[10px] ml-auto">
              {chartData.length} versions
            </Badge>
          </CardTitle>
        </CardHeader>

        <CardContent>
          {chartData.length < 2 ? (
            <div className="h-64 flex items-center justify-center text-sm text-muted-foreground">
              {loading ? "Chargement..." : "Lance au moins 2 entraînements pour voir l'évolution"}
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E232C" />
                  <XAxis dataKey="ver" stroke="#4B5563" fontSize={10} />
                  <YAxis stroke="#4B5563" fontSize={10} domain={[0, 1]} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#161922",
                      border: "1px solid #1E232C",
                      borderRadius: "8px",
                    }}
                    formatter={(value: any) => `${(Number(value || 0) * 100).toFixed(1)}%`}
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="f1"
                    name="F1 Score"
                    stroke="#7F77DD"
                    strokeWidth={2}
                    dot={{ fill: "#7F77DD" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="recall"
                    name="Recall"
                    stroke="#22c55e"
                    strokeWidth={2}
                    dot={{ fill: "#22c55e" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="fpr"
                    name="FPR"
                    stroke="#ef4444"
                    strokeWidth={2}
                    dot={{ fill: "#ef4444" }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      {/* History */}
      <Card className="bg-card/50 border-cyber-border">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <TrendingUp size={16} className="text-violet-400" />
            Historique des versions
            <Badge variant="secondary" className="text-[10px] ml-auto">
              {versions.length} version{versions.length !== 1 ? "s" : ""}
            </Badge>
          </CardTitle>
        </CardHeader>

        <CardContent>
          {versions.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">
              {loading ? "Chargement..." : "Aucun modèle — lance un entraînement ci-dessus"}
            </div>
          ) : (
            <div className="space-y-2">
              {[...versions].reverse().map((v) => (
                <div
                  key={v.version}
                  className={cn(
                    "flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 p-3 rounded-lg transition-colors",
                    v.is_active
                      ? "bg-violet-500/10 border border-violet-500/30"
                      : "bg-card/80 hover:bg-card border border-transparent"
                  )}
                >
                  <div className="flex items-center gap-4 flex-wrap">
                    <span
                      className={cn(
                        "font-mono font-bold text-sm",
                        v.is_active ? "text-violet-400" : "text-muted-foreground"
                      )}
                    >
                      {shortVersion(v.version)}
                    </span>

                    {v.is_active && (
                      <Badge
                        variant="secondary"
                        className="bg-violet-500/15 text-violet-400 text-[10px]"
                      >
                        ● Actif
                      </Badge>
                    )}

                    {v.metrics?.h1_validated && (
                      <Badge
                        variant="secondary"
                        className="bg-green-500/10 text-green-400 text-[10px]"
                      >
                        H1 ✓
                      </Badge>
                    )}

                    <span className="text-xs text-muted-foreground">
                      {v.created_at
                        ? new Date(v.created_at).toLocaleDateString("fr-FR")
                        : "—"}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-sm flex-wrap">
                    <span className={cn("font-mono", metricColor("f1", v.metrics?.f1_mean))}>
                      F1: {pct(v.metrics?.f1_mean)}
                    </span>
                    <span
                      className={cn(
                        "font-mono",
                        metricColor("recall", v.metrics?.recall_mean)
                      )}
                    >
                      Recall: {pct(v.metrics?.recall_mean)}
                    </span>
                    <span className={cn("font-mono", metricColor("fpr", v.metrics?.fpr_mean))}>
                      FPR: {pct(v.metrics?.fpr_mean, 1)}
                    </span>

                    {!v.is_active && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => handleDeploy(v.version)}
                        disabled={actionLoading}
                      >
                        <Play size={11} className="mr-1" />
                        Déployer
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Modal custom de déploiement */}
      {showDeploy && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,.55)",
            zIndex: 60,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "24px",
          }}
          onClick={() => setShowDeploy(false)}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "520px",
              background: "var(--cs-surface)",
              border: "1px solid var(--cs-border)",
              borderRadius: "16px",
              padding: "20px",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3 mb-4">
              <div>
                <h3 className="text-lg font-semibold">Confirmer le déploiement</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Déployer la version active sélectionnée comme modèle de production.
                </p>
              </div>

              <button
                onClick={() => setShowDeploy(false)}
                style={{
                  border: "none",
                  background: "transparent",
                  color: "var(--cs-text2)",
                  cursor: "pointer",
                }}
              >
                <X size={18} />
              </button>
            </div>

            <p className="text-sm text-muted-foreground mb-4">
              Déployer la version{" "}
              <code className="font-mono text-violet-400 bg-violet-500/10 px-1 rounded">
                {shortVersion(deployTarget)}
              </code>{" "}
              comme modèle actif ?
            </p>

            {deployedVersion ? (
              <div className="p-4 rounded-lg bg-card/80 border border-cyber-border grid grid-cols-3 gap-4 text-sm mb-4">
                <div>
                  <span className="text-muted-foreground text-xs block">F1 Score</span>
                  <span className="font-mono text-violet-400">
                    {pct(deployedVersion.metrics?.f1_mean, 1)}
                  </span>
                </div>

                <div>
                  <span className="text-muted-foreground text-xs block">Recall</span>
                  <span className="font-mono text-green-400">
                    {pct(deployedVersion.metrics?.recall_mean, 1)}
                  </span>
                </div>

                <div>
                  <span className="text-muted-foreground text-xs block">FPR</span>
                  <span className="font-mono text-orange-400">
                    {pct(deployedVersion.metrics?.fpr_mean, 1)}
                  </span>
                </div>
              </div>
            ) : null}

            <div className="flex gap-2">
              <Button
                variant="outline"
                className="flex-1"
                onClick={() => setShowDeploy(false)}
                disabled={actionLoading}
              >
                Annuler
              </Button>

              <Button
                className="flex-1 bg-green-600 hover:bg-green-700"
                onClick={confirmDeploy}
                disabled={actionLoading}
              >
                {actionLoading ? (
                  <>
                    <Loader2 size={16} className="mr-2 animate-spin" />
                    Déploiement...
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={16} className="mr-2" />
                    Déployer
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default MLModels;