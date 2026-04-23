import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import {
  GitBranch,
  Play,
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  AlertTriangle,
  GitPullRequest,
  FileCode,
  Shield,
  KeyRound,
  Hash,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { cn } from "../lib/utils";
import { cicdAPI } from "../services/api";

const statusConfig = {
  PASS: {
    icon: CheckCircle2,
    color: "text-cyber-green",
    bg: "bg-cyber-green/10",
    label: "Succès",
  },
  BLOCK: {
    icon: XCircle,
    color: "text-cyber-red",
    bg: "bg-cyber-red/10",
    label: "Bloqué",
  },
  RUNNING: {
    icon: Loader2,
    color: "text-cyber-violet",
    bg: "bg-cyber-violet/10",
    label: "En cours",
  },
  PENDING: {
    icon: Clock,
    color: "text-muted-foreground",
    bg: "bg-muted/20",
    label: "En attente",
  },
};

function formatDate(value?: string) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return value;
  }
}

function shortSha(sha?: string) {
  if (!sha) return "—";
  return sha.slice(0, 8);
}

function PipelineCard({ pipeline }: { pipeline: any }) {
  const decision = (pipeline.decision || "PENDING").toUpperCase();
  const config =
    statusConfig[decision as keyof typeof statusConfig] || statusConfig.PENDING;

  const StatusIcon = config.icon;

  const critical = Number(pipeline.critical_count || 0);
  const high = Number(pipeline.high_count || 0);
  const medium = Number(pipeline.medium_count || 0);
  const low = Number(pipeline.low_count || 0);
  const secretsFound = !!pipeline.secrets_found;

  return (
    <Card className="bg-card/50 border-cyber-border hover:border-cyber-violet/30 transition-colors">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4 mb-5">
          <div className="flex items-start gap-3">
            <div className={cn("p-2 rounded-lg mt-0.5", config.bg)}>
              <StatusIcon
                size={18}
                className={cn(config.color, decision === "RUNNING" && "animate-spin")}
              />
            </div>

            <div>
              <h4 className="font-semibold text-base">
                {pipeline.run_id || "Pipeline"}
              </h4>

              <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <GitBranch size={12} />
                  {pipeline.repo || "—"}
                </span>

                <span className="flex items-center gap-1">
                  <Hash size={12} />
                  {pipeline.branch || "—"}
                </span>

                {pipeline.pr_number && (
                  <span className="flex items-center gap-1">
                    <GitPullRequest size={12} />
                    PR #{pipeline.pr_number}
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-2">
            <Badge variant="secondary" className={cn(config.bg, config.color)}>
              {config.label}
            </Badge>

            {decision === "BLOCK" && (
              <Badge variant="secondary" className="bg-cyber-red/10 text-cyber-red">
                <AlertTriangle size={10} className="mr-1" />
                PR Bloquée
              </Badge>
            )}

            {secretsFound && (
              <Badge variant="secondary" className="bg-cyber-orange/10 text-cyber-orange">
                <KeyRound size={10} className="mr-1" />
                Secret détecté
              </Badge>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-5">
          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-lg font-bold font-mono text-cyber-red">{critical}</p>
            <p className="text-[10px] text-muted-foreground">Critiques</p>
          </div>

          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-lg font-bold font-mono text-cyber-orange">{high}</p>
            <p className="text-[10px] text-muted-foreground">Élevées</p>
          </div>

          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-lg font-bold font-mono text-cyber-blue">{medium}</p>
            <p className="text-[10px] text-muted-foreground">Moyennes</p>
          </div>

          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-lg font-bold font-mono text-cyber-green">{low}</p>
            <p className="text-[10px] text-muted-foreground">Faibles</p>
          </div>

          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-sm font-bold font-mono">{pipeline.source || "manual"}</p>
            <p className="text-[10px] text-muted-foreground">Source</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          <div className="rounded-lg border border-cyber-border bg-cyber-panel/20 p-3">
            <p className="text-[11px] text-muted-foreground mb-1">Commit SHA</p>
            <p className="font-mono text-sm">{shortSha(pipeline.commit_sha)}</p>
          </div>

          <div className="rounded-lg border border-cyber-border bg-cyber-panel/20 p-3">
            <p className="text-[11px] text-muted-foreground mb-1">Date</p>
            <p className="text-sm">
              {formatDate(pipeline.timestamp || pipeline.created_at)}
            </p>
          </div>
        </div>

        {(pipeline.message || pipeline.reason || pipeline.summary) && (
          <div className="rounded-lg border border-cyber-border bg-cyber-panel/20 p-3 mb-4">
            <p className="text-[11px] text-muted-foreground mb-1">Détail</p>
            <p className="text-sm text-foreground">
              {pipeline.message || pipeline.reason || pipeline.summary}
            </p>
          </div>
        )}

        <div className="flex items-center justify-between pt-3 border-t border-border/50 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield size={12} />
            Quality Gate:
            <span className={decision === "BLOCK" ? "text-cyber-red" : "text-cyber-green"}>
              {decision === "BLOCK" ? " Échec" : " Validé"}
            </span>
          </div>

          <div>
            {critical > 0 || high > 0 || secretsFound
              ? "Action requise"
              : "Aucune action critique"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function CICD() {
  const location = useLocation();

  const [pipelines, setPipelines] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("all");
  const [loading, setLoading] = useState(true);

  const loadRuns = async (showLoader = true) => {
    if (showLoader) setLoading(true);

    try {
      const res = await cicdAPI.getRuns();
      setStats(res);
      setPipelines(Array.isArray(res?.runs) ? res.runs : []);
    } catch (e) {
      console.error("CICD load error:", e);
      setPipelines([]);
    } finally {
      if (showLoader) setLoading(false);
    }
  };

  useEffect(() => {
    loadRuns(true);
  }, []);

  useEffect(() => {
    loadRuns(false);
  }, [location.key]);

  useEffect(() => {
    const interval = setInterval(() => {
      loadRuns(false);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const filteredPipelines = useMemo(() => {
    return pipelines.filter((p) => {
      const decision = (p.decision || "").toUpperCase();
      if (activeTab === "all") return true;
      if (activeTab === "blocked") return decision === "BLOCK";
      if (activeTab === "success") return decision === "PASS";
      return true;
    });
  }, [pipelines, activeTab]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">CI/CD</h1>
          <p className="text-sm text-muted-foreground">
            GitHub Actions — Workflows de sécurité Shift-Left
          </p>
        </div>

        <Button
          onClick={() => loadRuns(true)}
          className="gap-2 bg-cyber-violet hover:bg-cyber-violet-dark"
        >
          {loading ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
          Rafraîchir
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono">{stats?.total || 0}</p>
            <p className="text-xs text-muted-foreground">Total</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-green">
              {pipelines.filter((p) => (p.decision || "").toUpperCase() === "PASS").length}
            </p>
            <p className="text-xs text-muted-foreground">Succès</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-red">
              {stats?.blocked || 0}
            </p>
            <p className="text-xs text-muted-foreground">Bloqués</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-violet">
              {pipelines.filter((p) => (p.decision || "").toUpperCase() === "RUNNING").length}
            </p>
            <p className="text-xs text-muted-foreground">En cours</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-orange">
              {stats?.block_rate || 0}%
            </p>
            <p className="text-xs text-muted-foreground">Block rate</p>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card/50 border-cyber-border">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <FileCode size={16} className="text-cyber-violet" />
            Quality Gates
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-cyber-darker border border-cyber-border">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">SAST Gate</span>
                <CheckCircle2 size={16} className="text-cyber-green" />
              </div>
              <p className="text-xs text-muted-foreground">
                Blocage si vulnérabilités critiques détectées
              </p>
            </div>

            <div className="p-4 rounded-lg bg-cyber-darker border border-cyber-border">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">DAST Gate</span>
                <CheckCircle2 size={16} className="text-cyber-green" />
              </div>
              <p className="text-xs text-muted-foreground">
                Scan dynamique avant déploiement
              </p>
            </div>

            <div className="p-4 rounded-lg bg-cyber-darker border border-cyber-border">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">ML Quality Gate</span>
                <CheckCircle2 size={16} className="text-cyber-green" />
              </div>
              <p className="text-xs text-muted-foreground">
                Validation des critères avant promotion
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex gap-2">
        <button
          onClick={() => setActiveTab("all")}
          className={`px-3 py-2 rounded text-sm border ${
            activeTab === "all" ? "bg-cyber-panel border-cyber-violet" : "border-cyber-border"
          }`}
        >
          Tous
        </button>
        <button
          onClick={() => setActiveTab("blocked")}
          className={`px-3 py-2 rounded text-sm border ${
            activeTab === "blocked"
              ? "bg-cyber-panel border-cyber-violet"
              : "border-cyber-border"
          }`}
        >
          Bloqués
        </button>
        <button
          onClick={() => setActiveTab("success")}
          className={`px-3 py-2 rounded text-sm border ${
            activeTab === "success"
              ? "bg-cyber-panel border-cyber-violet"
              : "border-cyber-border"
          }`}
        >
          Succès
        </button>
      </div>

      <div className="space-y-4">
        {filteredPipelines.length === 0 ? (
          <Card className="bg-card/50 border-cyber-border">
            <CardContent className="p-8 text-center text-sm text-muted-foreground">
              Aucun résultat CI/CD trouvé pour le moment.
            </CardContent>
          </Card>
        ) : (
          filteredPipelines.map((pipeline) => (
            <PipelineCard key={pipeline.run_id} pipeline={pipeline} />
          ))
        )}
      </div>
    </div>
  );
}