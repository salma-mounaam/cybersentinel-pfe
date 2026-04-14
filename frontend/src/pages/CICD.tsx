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

function PipelineCard({ pipeline }: { pipeline: any }) {
  const decision = (pipeline.decision || "PENDING").toUpperCase();
  const config = statusConfig[decision as keyof typeof statusConfig] || statusConfig.PENDING;
  const StatusIcon = config.icon;

  return (
    <Card className="bg-card/50 border-cyber-border hover:border-cyber-violet/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={cn("p-2 rounded-lg", config.bg)}>
              <StatusIcon
                size={18}
                className={cn(config.color, decision === "RUNNING" && "animate-spin")}
              />
            </div>
            <div>
              <h4 className="font-medium text-sm">{pipeline.run_id || "—"}</h4>
              <p className="text-xs text-muted-foreground flex items-center gap-1">
                <GitBranch size={12} />
                {pipeline.repo || "—"}
              </p>
            </div>
          </div>

          <div className="text-right">
            <Badge variant="secondary" className={cn(config.bg, config.color)}>
              {config.label}
            </Badge>
            {decision === "BLOCK" && (
              <Badge variant="secondary" className="bg-cyber-red/10 text-cyber-red ml-2">
                <AlertTriangle size={10} className="mr-1" />
                PR Bloquée
              </Badge>
            )}
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3 mb-4">
          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-lg font-bold font-mono text-cyber-red">
              {pipeline.critical_count || 0}
            </p>
            <p className="text-[10px] text-muted-foreground">Critiques</p>
          </div>
          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-lg font-bold font-mono text-cyber-orange">
              {pipeline.high_count || 0}
            </p>
            <p className="text-[10px] text-muted-foreground">Élevées</p>
          </div>
          <div className="p-3 rounded-lg bg-cyber-panel/40 text-center">
            <p className="text-lg font-bold font-mono">{pipeline.source || "manual"}</p>
            <p className="text-[10px] text-muted-foreground">Source</p>
          </div>
        </div>

        <div className="flex items-center justify-between mt-4 pt-3 border-t border-border/50 text-xs text-muted-foreground">
          <div className="flex items-center gap-3">
            {pipeline.pr_number && (
              <span className="flex items-center gap-1">
                <GitPullRequest size={12} />
                PR #{pipeline.pr_number}
              </span>
            )}
            <span className="flex items-center gap-1">
              <Clock size={12} />
              {pipeline.timestamp ? new Date(pipeline.timestamp).toLocaleString("fr-FR") : "—"}
            </span>
          </div>
          <span>{pipeline.commit_sha?.slice(0, 7) || "—"}</span>
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
        <Button onClick={() => loadRuns(true)} className="gap-2 bg-cyber-violet hover:bg-cyber-violet-dark">
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
            <p className="text-2xl font-bold font-mono text-cyber-red">{stats?.blocked || 0}</p>
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
          className={`px-3 py-2 rounded text-sm border ${activeTab === "all" ? "bg-cyber-panel border-cyber-violet" : "border-cyber-border"}`}
        >
          Tous
        </button>
        <button
          onClick={() => setActiveTab("blocked")}
          className={`px-3 py-2 rounded text-sm border ${activeTab === "blocked" ? "bg-cyber-panel border-cyber-violet" : "border-cyber-border"}`}
        >
          Bloqués
        </button>
        <button
          onClick={() => setActiveTab("success")}
          className={`px-3 py-2 rounded text-sm border ${activeTab === "success" ? "bg-cyber-panel border-cyber-violet" : "border-cyber-border"}`}
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