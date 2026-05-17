// ============================================================
// pages/SASTScanner.tsx
// FIX : priorité au scanId transmis depuis ScanResults
//   → location.state?.scanId utilisé en premier
//   → getLatestScan() uniquement si accès direct à la page
//   → affiche toujours les findings du bon scan
// ============================================================
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { SevBadge } from "../components/common";
import {
  Play,
  GitCommit,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Download,
  Filter,
  Search,
  BrainCircuit,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { cn } from "../lib/utils";
import { sastAPI, vulnerabilityLLMAPI } from "../services/api";

const scannerIcons = {
  semgrep:  <FileCode size={16} />,
  trivy:    <AlertTriangle size={16} />,
  gitleaks: <GitCommit size={16} />,
};

const scannerColors = {
  semgrep:  "text-cyber-violet",
  trivy:    "text-cyber-blue",
  gitleaks: "text-cyber-orange",
};

function normalizeSeverity(sev?: string) {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "critique")          return "critical";
  if (s === "high"     || s === "eleve" || s === "élevé") return "high";
  if (s === "medium"   || s === "moyen")             return "medium";
  return "low";
}


function LLMExplanationPanel({
  explanation,
  loading,
  onClose,
}: {
  explanation: any | null;
  loading: boolean;
  onClose: () => void;
}) {
  if (!loading && !explanation) return null;

  return (
    <Card className="bg-purple-500/5 border-purple-500/25">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-3">
          <CardTitle className="text-sm flex items-center gap-2 text-purple-300">
            <BrainCircuit size={15} />
            Explication LLM
          </CardTitle>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 px-2">
            <X size={14} />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground py-3">
            <Loader2 size={15} className="animate-spin" />
            Génération de l'explication...
          </div>
        ) : (
          <div className="space-y-3 text-sm">
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Résumé</p>
              <p className="mt-1">{explanation?.resume_simple || "—"}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Description technique</p>
              <p className="mt-1 text-muted-foreground">{explanation?.description_technique || "—"}</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="rounded-lg border border-cyber-border bg-card/40 p-3">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Impact</p>
                <p className="mt-1 text-muted-foreground">{explanation?.impact || "—"}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-card/40 p-3">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Cause probable</p>
                <p className="mt-1 text-muted-foreground">{explanation?.cause_probable || "—"}</p>
              </div>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Correction recommandée</p>
              <p className="mt-1 text-muted-foreground">{explanation?.correction_recommandee || "—"}</p>
            </div>
            {explanation?.exemple_correction && (
              <pre className="rounded-lg bg-cyber-darker p-3 text-xs overflow-auto text-muted-foreground whitespace-pre-wrap">
                {explanation.exemple_correction}
              </pre>
            )}
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="rounded-full border border-purple-500/30 bg-purple-500/10 px-2 py-1 text-purple-300">
                Risque : {explanation?.niveau_risque || "—"}
              </span>
              <span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-2 py-1 text-blue-300">
                Priorité : {explanation?.priorite_correction || "—"}
              </span>
              <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-amber-300">
                Faux positif : {explanation?.faux_positif_possible ? "possible" : "peu probable"}
              </span>
            </div>
            {explanation?.raison_faux_positif && (
              <p className="text-xs text-muted-foreground">{explanation.raison_faux_positif}</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FindingRow({ finding, onExplain }: { finding: any; onExplain: (finding: any) => void }) {
  const severity = normalizeSeverity(finding.severity);

  return (
    <div className={cn(
      "p-3 rounded-lg border transition-all duration-200 hover:bg-cyber-panel/50",
      severity === "critical" && "bg-cyber-red/5 border-cyber-red/20",
      severity === "high"     && "bg-cyber-orange/5 border-cyber-orange/20",
      severity !== "critical" && severity !== "high" && "bg-card/30 border-border/50"
    )}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <SevBadge sev={severity?.toUpperCase()} />
            {finding.technique_id && (
              <span style={{
                fontSize: "10px", padding: "2px 8px", borderRadius: "999px",
                border: "0.5px solid rgba(59,130,246,.35)", background: "rgba(59,130,246,.10)",
                color: "var(--cs-blue)", fontFamily: "monospace",
              }}>
                {finding.technique_id}
              </span>
            )}
            {finding.cwe && (
              <span className="text-xs font-mono text-muted-foreground">{finding.cwe}</span>
            )}
            {finding.tool && (
              <Badge variant="secondary" className="text-[10px]">{finding.tool}</Badge>
            )}
          </div>

          <p className="text-sm font-medium">{finding.message || finding.title || "Finding"}</p>

          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
            <span className="flex items-center gap-1">
              <FileCode size={12} />
              {finding.file_path || finding.file || "—"}
              {finding.line_number ? `:${finding.line_number}` : ""}
              {finding.col_start  ? `:${finding.col_start}`  : ""}
            </span>
            {(finding.rule_id || finding.ruleId) && (
              <span className="font-mono">{finding.rule_id || finding.ruleId}</span>
            )}
            {finding.scan_id && (
              <span className="font-mono text-[10px] opacity-70">scan: {finding.scan_id.slice(0, 8)}</span>
            )}
          </div>
        </div>

        <Button variant="ghost" size="sm" onClick={() => onExplain(finding)} className="shrink-0 gap-1"><BrainCircuit size={13} />Expliquer</Button>
      </div>
    </div>
  );
}

function ResultCard({ tool, count, icon, color }: {
  tool: string; count: number; icon: React.ReactNode; color: string;
}) {
  return (
    <Card className="bg-card/50 border-cyber-border">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={cn("p-2 rounded-lg bg-muted/30", color)}>{icon}</div>
            <div>
              <h4 className="font-medium capitalize">{tool}</h4>
              <p className="text-xs text-muted-foreground">Analyse statique</p>
            </div>
          </div>
          <Badge variant="secondary" className="bg-cyber-green/10 text-cyber-green">
            <CheckCircle2 size={12} className="mr-1" />
            Disponible
          </Badge>
        </div>
        <div className="text-center p-4 rounded bg-cyber-panel/40">
          <p className="text-3xl font-bold font-mono">{count}</p>
          <p className="text-xs text-muted-foreground mt-1">Findings</p>
        </div>
      </CardContent>
    </Card>
  );
}

export default function SASTScanner() {
  const navigate = useNavigate();
  const location = useLocation();

  const [searchQuery, setSearchQuery] = useState("");
  const [loading,     setLoading]     = useState(true);
  const [stats,       setStats]       = useState<any>(null);
  const [data,        setData]        = useState<any[]>([]);
  const [scanId,      setScanId]      = useState<string | null>(null);

  const [llmLoading, setLlmLoading] = useState(false);
  const [llmExplanation, setLlmExplanation] = useState<any | null>(null);
  const [llmError, setLlmError] = useState("");

  const loadData = async () => {
    setLoading(true);
    try {
      // ── Priorité 1 : scanId transmis depuis ScanResults ──
      // Quand l'utilisateur clique "SAST complet" ou "Voir tous les findings"
      // depuis ScanResults, le scan_id du scan courant est passé dans le state
      // → on affiche exactement les findings de CE scan
      //
      // ── Priorité 2 : getLatestScan() ─────────────────────
      // Accès direct à /sast (menu latéral) sans scan_id dans le state
      // → on affiche le dernier scan disponible en base
      const stateId = (location.state as any)?.scanId || null;

      let currentScanId: string | null = stateId;

      if (!currentScanId) {
        const latest = await sastAPI.getLatestScan();
        currentScanId = latest?.scan_id || null;
      }

      setScanId(currentScanId);

      const [statsRes, findingsRes] = await Promise.all([
        sastAPI.getStats(currentScanId ? { scan_id: currentScanId } : {}),
        sastAPI.getFindings(currentScanId ? { limit: 200, scan_id: currentScanId } : { limit: 200 }),
      ]);

      setStats(statsRes);
      setData(findingsRes.findings || []);
    } catch (e) {
      console.error("SAST load error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  // location.state en dépendance : rechargement si on navigue avec un nouveau scanId
  }, [location.state]);

  const handleLaunchScan = () => navigate("/scan-code");

  const explainFinding = async (finding: any) => {
    setLlmLoading(true);
    setLlmExplanation(null);
    setLlmError("");
    try {
      const result = await vulnerabilityLLMAPI.explain("sast", finding);
      setLlmExplanation(result.explanation);
    } catch (e: any) {
      setLlmError(e?.message || "Erreur LLM");
      setLlmExplanation({
        resume_simple: "Impossible de générer l'explication LLM.",
        description_technique: "Le service LLM est indisponible ou la réponse n'est pas exploitable.",
        impact: "Non disponible.",
        cause_probable: "Non disponible.",
        correction_recommandee: "Vérifier Ollama, le backend et l'endpoint /api/vulnerabilities/llm/explain.",
        exemple_correction: "ollama run llama3.1:8b",
        niveau_risque: finding?.severity || "INFO",
        priorite_correction: "P4",
        faux_positif_possible: true,
        raison_faux_positif: e?.message || "Analyse LLM non disponible.",
      });
    } finally {
      setLlmLoading(false);
    }
  };

  const filteredFindings = useMemo(() => {
    const text = searchQuery.toLowerCase();
    return data.filter((f) =>
      (f.message    || f.title   || "").toLowerCase().includes(text) ||
      (f.file_path  || f.file    || "").toLowerCase().includes(text) ||
      (f.rule_id    || "").toLowerCase().includes(text) ||
      (f.cwe        || "").toLowerCase().includes(text)
    );
  }, [data, searchQuery]);

  const byTool     = stats?.by_tool     || {};
  const bySeverity = stats?.by_severity || {};

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">SAST Scanner</h1>
          <p className="text-sm text-muted-foreground">
            Semgrep + Trivy + Gitleaks — Analyse statique de code
          </p>
          {scanId && (
            <p className="text-xs text-muted-foreground mt-1 font-mono">
              {/* Indique si le scan vient de ScanResults ou du dernier en base */}
              {(location.state as any)?.scanId
                ? "Scan sélectionné : "
                : "Dernier scan : "
              }
              {scanId}
            </p>
          )}
        </div>
        <Button onClick={handleLaunchScan} className="gap-2 bg-cyber-violet hover:bg-cyber-violet-dark">
          <Play size={16} />
          Lancer un scan
        </Button>
      </div>

      {loading && (
        <Card className="bg-card/50 border-cyber-violet/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-sm">
              <Loader2 size={16} className="animate-spin" />
              Chargement...
            </div>
          </CardContent>
        </Card>
      )}

      {/* Cartes par outil */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <ResultCard tool="semgrep"  count={byTool.semgrep  || 0} icon={scannerIcons.semgrep}  color={scannerColors.semgrep}  />
        <ResultCard tool="trivy"    count={byTool.trivy    || 0} icon={scannerIcons.trivy}    color={scannerColors.trivy}    />
        <ResultCard tool="gitleaks" count={byTool.gitleaks || 0} icon={scannerIcons.gitleaks} color={scannerColors.gitleaks} />
      </div>

      {/* Compteurs sévérité */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-red">{bySeverity.CRITICAL || 0}</p>
            <p className="text-xs text-muted-foreground">Critiques</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-orange">{bySeverity.HIGH || 0}</p>
            <p className="text-xs text-muted-foreground">Élevées</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-blue">{bySeverity.MEDIUM || 0}</p>
            <p className="text-xs text-muted-foreground">Moyennes</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-cyber-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold font-mono text-cyber-green">{bySeverity.LOW || 0}</p>
            <p className="text-xs text-muted-foreground">Faibles</p>
          </CardContent>
        </Card>
      </div>

      {llmError && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/8 p-3 text-sm text-red-300">
          {llmError}
        </div>
      )}

      <LLMExplanationPanel
        explanation={llmExplanation}
        loading={llmLoading}
        onClose={() => { setLlmExplanation(null); setLlmError(""); }}
      />

      {/* Liste findings */}
      <Card className="bg-card/50 border-cyber-border">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                placeholder="Rechercher une vulnérabilité..."
                value={searchQuery}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-3 py-2 rounded-md bg-cyber-panel border border-cyber-border text-sm outline-none"
              />
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" className="gap-2"><Filter size={14} />Filtrer</Button>
              <Button variant="outline" size="sm" className="gap-2"><Download size={14} />Export</Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="max-h-96 overflow-auto">
            <div className="space-y-2">
              {filteredFindings.map((finding, index) => (
                <FindingRow key={finding.id || index} finding={finding} onExplain={explainFinding} />
              ))}
              {!loading && filteredFindings.length === 0 && (
                <div className="text-sm text-muted-foreground py-6 text-center">
                  Aucun finding pour ce scan.
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* SARIF Viewer */}
      <Card className="bg-card/50 border-cyber-border">
        <CardHeader>
          <CardTitle className="text-sm">SARIF Viewer</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-cyber-darker rounded-lg p-4 font-mono text-xs overflow-auto">
            <pre className="text-muted-foreground">
              {JSON.stringify({
                scan_id:        scanId,
                total:          stats?.total       || 0,
                by_tool:        stats?.by_tool     || {},
                by_severity:    stats?.by_severity || {},
                sample_results: filteredFindings.slice(0, 5),
              }, null, 2)}
            </pre>
          </div>
        </CardContent>
      </Card>

    </div>
  );
}