// ============================================================
// pages/DASTSandbox.tsx — Style plateforme de prod
// Dashboard sessions · Lancement rapide · Findings
// M5 · OWASP ZAP · sandbox-net internal:true
// FIX v12.1 : Ajout support builds Docker désactivés + logs
// ============================================================
import React, { useState, useEffect, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Play, RefreshCw, ShieldCheck, ShieldAlert,
  Clock, Bug, Target, ExternalLink, ChevronDown,
  AlertTriangle, CheckCircle, XCircle, Loader2,
  GitBranch, Upload, Container, Zap, FileText, Terminal,
  BrainCircuit, X,
} from "lucide-react";
import { dastAPI, vulnerabilityLLMAPI } from "../services/api";
import { cn } from "../lib/utils";

// ── Helpers ───────────────────────────────────────────────────

function safeStr(v: any): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

function safePcapName(pcap_path: any): string {
  const s = safeStr(pcap_path);
  if (s === "—") return "—";
  return s.split("/").pop() || s;
}

function timeAgo(iso: string): string {
  if (!iso) return "—";
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60)   return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}min`;
  return `${Math.floor(diff / 3600)}h`;
}

const RISK_COLOR: Record<string, string> = {
  High:          "text-red-400 bg-red-500/10 border-red-500/30",
  Medium:        "text-amber-400 bg-amber-500/10 border-amber-500/30",
  Low:           "text-blue-400 bg-blue-500/10 border-blue-500/30",
  Informational: "text-gray-400 bg-gray-500/10 border-gray-500/30",
};

async function uploadAndScanDast(file: File): Promise<any> {
  const formData = new FormData();
  formData.append("file", file);
  const apiBase =
    process.env.REACT_APP_API_URL?.replace(/\/$/, "") || "http://localhost:8000/api";
  const res = await fetch(`${apiBase}/dast/start/from-upload`, {
    method: "POST", body: formData,
  });
  let payload: any = null;
  try { payload = await res.json(); } catch { payload = null; }
  if (!res.ok) {
    const msg = payload?.detail || payload?.error || `Erreur HTTP ${res.status}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return payload;
}

// ── Types ─────────────────────────────────────────────────────

interface SessionRow {
  session_id: string;
  target_url: string;
  total_vulns: number;
  started_at?: string;
  finished_at?: string;
  error?: string;
  phases?: Record<string, any>;
  git_project?: any;
  uploaded_project?: any;
  docker_image_scan?: any;
  build_logs?: string;
  container_logs?: string;
}

// ── Composant principal ───────────────────────────────────────

export default function DASTSandbox() {
  const location  = useLocation();
  const navigate  = useNavigate();
  const navState  = location.state as { dastResult?: any } | null;
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // ── État global ───────────────────────────────────────────
  const [zapStatus,  setZapStatus]  = useState<any>(null);
  const [isoCheck,   setIsoCheck]   = useState<any>(null);
  const [isoLoading, setIsoLoading] = useState(false);

  // ── Sessions (historique local) ───────────────────────────
  const [sessions,         setSessions]         = useState<SessionRow[]>([]);
  const [selectedSession,  setSelectedSession]  = useState<SessionRow | null>(null);
  const [sessionFindings,  setSessionFindings]  = useState<any[]>([]);
  const [findingsLoading,  setFindingsLoading]  = useState(false);
  const [showBuildLogs,    setShowBuildLogs]    = useState(false);
  const [showContainerLogs,setShowContainerLogs]= useState(false);

  // ── Lancement rapide ──────────────────────────────────────
  const [scanTarget,   setScanTarget]   = useState<"webgoat" | "dvwa" | "url" | "upload" | "git">("webgoat");
  const [customUrl,    setCustomUrl]    = useState("");
  const [gitUrl,       setGitUrl]       = useState("");
  const [gitBranch,    setGitBranch]    = useState("main");
  const [uploadFile,   setUploadFile]   = useState<File | null>(null);
  const [isDragging,   setIsDragging]   = useState(false);
  const [running,      setRunning]      = useState(false);
  const [runError,     setRunError]     = useState("");
  const [detailedError,setDetailedError] = useState("");

  const [llmLoading, setLlmLoading] = useState(false);
  const [llmExplanation, setLlmExplanation] = useState<any | null>(null);
  const [llmError, setLlmError] = useState("");

  // ── Init ──────────────────────────────────────────────────
  useEffect(() => {
    refreshStatus();
    loadHistory();
    // Si on arrive depuis CodeScan avec un résultat DAST
    if (navState?.dastResult) {
      addSession(navState.dastResult);
    }
  }, []);

  useEffect(() => {
    if (!zapStatus?.active) return;
    const id = setInterval(refreshStatus, 4000);
    return () => clearInterval(id);
  }, [zapStatus?.active]);

  const refreshStatus = async () => {
    try {
      const s = await dastAPI.getStatus();
      setZapStatus(s);
    } catch {}
  };

  const loadHistory = async () => {
    try {
      const h = await dastAPI.getFindingsHistory(200);
      // Regrouper par session_id
      const map: Record<string, SessionRow> = {};
      for (const f of (h.findings || [])) {
        const sid = f.session_id || "unknown";
        if (!map[sid]) {
          map[sid] = {
            session_id: sid,
            target_url: f.url?.split("/").slice(0, 3).join("/") || "—",
            total_vulns: 0,
            started_at: f.timestamp,
          };
        }
        map[sid].total_vulns += 1;
      }
      setSessions(Object.values(map).reverse());
    } catch {}
  };

  const addSession = (result: any) => {
    if (!result?.session_id) return;
    const row: SessionRow = {
      session_id:      result.session_id,
      target_url:      result.target_url || "—",
      total_vulns:     result.total_vulns || 0,
      started_at:      result.started_at,
      finished_at:     result.finished_at,
      error:           result.error,
      phases:          result.phases,
      git_project:     result.git_project,
      uploaded_project:result.uploaded_project,
      docker_image_scan:result.docker_image_scan,
      build_logs:      result.build_logs,
      container_logs:  result.container_logs,
    };
    setSessions(prev => [row, ...prev.filter(s => s.session_id !== row.session_id)]);
    setSelectedSession(row);
    loadSessionFindings(row.session_id);
  };

  const selectSession = async (row: SessionRow) => {
    setSelectedSession(row);
    setShowBuildLogs(false);
    setShowContainerLogs(false);
    await loadSessionFindings(row.session_id);
  };

  const loadSessionFindings = async (sid: string) => {
    setFindingsLoading(true);
    try {
      const f = await dastAPI.getFindings(100, sid);
      setSessionFindings(f.findings || []);
    } catch {
      setSessionFindings([]);
    } finally {
      setFindingsLoading(false);
    }
  };

  const checkIsolation = async () => {
    setIsoLoading(true);
    try {
      const r = await dastAPI.verifyIsolation();
      setIsoCheck(r);
    } catch (e: any) {
      setIsoCheck({ ca09_passed: false, message: "Erreur", error: String(e?.message || e) });
    } finally {
      setIsoLoading(false);
    }
  };

  const explainDastFinding = async (finding: any) => {
    setLlmLoading(true);
    setLlmExplanation(null);
    setLlmError("");
    try {
      const result = await vulnerabilityLLMAPI.explain("dast", finding);
      setLlmExplanation(result.explanation);
    } catch (e: any) {
      setLlmError(e?.message || "Erreur LLM");
      setLlmExplanation({
        resume_simple: "Impossible de générer l'explication LLM.",
        description_technique: "Le service LLM est indisponible ou la réponse n'est pas exploitable.",
        impact: "Non disponible.",
        cause_probable: "Non disponible.",
        preuve_observee: finding?.evidence || finding?.url || "—",
        niveau_risque: finding?.risk || finding?.severity || "INFO",
        priorite_correction: "P4",
        correction_recommandee: "Vérifier Ollama, le backend et l'endpoint /api/vulnerabilities/llm/explain.",
        exemple_correction: "ollama run llama3.1:8b",
        faux_positif_possible: true,
        raison_faux_positif: e?.message || "Analyse LLM non disponible.",
      });
    } finally {
      setLlmLoading(false);
    }
  };

  // ── Lancement scan ────────────────────────────────────────
  const canLaunch = !running && !zapStatus?.active && (() => {
    if (scanTarget === "webgoat" || scanTarget === "dvwa") return true;
    if (scanTarget === "url")    return customUrl.startsWith("http");
    if (scanTarget === "upload") return !!uploadFile && uploadFile.name.endsWith(".zip");
    if (scanTarget === "git")    return gitUrl.startsWith("https://github.com/");
    return false;
  })();

  const launchScan = async () => {
    setRunning(true);
    setRunError("");
    setDetailedError("");
    try {
      let result: any = null;

      if (scanTarget === "webgoat" || scanTarget === "dvwa") {
        result = await dastAPI.startSync({ target: scanTarget, deploy_target: true });
      } else if (scanTarget === "url") {
        result = await dastAPI.startSync({ target_url: customUrl.trim(), deploy_target: false });
      } else if (scanTarget === "upload" && uploadFile) {
        result = await uploadAndScanDast(uploadFile);
      } else if (scanTarget === "git") {
        const repoName = gitUrl.split("/").pop()?.replace(".git", "") || "git-project";
        result = await dastAPI.startFromGit({
          repo_url:     gitUrl.trim(),
          branch:       gitBranch.trim() || "main",
          project_name: repoName,
        });
      }

      if (result) {
        if (result.error) {
          setRunError(result.error);
          if (result.container_logs) {
            setDetailedError(result.container_logs);
          }
        } else {
          addSession(result);
          await loadHistory();
        }
      }
    } catch (e: any) {
      const errorMsg = String(e?.message || e);
      setRunError(errorMsg);
      // Essayer d'extraire les logs de build si présents
      if (errorMsg.includes("Build échoué") || errorMsg.includes("STDOUT:")) {
        setDetailedError(errorMsg);
      }
    } finally {
      setRunning(false);
      refreshStatus();
    }
  };

  // ── Stats globales ────────────────────────────────────────
  const totalSessions = sessions.length;
  const totalVulns    = sessions.reduce((s, r) => s + r.total_vulns, 0);
  const lastSession   = sessions[0];

  // ── Render ────────────────────────────────────────────────
  return (
    <div className="flex flex-col gap-6 px-6 py-6 max-w-7xl mx-auto w-full">

      {/* ── Header ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">DAST Sandbox</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            M5 · OWASP ZAP · Docker sandbox-net internal:true · 6 phases
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Statut ZAP */}
          <div className={cn(
            "flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border",
            zapStatus?.active
              ? "bg-red-500/10 text-red-400 border-red-500/20"
              : "bg-green-500/10 text-green-400 border-green-500/20"
          )}>
            <span className={cn(
              "w-1.5 h-1.5 rounded-full",
              zapStatus?.active ? "bg-red-400 animate-pulse" : "bg-green-400"
            )} />
            {zapStatus?.active ? `Session active : ${zapStatus.session_id}` : "Inactif"}
          </div>
          {/* Isolation */}
          <button
            onClick={checkIsolation}
            disabled={isoLoading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs border border-cyber-border text-muted-foreground hover:text-foreground hover:bg-card/50 transition-colors"
          >
            {isoLoading ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
            Vérifier isolation
          </button>
        </div>
      </div>

      {/* Isolation result */}
      {isoCheck && (
        <div className={cn(
          "flex items-center gap-3 rounded-lg border px-4 py-3 text-sm",
          isoCheck.ca09_passed
            ? "bg-green-500/8 border-green-500/20 text-green-400"
            : "bg-red-500/8 border-red-500/20 text-red-400"
        )}>
          {isoCheck.ca09_passed
            ? <CheckCircle size={14} />
            : <ShieldAlert size={14} />}
          {safeStr(isoCheck.message)} — CA09 : {isoCheck.ca09_passed ? "✓ RESPECTÉ" : "✗ VIOLÉ"}
          {isoCheck.error && ` (${safeStr(isoCheck.error)})`}
        </div>
      )}

      {/* ── KPIs ───────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-4">
        {[
          {
            label: "Sessions totales",
            value: totalSessions,
            icon: <Target size={16} className="text-blue-400" />,
            color: "text-blue-400",
          },
          {
            label: "Vulnérabilités détectées",
            value: totalVulns,
            icon: <Bug size={16} className="text-red-400" />,
            color: "text-red-400",
          },
          {
            label: "Dernier scan",
            value: lastSession ? timeAgo(lastSession.started_at || "") : "—",
            icon: <Clock size={16} className="text-muted-foreground" />,
            color: "text-foreground",
          },
        ].map(({ label, value, icon, color }) => (
          <div key={label} className="rounded-xl border border-cyber-border bg-card/40 p-4 flex items-center gap-4">
            <div className="p-2 rounded-lg bg-card border border-cyber-border/60">{icon}</div>
            <div>
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={cn("text-2xl font-bold font-mono mt-0.5", color)}>{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* ── Grille principale ──────────────────────────────── */}
      <div className="grid grid-cols-[1fr_2fr] gap-6">

        {/* ── Colonne gauche : Nouveau scan + Sessions ──────── */}
        <div className="flex flex-col gap-4">

          {/* Nouveau scan */}
          <div className="rounded-xl border border-cyber-border bg-card/40 p-5">
            <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
              <Zap size={14} className="text-red-400" />
              Nouveau scan
            </h2>

            {/* Sélecteur cible */}
            <div className="grid grid-cols-3 gap-1.5 mb-4">
              {([
                { key: "webgoat", label: "WebGoat" },
                { key: "dvwa",    label: "DVWA" },
                { key: "url",     label: "URL" },
                { key: "upload",  label: "ZIP" },
                { key: "git",     label: "GitHub" },
              ] as { key: typeof scanTarget; label: string }[]).map(({ key, label }) => (
                <button
                  key={key}
                  onClick={() => setScanTarget(key)}
                  className={cn(
                    "text-xs py-1.5 px-2 rounded-lg border transition-all",
                    scanTarget === key
                      ? "bg-red-500/15 text-red-400 border-red-500/30"
                      : "text-muted-foreground border-cyber-border hover:border-cyber-border/80 hover:text-foreground"
                  )}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Input selon cible */}
            {scanTarget === "url" && (
              <input
                value={customUrl}
                onChange={e => setCustomUrl(e.target.value)}
                placeholder="https://target.example.com"
                className="w-full text-xs bg-card border border-cyber-border rounded-lg px-3 py-2 mb-3 font-mono focus:outline-none focus:border-red-500/40"
              />
            )}

            {scanTarget === "git" && (
              <div className="flex flex-col gap-2 mb-3">
                <input
                  value={gitUrl}
                  onChange={e => setGitUrl(e.target.value)}
                  placeholder="https://github.com/org/repo"
                  className="w-full text-xs bg-card border border-cyber-border rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-red-500/40"
                />
                <input
                  value={gitBranch}
                  onChange={e => setGitBranch(e.target.value)}
                  placeholder="branche : main"
                  className="w-full text-xs bg-card border border-cyber-border rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-red-500/40"
                />
              </div>
            )}

            {scanTarget === "upload" && (
              <>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  className="hidden"
                  onChange={e => { const f = e.target.files?.[0]; if (f) setUploadFile(f); }}
                />
                <div
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={e => {
                    e.preventDefault(); setIsDragging(false);
                    const f = e.dataTransfer.files?.[0]; if (f) setUploadFile(f);
                  }}
                  className={cn(
                    "mb-3 rounded-lg border-2 border-dashed p-4 text-center cursor-pointer transition-all text-xs",
                    isDragging   ? "border-red-500/50 bg-red-500/5" :
                    uploadFile   ? "border-green-500/40 bg-green-500/5 text-green-400" :
                                   "border-cyber-border text-muted-foreground hover:border-cyber-border/80"
                  )}
                >
                  {uploadFile
                    ? `✓ ${uploadFile.name} (${(uploadFile.size/1024).toFixed(0)} KB)`
                    : "Glissez un ZIP ou cliquez"}
                </div>
              </>
            )}

            {/* Infos modes avancés */}
            {(scanTarget === "git" || scanTarget === "upload") && (
              <p className="text-[10px] text-muted-foreground mb-3">
                {scanTarget === "git"
                  ? "Clone → Dockerfile natif ou auto → sandbox-net → ZAP"
                  : "Build auto (Node/Flask/PHP/Spring) → sandbox-net → ZAP"}
              </p>
            )}

            {/* Bouton lancer */}
            <button
              onClick={launchScan}
              disabled={!canLaunch}
              className={cn(
                "w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-all",
                canLaunch
                  ? "bg-red-600 hover:bg-red-700 text-white"
                  : "bg-card text-muted-foreground cursor-not-allowed border border-cyber-border"
              )}
            >
              {running
                ? <><Loader2 size={14} className="animate-spin" /> Scan en cours...</>
                : <><Play size={14} /> Lancer le scan</>}
            </button>

            {runError && (
              <div className="mt-3 rounded-lg bg-red-500/8 border border-red-500/20 p-3">
                <div className="flex items-start gap-2 text-xs text-red-400">
                  <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <p className="font-medium mb-1">Erreur :</p>
                    <p className="break-words font-mono text-[11px]">{runError.slice(0, 500)}</p>
                    {detailedError && (
                      <details className="mt-2">
                        <summary className="text-[10px] cursor-pointer hover:text-red-300 flex items-center gap-1">
                          <Terminal size={10} /> Voir les logs détaillés
                        </summary>
                        <pre className="mt-2 text-[10px] bg-black/30 p-2 rounded overflow-x-auto max-h-64">
                          {detailedError.slice(0, 3000)}
                        </pre>
                      </details>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Lien vers CodeScan pour les scans complets */}
            <button
              onClick={() => navigate("/scan-code")}
              className="mt-3 w-full flex items-center justify-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <ExternalLink size={11} />
              Scan complet SAST + DAST + CI/CD → Code Scan
            </button>
          </div>

          {/* Sessions récentes */}
          <div className="rounded-xl border border-cyber-border bg-card/40 overflow-hidden flex-1">
            <div className="px-4 py-3 border-b border-cyber-border flex items-center justify-between">
              <h2 className="text-sm font-semibold">Sessions récentes</h2>
              <button onClick={loadHistory} className="text-muted-foreground hover:text-foreground transition-colors">
                <RefreshCw size={13} />
              </button>
            </div>

            {sessions.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs text-muted-foreground">
                Aucune session
              </div>
            ) : (
              <div className="divide-y divide-cyber-border/50 max-h-[340px] overflow-y-auto">
                {sessions.map(row => (
                  <div
                    key={row.session_id}
                    onClick={() => selectSession(row)}
                    className={cn(
                      "px-4 py-3 cursor-pointer hover:bg-card/60 transition-colors",
                      selectedSession?.session_id === row.session_id && "bg-card/60 border-l-2 border-red-500/50"
                    )}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono text-muted-foreground truncate max-w-[120px]">
                        {row.session_id}
                      </span>
                      <span className={cn(
                        "text-[10px] font-medium px-1.5 py-0.5 rounded border",
                        row.error
                          ? "text-red-400 bg-red-500/10 border-red-500/20"
                          : row.total_vulns > 0
                          ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                          : "text-green-400 bg-green-500/10 border-green-500/20"
                      )}>
                        {row.error ? "Erreur" : `${row.total_vulns} vulns`}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-muted-foreground truncate max-w-[140px]">
                        {row.target_url}
                      </span>
                      <span className="text-[10px] text-muted-foreground/60">
                        {timeAgo(row.started_at || "")}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Colonne droite : Détail session + Findings ──────── */}
        <div className="flex flex-col gap-4">

          {selectedSession ? (
            <>
              {/* Header session sélectionnée */}
              <div className="rounded-xl border border-cyber-border bg-card/40 p-5">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <p className="text-[10px] font-mono text-muted-foreground">{selectedSession.session_id}</p>
                    <p className="text-sm font-medium mt-0.5 font-mono">{selectedSession.target_url}</p>
                    {selectedSession.git_project && (
                      <div className="flex items-center gap-1.5 mt-1">
                        <GitBranch size={11} className="text-green-400" />
                        <span className="text-[10px] text-green-400">
                          {selectedSession.git_project.repo_url?.split("/").slice(-2).join("/")}
                          {" · "}{selectedSession.git_project.branch}
                          {" · Dockerfile: "}{selectedSession.git_project.dockerfile}
                        </span>
                      </div>
                    )}
                    {selectedSession.uploaded_project && (
                      <div className="flex items-center gap-1.5 mt-1">
                        <Upload size={11} className="text-blue-400" />
                        <span className="text-[10px] text-blue-400">
                          {selectedSession.uploaded_project.filename}
                        </span>
                      </div>
                    )}
                    {selectedSession.docker_image_scan && (
                      <div className="flex items-center gap-1.5 mt-1">
                        <Container size={11} className="text-violet-400" />
                        <span className="text-[10px] text-violet-400">
                          {selectedSession.docker_image_scan.image_name}
                          {" · Trivy: "}{selectedSession.docker_image_scan.trivy_summary?.length || 0} résultats
                        </span>
                      </div>
                    )}
                  </div>
                  <div className={cn(
                    "text-xs font-medium px-2.5 py-1 rounded-full border",
                    selectedSession.error
                      ? "text-red-400 bg-red-500/10 border-red-500/20"
                      : selectedSession.total_vulns > 0
                      ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                      : "text-green-400 bg-green-500/10 border-green-500/20"
                  )}>
                    {selectedSession.error
                      ? "Erreur"
                      : `${selectedSession.total_vulns} vulnérabilités`}
                  </div>
                </div>

                {/* Logs section si erreur */}
                {(selectedSession.error || selectedSession.container_logs) && (
                  <div className="mt-3 rounded-lg bg-red-500/5 border border-red-500/20 p-3">
                    <div className="flex items-start gap-2">
                      <AlertTriangle size={14} className="text-red-400 shrink-0 mt-0.5" />
                      <div className="flex-1">
                        <p className="text-xs font-medium text-red-400 mb-1">Erreur de déploiement</p>
                        {selectedSession.container_logs && (
                          <details className="mt-2">
                            <summary className="text-[10px] cursor-pointer hover:text-red-300 flex items-center gap-1">
                              <Terminal size={10} /> Logs du container
                            </summary>
                            <pre className="mt-2 text-[10px] bg-black/30 p-2 rounded overflow-x-auto max-h-48">
                              {selectedSession.container_logs}
                            </pre>
                          </details>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Phases */}
                {selectedSession.phases && (
                  <div className="grid grid-cols-6 gap-2 mt-4">
                    {[
                      { key: "1_deploy",  label: "Déploiement" },
                      { key: "2_spider",  label: "Spider" },
                      { key: "3_inject",  label: "Injection" },
                      { key: "4_capture", label: "PCAP" },
                      { key: "5_proofs",  label: "Preuves" },
                      { key: "6_teardown",label: "Teardown" },
                    ].map(({ key, label }) => {
                      const phase   = selectedSession.phases?.[key];
                      const ok      = phase?.success === true;
                      const pending = !phase;
                      return (
                        <div
                          key={key}
                          className={cn(
                            "rounded-lg px-2 py-2 text-center border",
                            pending
                              ? "border-cyber-border bg-card/30"
                              : ok
                              ? "border-green-500/20 bg-green-500/8"
                              : "border-red-500/20 bg-red-500/8"
                          )}
                        >
                          <div className={cn(
                            "text-[10px] font-medium",
                            pending ? "text-muted-foreground" : ok ? "text-green-400" : "text-red-400"
                          )}>
                            {pending ? "—" : ok ? "✓" : "✗"}
                          </div>
                          <div className="text-[9px] text-muted-foreground mt-0.5">{label}</div>
                          {phase?.urls_found !== undefined && (
                            <div className="text-[9px] text-muted-foreground/60">{phase.urls_found} URLs</div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>


              {/* Explication LLM */}
              {(llmLoading || llmExplanation || llmError) && (
                <div className="rounded-xl border border-purple-500/25 bg-purple-500/5 p-4">
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <h2 className="text-sm font-semibold flex items-center gap-2 text-purple-300">
                      <BrainCircuit size={14} />
                      Explication LLM
                    </h2>
                    <button
                      onClick={() => { setLlmExplanation(null); setLlmError(""); }}
                      className="text-muted-foreground hover:text-foreground"
                    >
                      <X size={14} />
                    </button>
                  </div>

                  {llmLoading ? (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Loader2 size={14} className="animate-spin" />
                      Génération de l'explication...
                    </div>
                  ) : (
                    <div className="space-y-3 text-xs">
                      {llmError && <p className="text-red-300">{llmError}</p>}
                      <div>
                        <p className="uppercase tracking-wide text-muted-foreground">Résumé</p>
                        <p className="mt-1 text-sm">{llmExplanation?.resume_simple || "—"}</p>
                      </div>
                      <div>
                        <p className="uppercase tracking-wide text-muted-foreground">Impact</p>
                        <p className="mt-1 text-muted-foreground">{llmExplanation?.impact || "—"}</p>
                      </div>
                      <div>
                        <p className="uppercase tracking-wide text-muted-foreground">Correction recommandée</p>
                        <p className="mt-1 text-muted-foreground">{llmExplanation?.correction_recommandee || "—"}</p>
                      </div>
                      {llmExplanation?.exemple_correction && (
                        <pre className="rounded-lg bg-black/30 p-3 overflow-x-auto whitespace-pre-wrap">
                          {llmExplanation.exemple_correction}
                        </pre>
                      )}
                      <div className="flex flex-wrap gap-2">
                        <span className="rounded-full border border-purple-500/30 bg-purple-500/10 px-2 py-1 text-purple-300">
                          Risque : {llmExplanation?.niveau_risque || "—"}
                        </span>
                        <span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-2 py-1 text-blue-300">
                          Priorité : {llmExplanation?.priorite_correction || "—"}
                        </span>
                        <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-amber-300">
                          Faux positif : {llmExplanation?.faux_positif_possible ? "possible" : "peu probable"}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Findings */}
              <div className="rounded-xl border border-cyber-border bg-card/40 overflow-hidden flex-1">
                <div className="px-4 py-3 border-b border-cyber-border flex items-center justify-between">
                  <h2 className="text-sm font-semibold flex items-center gap-2">
                    <Bug size={14} className="text-red-400" />
                    Findings
                    <span className="text-[10px] font-normal text-muted-foreground">
                      {findingsLoading ? "chargement..." : `${sessionFindings.length} entrées`}
                    </span>
                  </h2>
                  {/* Compteurs par sévérité */}
                  <div className="flex items-center gap-2">
                    {(["High", "Medium", "Low"] as const).map(risk => {
                      const count = sessionFindings.filter(f => f.risk === risk).length;
                      if (!count) return null;
                      return (
                        <span key={risk} className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded border font-medium",
                          RISK_COLOR[risk]
                        )}>
                          {risk[0]} {count}
                        </span>
                      );
                    })}
                  </div>
                </div>

                {findingsLoading ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 size={20} className="animate-spin text-muted-foreground" />
                  </div>
                ) : sessionFindings.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                    <CheckCircle size={24} className="mb-2 text-green-400/50" />
                    <p className="text-sm">Aucun finding pour cette session</p>
                    {selectedSession.error && (
                      <p className="text-xs mt-2 text-muted-foreground/60">
                        Le scan n'a pas pu être complété à cause d'une erreur de déploiement
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="divide-y divide-cyber-border/40 max-h-[420px] overflow-y-auto">
                    {sessionFindings.map((f, i) => (
                      <div key={i} className="px-4 py-3 hover:bg-card/40 transition-colors">
                        <div className="flex items-start gap-3">
                          <span className={cn(
                            "mt-0.5 shrink-0 text-[10px] px-1.5 py-0.5 rounded border font-medium",
                            RISK_COLOR[f.risk] || RISK_COLOR["Low"]
                          )}>
                            {f.risk || "Info"}
                          </span>
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-medium">{safeStr(f.alert_name || f.title)}</p>
                            <p className="text-[10px] text-muted-foreground mt-0.5 truncate">
                              {safeStr(f.url)}
                            </p>
                            {f.attack && (
                              <p className="text-[10px] text-muted-foreground/70 mt-0.5">
                                Payload :{" "}
                                <code className="font-mono text-amber-400/80 bg-card px-1 rounded">
                                  {safeStr(f.attack).slice(0, 60)}
                                </code>
                              </p>
                            )}
                          </div>
                          {f.cwe_id && (
                            <span className="text-[10px] font-mono text-muted-foreground/50 shrink-0">
                              CWE-{f.cwe_id}
                            </span>
                          )}
                          <button
                            onClick={() => explainDastFinding(f)}
                            className="shrink-0 flex items-center gap-1 rounded-lg border border-purple-500/30 bg-purple-500/10 px-2 py-1 text-[10px] text-purple-300 hover:bg-purple-500/15"
                          >
                            <BrainCircuit size={11} />
                            Expliquer
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            // Aucune session sélectionnée
            <div className="rounded-xl border border-cyber-border bg-card/40 flex flex-col items-center justify-center py-20 text-muted-foreground">
              <Target size={32} className="mb-3 opacity-30" />
              <p className="text-sm font-medium">Aucune session sélectionnée</p>
              <p className="text-xs mt-1">Lancez un scan ou choisissez une session dans l'historique</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}