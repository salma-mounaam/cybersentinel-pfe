// ============================================================
// pages/ScanResults.tsx — Page de résultats unifiée
// FIX 3: DastCard gère les deux cas (dastResult avec phases OU getStatus)
// FIX 4: SASTScanner handleLaunchScan → /scan-code simple
// ============================================================
import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  Shield, Zap, Code2, ArrowLeft, ArrowRight,
  CheckCircle2, XCircle, AlertTriangle, Loader2, ExternalLink,
} from "lucide-react";
import { cn } from "../lib/utils";
import { sastAPI, dastAPI, cicdAPI } from "../services/api";

interface ScanState {
  sastOn: boolean;
  dastOn: boolean;
  cicdOn: boolean;
  projectName: string;
  sourceMode: string;
  dastTarget: string;
  // dastResult peut avoir :
  // - .phases (zip upload ou preset sync)
  // - .total_vulns
  // - .error
  dastResult?: any;
}

function safeStr(v: any): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

// ── Score global ─────────────────────────────────────────────
function globalRisk(sastData: any, dastData: any, cicdData: any) {
  let score = 0;
  if (sastData) {
    const b = sastData.by_severity || {};
    score += (b.CRITICAL || 0) * 3 + (b.HIGH || 0) * 2 + (b.MEDIUM || 0);
  }
  if (dastData) score += (dastData.total_vulns || dastData.total_proofs || 0) * 2;
  if (cicdData) score += (cicdData.blocked || 0) * 3;

  if (score >= 15) return { score, level: "critical" as const, label: "Critique" };
  if (score >= 8)  return { score, level: "high"     as const, label: "Élevé" };
  if (score >= 3)  return { score, level: "medium"   as const, label: "Moyen" };
  return { score, level: "low" as const, label: "Faible" };
}

function SevCount({ count, label, color }: { count: number; label: string; color: string }) {
  return (
    <div className="text-center">
      <div className={cn("text-xl font-bold font-mono", color)}>{count}</div>
      <div className="text-[10px] text-muted-foreground mt-0.5">{label}</div>
    </div>
  );
}

// ── Carte SAST ───────────────────────────────────────────────
function SastCard({ data, loading, onDetail }: { data: any; loading: boolean; onDetail: () => void }) {
  const bySev = data?.by_severity || {};
  const total = data?.total || 0;
  const findings = data?.top_findings || [];

  return (
    <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-5 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-blue-400" />
          <span className="text-sm font-medium text-blue-400">Scan statique</span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/20">M4</span>
        </div>
        {loading ? <Loader2 size={14} className="animate-spin text-muted-foreground" /> : (
          <span className={cn("text-xs px-2 py-0.5 rounded-full border font-medium",
            total === 0 ? "bg-green-500/10 text-green-400 border-green-500/20" :
            bySev.CRITICAL > 0 ? "bg-red-500/10 text-red-400 border-red-500/20" :
            "bg-amber-500/10 text-amber-400 border-amber-500/20"
          )}>
            {total === 0 ? "Aucun finding" : `${total} findings`}
          </span>
        )}
      </div>

      {!loading && data && (
        <>
          <div className="grid grid-cols-4 gap-2 py-3 border-y border-blue-500/10">
            <SevCount count={bySev.CRITICAL || 0} label="Critique" color="text-red-400" />
            <SevCount count={bySev.HIGH || 0}     label="Élevé"    color="text-amber-400" />
            <SevCount count={bySev.MEDIUM || 0}   label="Moyen"    color="text-blue-400" />
            <SevCount count={bySev.LOW || 0}       label="Faible"   color="text-green-400" />
          </div>
          {findings.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Top findings</p>
              {findings.slice(0, 3).map((f: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className={cn("w-1.5 h-1.5 rounded-full shrink-0",
                    f.severity === "CRITICAL" ? "bg-red-400" :
                    f.severity === "HIGH" ? "bg-amber-400" : "bg-blue-400"
                  )} />
                  <span className="text-muted-foreground truncate">{f.message || f.title || "Finding"}</span>
                  {f.tool && <span className="ml-auto text-[10px] text-muted-foreground/60 shrink-0">{f.tool}</span>}
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {!loading && !data && <p className="text-xs text-muted-foreground">Aucune donnée disponible</p>}

      <button onClick={onDetail} className="mt-auto flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors">
        Voir tous les findings <ArrowRight size={12} />
      </button>
    </div>
  );
}

// ── Carte DAST ───────────────────────────────────────────────
// FIX 3: gère les deux sources de données
// - dastResult passé dans le state (a .phases, .total_vulns)
// - getStatus() depuis l'API (a .active, .last_scan_vulns)
function DastCard({ data, loading, onDetail }: { data: any; loading: boolean; onDetail: () => void }) {
  // total_vulns vient du résultat direct du scan
  // total_proofs vient de getFindings()
  const totalVulns = Number(data?.total_vulns ?? data?.total_proofs ?? 0);

  // phases disponibles seulement si dastResult a été passé
  const phases = data?.phases || {};
  const phaseKeys = Object.keys(phases);
  const passedPhases = phaseKeys.filter(k => phases[k]?.success === true).length;

  // statut session (depuis getStatus)
  const isActive = data?.active || data?.running || false;

  return (
    <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-5 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap size={16} className="text-red-400" />
          <span className="text-sm font-medium text-red-400">Scan dynamique</span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">M5</span>
        </div>
        {loading ? <Loader2 size={14} className="animate-spin text-muted-foreground" /> : (
          <span className={cn("text-xs px-2 py-0.5 rounded-full border font-medium",
            data?.error ? "bg-red-500/10 text-red-400 border-red-500/20" :
            totalVulns === 0 ? "bg-green-500/10 text-green-400 border-green-500/20" :
            "bg-red-500/10 text-red-400 border-red-500/20"
          )}>
            {data?.error ? "Erreur" : totalVulns === 0 ? "Aucune vulnérabilité" : `${totalVulns} vulnérabilités`}
          </span>
        )}
      </div>

      {!loading && data && !data.error && (
        <>
          {/* Phases si disponibles (résultat direct du scan) */}
          {phaseKeys.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Phases d'exécution</p>
                <span className="text-[10px] text-muted-foreground">{passedPhases}/{phaseKeys.length} OK</span>
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                {phaseKeys.slice(0, 6).map((k) => {
                  const ok = phases[k]?.success === true;
                  return (
                    <div key={k} className={cn("flex items-center gap-1 text-[10px] px-2 py-1 rounded",
                      ok ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"
                    )}>
                      {ok ? <CheckCircle2 size={10} className="shrink-0" /> : <XCircle size={10} className="shrink-0" />}
                      <span className="truncate">{k.replace(/^\d_/, "").replace(/_/g, " ")}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Pas de phases → afficher statut session depuis API */}
          {phaseKeys.length === 0 && (
            <div className="py-2">
              <div className="flex items-center gap-2 text-xs">
                <span className={cn("w-2 h-2 rounded-full", isActive ? "bg-red-400" : "bg-green-400")} />
                <span className="text-muted-foreground">Session {isActive ? "en cours" : "terminée"}</span>
              </div>
              {data.total_pcaps !== undefined && (
                <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
                  <span>Fichiers PCAP</span>
                  <span className="font-mono text-purple-400">{data.total_pcaps}</span>
                </div>
              )}
            </div>
          )}

          {data.pcap_path && (
            <div className="flex items-center gap-2 text-[10px] text-purple-400 font-mono">
              <span>PCAP :</span>
              <span>{safeStr(data.pcap_path).split("/").pop()}</span>
            </div>
          )}
        </>
      )}

      {!loading && data?.error && (
        <p className="text-xs text-red-400">{safeStr(data.error).slice(0, 120)}</p>
      )}

      {!loading && !data && <p className="text-xs text-muted-foreground">Aucune donnée disponible</p>}

      <button onClick={onDetail} className="mt-auto flex items-center gap-1.5 text-xs text-red-400 hover:text-red-300 transition-colors">
        Voir les preuves DAST <ArrowRight size={12} />
      </button>
    </div>
  );
}

// ── Carte CI/CD ──────────────────────────────────────────────
function CicdCard({ data, loading, onDetail }: { data: any; loading: boolean; onDetail: () => void }) {
  const runs = Array.isArray(data?.runs) ? data.runs : [];
  const lastRun = runs[0];
  const blocked = data?.blocked || 0;
  const passed = runs.filter((r: any) => (r.decision || "").toUpperCase() === "PASS").length;
  const isBlocked = lastRun && (lastRun.decision || "").toUpperCase() === "BLOCK";

  return (
    <div className="rounded-xl border border-teal-500/20 bg-teal-500/5 p-5 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Code2 size={16} className="text-teal-400" />
          <span className="text-sm font-medium text-teal-400">Pipeline CI/CD</span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-teal-500/15 text-teal-400 border border-teal-500/20">M8</span>
        </div>
        {loading ? <Loader2 size={14} className="animate-spin text-muted-foreground" /> :
          lastRun ? (
            <span className={cn("text-xs px-2 py-0.5 rounded-full border font-medium",
              isBlocked ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-green-500/10 text-green-400 border-green-500/20"
            )}>
              {isBlocked ? "Bloqué" : "Validé"}
            </span>
          ) : null
        }
      </div>

      {!loading && data && (
        <>
          <div className="grid grid-cols-3 gap-2 py-3 border-y border-teal-500/10">
            <SevCount count={runs.length} label="Total runs" color="text-foreground" />
            <SevCount count={passed}      label="Succès"     color="text-green-400" />
            <SevCount count={blocked}     label="Bloqués"    color="text-red-400" />
          </div>
          {lastRun && (
            <div className="space-y-1.5">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Dernier run</p>
              <div className="text-xs space-y-1">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Repo</span>
                  <span className="font-mono text-foreground truncate max-w-[140px]">{lastRun.repo || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Critiques</span>
                  <span className={cn("font-mono", lastRun.critical_count > 0 ? "text-red-400" : "text-green-400")}>
                    {lastRun.critical_count || 0}
                  </span>
                </div>
                {lastRun.secrets_found && (
                  <div className="flex items-center gap-1 text-amber-400 text-[10px]">
                    <AlertTriangle size={10} />
                    Secret exposé détecté
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
      {!loading && !data && <p className="text-xs text-muted-foreground">Aucune donnée disponible</p>}

      <button onClick={onDetail} className="mt-auto flex items-center gap-1.5 text-xs text-teal-400 hover:text-teal-300 transition-colors">
        Voir les pipelines <ArrowRight size={12} />
      </button>
    </div>
  );
}

// ── Composant principal ──────────────────────────────────────
export default function ScanResults() {
  const navigate = useNavigate();
  const location = useLocation();
  const scanState = (location.state as ScanState) || {};
  const { sastOn, dastOn, cicdOn, projectName, dastResult } = scanState;

  const [sastData, setSastData] = useState<any>(null);
  const [dastData, setDastData] = useState<any>(dastResult || null);
  const [cicdData, setCicdData] = useState<any>(null);
  const [sastLoading, setSastLoading] = useState(!!sastOn);
  // FIX 3: si dastResult déjà dans state, pas besoin de charger
  const [dastLoading, setDastLoading] = useState(!!dastOn && !dastResult);
  const [cicdLoading, setCicdLoading] = useState(!!cicdOn);

  useEffect(() => {
    if (sastOn) {
      Promise.all([
        sastAPI.getStats({}),
        sastAPI.getFindings({ limit: 5 }),
      ]).then(([stats, findings]) => {
        setSastData({ ...stats, top_findings: findings?.findings || [] });
      }).catch(() => setSastData(null))
        .finally(() => setSastLoading(false));
    }

    if (dastOn && !dastResult) {
      // FIX 3: charger getStatus() (qui a .active, .total_pcaps) + getFindings() pour le count
      Promise.all([
        dastAPI.getStatus(),
        dastAPI.getFindings(5),
      ]).then(([status, findings]) => {
        setDastData({
          ...status,
          total_vulns: findings?.total_proofs || findings?.total || 0,
          total_pcaps: findings?.total_pcaps || 0,
          // pas de phases disponibles dans ce cas → DastCard affichera le statut session
        });
      }).catch(() => setDastData(null))
        .finally(() => setDastLoading(false));
    }

    if (cicdOn) {
      cicdAPI.getRuns()
        .then((r) => setCicdData(r))
        .catch(() => setCicdData(null))
        .finally(() => setCicdLoading(false));
    }
  }, []);

  const risk = globalRisk(sastData, dastData, cicdData);

  const riskColors = {
    critical: { bg: "bg-red-500/10",   border: "border-red-500/30",   text: "text-red-400",   bar: "bg-red-500" },
    high:     { bg: "bg-amber-500/10", border: "border-amber-500/30", text: "text-amber-400", bar: "bg-amber-500" },
    medium:   { bg: "bg-blue-500/10",  border: "border-blue-500/30",  text: "text-blue-400",  bar: "bg-blue-500" },
    low:      { bg: "bg-green-500/10", border: "border-green-500/30", text: "text-green-400", bar: "bg-green-500" },
  };

  const rc = riskColors[risk.level];
  const isLoading = sastLoading || dastLoading || cicdLoading;
  const activeCount = [sastOn, dastOn, cicdOn].filter(Boolean).length;

  return (
    <div className="flex flex-col items-center w-full px-8 py-10">
      <div className="w-full max-w-5xl space-y-8">

        {/* Header */}
        <div className="flex items-center gap-3">
          <button onClick={() => navigate("/scan-code")} className="rounded p-1 text-muted-foreground transition-colors hover:text-foreground">
            <ArrowLeft size={16} />
          </button>
          <div>
            <h1 className="text-2xl font-semibold">Résultats du scan</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {projectName ? `Projet : ${projectName}` : "Analyse complète"}
              {" · "}
              {[sastOn && "SAST", dastOn && "DAST", cicdOn && "CI/CD"].filter(Boolean).join(" + ")}
            </p>
          </div>
          {isLoading && (
            <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 size={13} className="animate-spin" />
              Chargement des résultats...
            </div>
          )}
        </div>

        {/* Score global */}
        <div className={cn("rounded-xl border p-5", rc.bg, rc.border)}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className={cn("text-3xl font-bold font-mono", rc.text)}>{risk.label}</div>
              <div>
                <p className="text-sm text-muted-foreground">Niveau de risque global</p>
                <p className="text-xs text-muted-foreground/60">Score agrégé {[sastOn && "SAST", dastOn && "DAST", cicdOn && "CI/CD"].filter(Boolean).join(" + ")}</p>
              </div>
            </div>
            <div className={cn("text-4xl font-bold font-mono", rc.text)}>{risk.score}</div>
          </div>
          <div className="w-full h-1.5 rounded-full bg-cyber-border/40 overflow-hidden">
            <div className={cn("h-full rounded-full transition-all", rc.bar)} style={{ width: `${Math.min(100, (risk.score / 30) * 100)}%` }} />
          </div>
        </div>

        {/* Cartes résultats */}
        <div className={cn("grid gap-5",
          activeCount === 1 ? "grid-cols-1 max-w-sm" :
          activeCount === 2 ? "grid-cols-2" : "grid-cols-3"
        )}>
          {sastOn && <SastCard data={sastData} loading={sastLoading} onDetail={() => navigate("/sast")} />}
          {dastOn && <DastCard data={dastData} loading={dastLoading} onDetail={() => navigate("/dast")} />}
          {cicdOn && <CicdCard data={cicdData} loading={cicdLoading} onDetail={() => navigate("/cicd")} />}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3 pt-2 border-t border-cyber-border/40 flex-wrap">
          <button onClick={() => navigate("/scan-code")} className="flex items-center gap-2 px-4 py-2 rounded-lg border border-cyber-border text-sm text-muted-foreground hover:text-foreground hover:bg-card/50 transition-colors">
            <ArrowLeft size={14} />
            Nouveau scan
          </button>
          {sastOn && (
            <button onClick={() => navigate("/sast")} className="flex items-center gap-2 px-4 py-2 rounded-lg border border-blue-500/30 bg-blue-500/5 text-sm text-blue-400 hover:bg-blue-500/10 transition-colors">
              <ExternalLink size={14} /> SAST complet
            </button>
          )}
          {dastOn && (
            <button onClick={() => navigate("/dast")} className="flex items-center gap-2 px-4 py-2 rounded-lg border border-red-500/30 bg-red-500/5 text-sm text-red-400 hover:bg-red-500/10 transition-colors">
              <ExternalLink size={14} /> DAST complet
            </button>
          )}
          {cicdOn && (
            <button onClick={() => navigate("/cicd")} className="flex items-center gap-2 px-4 py-2 rounded-lg border border-teal-500/30 bg-teal-500/5 text-sm text-teal-400 hover:bg-teal-500/10 transition-colors">
              <ExternalLink size={14} /> CI/CD complet
            </button>
          )}
          <button onClick={() => navigate("/incidents")} className="ml-auto flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-violet hover:bg-cyber-violet-dark text-sm text-white transition-colors">
            Voir les incidents générés <ArrowRight size={14} />
          </button>
        </div>

      </div>
    </div>
  );
}