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
  dastResult?: any;
  sastScanId?: string | null;
}

function safeStr(v: any): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

function globalRisk(sastData: any, dastData: any, cicdData: any) {
  const b = sastData?.by_severity || {};
  const critical = b.CRITICAL || 0;
  const high = b.HIGH || 0;
  const medium = b.MEDIUM || 0;

  const dastVulns = Number(dastData?.total_vulns ?? dastData?.total_proofs ?? 0);
  const blocked = cicdData?.blocked || 0;

  const raw = Math.min(
    critical * 10 + high * 3 + medium + dastVulns * 5 + blocked * 8,
    100
  );

  if (critical > 0 || raw >= 80) return { score: raw, level: "critical" as const, label: "Critique" };
  if (raw >= 50) return { score: raw, level: "high" as const, label: "Élevé" };
  if (raw >= 20) return { score: raw, level: "medium" as const, label: "Moyen" };
  return { score: raw, level: "low" as const, label: "Faible" };
}

function SevCount({ count, label, color }: { count: number; label: string; color: string }) {
  return (
    <div className="text-center">
      <div className={cn("text-xl font-bold font-mono", color)}>{count}</div>
      <div className="text-[10px] text-muted-foreground mt-0.5">{label}</div>
    </div>
  );
}

function SastCard({
  data, loading, scanId, onDetail,
}: {
  data: any;
  loading: boolean;
  scanId: string | null;
  onDetail: () => void;
}) {
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

        {loading ? (
          <Loader2 size={14} className="animate-spin text-muted-foreground" />
        ) : (
          <span className={cn(
            "text-xs px-2 py-0.5 rounded-full border font-medium",
            total === 0 ? "bg-green-500/10 text-green-400 border-green-500/20" :
            bySev.CRITICAL > 0 ? "bg-red-500/10 text-red-400 border-red-500/20" :
            "bg-amber-500/10 text-amber-400 border-amber-500/20"
          )}>
            {total === 0 ? "Aucun finding" : `${total} findings`}
          </span>
        )}
      </div>

      <p className="text-[10px] font-mono text-muted-foreground/50 -mt-2 truncate">
        scan : {scanId || "non reçu"}
      </p>

      {!loading && data && (
        <>
          <div className="grid grid-cols-4 gap-2 py-3 border-y border-blue-500/10">
            <SevCount count={bySev.CRITICAL || 0} label="Critique" color="text-red-400" />
            <SevCount count={bySev.HIGH || 0} label="Élevé" color="text-amber-400" />
            <SevCount count={bySev.MEDIUM || 0} label="Moyen" color="text-blue-400" />
            <SevCount count={bySev.LOW || 0} label="Faible" color="text-green-400" />
          </div>

          {findings.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Top findings</p>
              {findings.slice(0, 3).map((f: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className={cn("w-1.5 h-1.5 rounded-full shrink-0",
                    f.severity === "CRITICAL" ? "bg-red-400" :
                    f.severity === "HIGH" ? "bg-amber-400" :
                    "bg-blue-400"
                  )} />
                  <span className="text-muted-foreground truncate">
                    {f.message || f.title || "Finding"}
                  </span>
                  {f.tool && (
                    <span className="ml-auto text-[10px] text-muted-foreground/60 shrink-0">
                      {f.tool}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {!loading && !data && (
        <p className="text-xs text-muted-foreground">Aucune donnée disponible</p>
      )}

      <button
        onClick={onDetail}
        className="mt-auto flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
      >
        Voir tous les findings <ArrowRight size={12} />
      </button>
    </div>
  );
}

function DastCard({ data, loading, onDetail }: { data: any; loading: boolean; onDetail: () => void }) {
  const totalVulns = Number(data?.total_vulns ?? data?.total_proofs ?? 0);
  const phases = data?.phases || {};
  const phaseKeys = Object.keys(phases);
  const passedPhases = phaseKeys.filter(k => phases[k]?.success === true).length;
  const isActive = data?.active || data?.running || false;

  return (
    <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-5 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap size={16} className="text-red-400" />
          <span className="text-sm font-medium text-red-400">Scan dynamique</span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">M5</span>
        </div>

        {loading ? (
          <Loader2 size={14} className="animate-spin text-muted-foreground" />
        ) : (
          <span className={cn(
            "text-xs px-2 py-0.5 rounded-full border font-medium",
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
                    <div key={k} className={cn(
                      "flex items-center gap-1 text-[10px] px-2 py-1 rounded",
                      ok ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"
                    )}>
                      {ok ? <CheckCircle2 size={10} /> : <XCircle size={10} />}
                      <span className="truncate">{k.replace(/^\d_/, "").replace(/_/g, " ")}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {phaseKeys.length === 0 && (
            <div className="py-2">
              <div className="flex items-center gap-2 text-xs">
                <span className={cn("w-2 h-2 rounded-full", isActive ? "bg-red-400" : "bg-green-400")} />
                <span className="text-muted-foreground">
                  Session {isActive ? "en cours" : "terminée"}
                </span>
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

      {!loading && !data && (
        <p className="text-xs text-muted-foreground">Aucune donnée disponible</p>
      )}

      <button
        onClick={onDetail}
        className="mt-auto flex items-center gap-1.5 text-xs text-red-400 hover:text-red-300 transition-colors"
      >
        Voir les preuves DAST <ArrowRight size={12} />
      </button>
    </div>
  );
}

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

        {loading ? (
          <Loader2 size={14} className="animate-spin text-muted-foreground" />
        ) : lastRun ? (
          <span className={cn(
            "text-xs px-2 py-0.5 rounded-full border font-medium",
            isBlocked ? "bg-red-500/10 text-red-400 border-red-500/20" :
            "bg-green-500/10 text-green-400 border-green-500/20"
          )}>
            {isBlocked ? "Bloqué" : "Validé"}
          </span>
        ) : null}
      </div>

      {!loading && data && (
        <>
          <div className="grid grid-cols-3 gap-2 py-3 border-y border-teal-500/10">
            <SevCount count={runs.length} label="Total runs" color="text-foreground" />
            <SevCount count={passed} label="Succès" color="text-green-400" />
            <SevCount count={blocked} label="Bloqués" color="text-red-400" />
          </div>

          {lastRun && (
            <div className="space-y-1.5">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Dernier run</p>
              <div className="text-xs space-y-1">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Repo</span>
                  <span className="font-mono text-foreground truncate max-w-[140px]">
                    {lastRun.repo || "—"}
                  </span>
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

      {!loading && !data && (
        <p className="text-xs text-muted-foreground">Aucune donnée disponible</p>
      )}

      <button
        onClick={onDetail}
        className="mt-auto flex items-center gap-1.5 text-xs text-teal-400 hover:text-teal-300 transition-colors"
      >
        Voir les pipelines <ArrowRight size={12} />
      </button>
    </div>
  );
}

export default function ScanResults() {
  const navigate = useNavigate();
  const location = useLocation();
  const scanState = (location.state as ScanState) || {};
  const { sastOn, dastOn, cicdOn, projectName, dastResult, sastScanId } = scanState;

  const [sastData, setSastData] = useState<any>(null);
  const [dastData, setDastData] = useState<any>(dastResult || null);
  const [cicdData, setCicdData] = useState<any>(null);

  const [sastLoading, setSastLoading] = useState(!!sastOn);
  const [dastLoading, setDastLoading] = useState(!!dastOn && !dastResult);
  const [cicdLoading, setCicdLoading] = useState(!!cicdOn);

  useEffect(() => {
    let cancelled = false;

    const loadSast = async () => {
      if (!sastOn) return;

      setSastLoading(true);
      const scanId = sastScanId || null;

      for (let attempt = 0; attempt < 30; attempt++) {
        try {
          const [stats, findings] = await Promise.all([
            sastAPI.getStats(scanId ? { scan_id: scanId } : {}),
            sastAPI.getFindings(scanId ? { limit: 5, scan_id: scanId } : { limit: 5 }),
          ]);

          const total =
            Number(stats?.total || 0) ||
            Number(findings?.total || 0) ||
            Number(findings?.findings?.length || 0);

          if (!cancelled && stats) {
            setSastData({
              ...stats,
              total,
              top_findings: findings?.findings || [],
            });
            setSastLoading(false);
            return;
          }
        } catch (e) {
          console.error("SAST polling error:", e);
        }

        await new Promise((resolve) => setTimeout(resolve, 2000));
      }

      if (!cancelled) setSastLoading(false);
    };

    const loadDast = async () => {
      if (!dastOn || dastResult) return;

      setDastLoading(true);

      Promise.all([dastAPI.getStatus(), dastAPI.getFindings(5)])
        .then(([status, findings]) => setDastData({
          ...status,
          total_vulns: findings?.total_proofs || findings?.total || 0,
          total_pcaps: findings?.total_pcaps || 0,
        }))
        .catch(() => setDastData(null))
        .finally(() => setDastLoading(false));
    };

    const loadCicd = async () => {
      if (!cicdOn) return;

      setCicdLoading(true);

      cicdAPI.getRuns()
        .then((r) => setCicdData(r))
        .catch(() => setCicdData(null))
        .finally(() => setCicdLoading(false));
    };

    loadSast();
    loadDast();
    loadCicd();

    return () => {
      cancelled = true;
    };
  }, [sastOn, dastOn, cicdOn, sastScanId, dastResult]);

  const goToSast = () => navigate("/sast", { state: { scanId: sastScanId || null } });

  const risk = globalRisk(sastData, dastData, cicdData);

  const riskColors = {
    critical: { bg: "bg-red-500/10", border: "border-red-500/30", text: "text-red-400", bar: "bg-red-500" },
    high: { bg: "bg-amber-500/10", border: "border-amber-500/30", text: "text-amber-400", bar: "bg-amber-500" },
    medium: { bg: "bg-blue-500/10", border: "border-blue-500/30", text: "text-blue-400", bar: "bg-blue-500" },
    low: { bg: "bg-green-500/10", border: "border-green-500/30", text: "text-green-400", bar: "bg-green-500" },
  };

  const rc = riskColors[risk.level];
  const isLoading = sastLoading || dastLoading || cicdLoading;
  const activeCount = [sastOn, dastOn, cicdOn].filter(Boolean).length;
  const moduleLabel = [sastOn && "SAST", dastOn && "DAST", cicdOn && "CI/CD"].filter(Boolean).join(" + ");

  return (
    <div className="flex flex-col items-center w-full px-8 py-10">
      <div className="w-full max-w-5xl space-y-8">

        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate("/scan-code")}
            className="rounded p-1 text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft size={16} />
          </button>

          <div>
            <h1 className="text-2xl font-semibold">Résultats du scan</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {projectName ? `Projet : ${projectName}` : "Analyse complète"} · {moduleLabel}
            </p>

            {sastOn && (
              <p className="text-xs font-mono text-muted-foreground mt-1">
                scan_id : {sastScanId || "non reçu"}
              </p>
            )}
          </div>

          {isLoading && (
            <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 size={13} className="animate-spin" />
              Chargement des résultats...
            </div>
          )}
        </div>

        <div className={cn("rounded-xl border p-5", rc.bg, rc.border)}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className={cn("text-3xl font-bold font-mono", rc.text)}>
                {risk.label}
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Niveau de risque global</p>
                <p className="text-xs text-muted-foreground/60">Score agrégé {moduleLabel}</p>
              </div>
            </div>

            <div className="text-right">
              <div className={cn("text-4xl font-bold font-mono", rc.text)}>
                {risk.score}
              </div>
              <div className="text-[10px] text-muted-foreground/60 mt-0.5">/ 100</div>
            </div>
          </div>

          <div className="w-full h-1.5 rounded-full bg-cyber-border/40 overflow-hidden">
            <div className={cn("h-full rounded-full transition-all", rc.bar)} style={{ width: `${risk.score}%` }} />
          </div>
        </div>

        <div className={cn(
          "grid gap-5",
          activeCount === 1 ? "grid-cols-1 max-w-sm" :
          activeCount === 2 ? "grid-cols-2" :
          "grid-cols-3"
        )}>
          {sastOn && (
            <SastCard
              data={sastData}
              loading={sastLoading}
              scanId={sastScanId || null}
              onDetail={goToSast}
            />
          )}

          {dastOn && (
            <DastCard
              data={dastData}
              loading={dastLoading}
              onDetail={() => navigate("/dast")}
            />
          )}

          {cicdOn && (
            <CicdCard
              data={cicdData}
              loading={cicdLoading}
              onDetail={() => navigate("/cicd")}
            />
          )}
        </div>

        <div className="flex items-center gap-3 pt-2 border-t border-cyber-border/40 flex-wrap">
          <button
            onClick={() => navigate("/scan-code")}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-cyber-border text-sm text-muted-foreground hover:text-foreground hover:bg-card/50 transition-colors"
          >
            <ArrowLeft size={14} />
            Nouveau scan
          </button>

          {sastOn && (
            <button
              onClick={goToSast}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-blue-500/30 bg-blue-500/5 text-sm text-blue-400 hover:bg-blue-500/10 transition-colors"
            >
              <ExternalLink size={14} />
              SAST complet
            </button>
          )}

          {dastOn && (
            <button
              onClick={() => navigate("/dast")}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-red-500/30 bg-red-500/5 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
            >
              <ExternalLink size={14} />
              DAST complet
            </button>
          )}

          {cicdOn && (
            <button
              onClick={() => navigate("/cicd")}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-teal-500/30 bg-teal-500/5 text-sm text-teal-400 hover:bg-teal-500/10 transition-colors"
            >
              <ExternalLink size={14} />
              CI/CD complet
            </button>
          )}

          <button
            onClick={() => navigate("/incidents")}
            className="ml-auto flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-violet hover:bg-cyber-violet-dark text-sm text-white transition-colors"
          >
            Voir les incidents générés <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}