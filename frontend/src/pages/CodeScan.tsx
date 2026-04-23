// ============================================================
// pages/CodeScan.tsx — Version corrigée + auto-start SAST
// ============================================================
import { useState, useCallback, useRef, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  FolderOpen,
  GitBranch,
  Shield,
  Zap,
  ArrowLeft,
  Loader2,
  AlertTriangle,
  Code2,
  Play,
  Upload,
  Globe,
  CheckCircle2,
  X,
  FileArchive,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { cn } from "../lib/utils";
import { sastAPI, cicdAPI } from "../services/api";

type ServiceMode = "sast" | "cicd" | "dast";
type ScanStatus = "idle" | "scanning" | "done" | "error";
type CicdMode = "repo" | "results";
type DastMode = "preset" | "custom" | "upload";
type SastMode = "path" | "upload";

const SERVICES = [
  {
    id: "sast" as ServiceMode,
    title: "Scan Statique (M4)",
    subtitle: "Analyser un dossier local ou un ZIP",
    desc: "Semgrep · Trivy · Gitleaks",
    icon: Shield,
    iconClass: "text-blue-400",
    cardClass: "border-blue-500/30 bg-blue-500/8 hover:bg-blue-500/12",
    activeClass: "border-blue-500 bg-blue-500/15 ring-1 ring-blue-500/30",
    buttonClass: "bg-blue-600 hover:bg-blue-700",
  },
  {
    id: "cicd" as ServiceMode,
    title: "Scan CI/CD (M8)",
    subtitle: "Scanner un repo GitHub ou traiter des résultats pipeline",
    desc: "GitHub · Quality Gate · Pipeline",
    icon: Code2,
    iconClass: "text-teal-400",
    cardClass: "border-teal-500/30 bg-teal-500/8 hover:bg-teal-500/12",
    activeClass: "border-teal-500 bg-teal-500/15 ring-1 ring-teal-500/30",
    buttonClass: "bg-teal-600 hover:bg-teal-700",
  },
  {
    id: "dast" as ServiceMode,
    title: "Scan Dynamique (M5)",
    subtitle: "Tester une cible web déployée",
    desc: "OWASP ZAP · Sandbox isolée",
    icon: Zap,
    iconClass: "text-red-400",
    cardClass: "border-red-500/30 bg-red-500/8 hover:bg-red-500/12",
    activeClass: "border-red-500 bg-red-500/15 ring-1 ring-red-500/30",
    buttonClass: "bg-red-600 hover:bg-red-700",
  },
];

// ── Upload ZIP DAST ─────────────────────────────────────────
async function uploadAndScanDast(file: File): Promise<any> {
  const formData = new FormData();
  formData.append("file", file);

  const apiBase =
    process.env.REACT_APP_API_URL?.replace(/\/$/, "") || "http://localhost:8000/api";

  const res = await fetch(`${apiBase}/dast/start/from-upload`, {
    method: "POST",
    body: formData,
  });

  let payload: any = null;
  try {
    payload = await res.json();
  } catch {
    payload = null;
  }

  if (!res.ok) {
    const msg = payload?.detail || payload?.error || `Erreur HTTP ${res.status}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }

  return payload;
}

// ── Sécurise n'importe quelle valeur pour l'affichage JSX ───
function safeStr(v: any): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

export function CodeScan() {
  const navigate = useNavigate();
  const location = useLocation();

  const autoStartedRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const sastFileInputRef = useRef<HTMLInputElement | null>(null);

  const [service, setService] = useState<ServiceMode>("sast");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [error, setError] = useState("");
  const [result, setResult] = useState<any>(null);

  // SAST
  const [sastMode, setSastMode] = useState<SastMode>("path");
  const [localPath, setLocalPath] = useState("");
  const [projectName, setProjectName] = useState("");
  const [sastFile, setSastFile] = useState<File | null>(null);
  const [isSastDragging, setIsSastDragging] = useState(false);

  // CI/CD
  const [cicdMode, setCicdMode] = useState<CicdMode>("repo");
  const [gitUrl, setGitUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [pipelinePayload, setPipelinePayload] = useState(`{
  "run_id": "run_001",
  "repo": "user/repo",
  "commit_sha": "abc123",
  "decision": "PASS",
  "critical_count": 0,
  "high_count": 2
}`);

  // DAST
  const [dastMode, setDastMode] = useState<DastMode>("preset");
  const [dastTarget, setDastTarget] = useState<"webgoat" | "dvwa">("webgoat");
  const [customTargetUrl, setCustomTargetUrl] = useState("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const currentService = SERVICES.find((s) => s.id === service)!;

  const resetResult = () => {
    setResult(null);
    setError("");
  };

  const canScan = () => {
    if (status === "scanning") return false;

    if (service === "sast") {
      if (sastMode === "path") return localPath.trim().length > 2;
      if (sastMode === "upload") {
        return !!sastFile && sastFile.name.toLowerCase().endsWith(".zip");
      }
    }

    if (service === "dast") {
      if (dastMode === "preset") return true;
      if (dastMode === "custom") {
        return (
          customTargetUrl.startsWith("http://") ||
          customTargetUrl.startsWith("https://")
        );
      }
      if (dastMode === "upload") {
        return !!uploadFile && uploadFile.name.toLowerCase().endsWith(".zip");
      }
    }

    if (service === "cicd") {
      if (cicdMode === "repo") return gitUrl.startsWith("https://github.com/");
      if (cicdMode === "results") return pipelinePayload.trim().length > 2;
    }

    return false;
  };

  const handleScan = useCallback(async () => {
    setStatus("scanning");
    setError("");
    setResult(null);

    try {
      // ── SAST ────────────────────────────────────────────
      if (service === "sast") {
        if (sastMode === "upload" && sastFile) {
          await sastAPI.uploadScan(sastFile, projectName || "scan");
        } else {
          await sastAPI.scanSync(localPath, projectName || "scan");
        }

        navigate("/sast");
        return;
      }

      // ── DAST ────────────────────────────────────────────
      if (service === "dast") {
        const { dastAPI } = await import("../services/api");
        let res: any = null;

        if (dastMode === "preset") {
          res = await dastAPI.startSync({ target: dastTarget, deploy_target: true });
        } else if (dastMode === "custom") {
          res = await dastAPI.startSync({
            target_url: customTargetUrl.trim(),
            deploy_target: false,
          });
        } else if (dastMode === "upload" && uploadFile) {
          res = await uploadAndScanDast(uploadFile);
          if (res && typeof res === "object") res._type = "dast_upload";
        }

        if (dastMode === "upload") {
          setResult(res);
          setStatus("done");
        } else {
          navigate("/dast", { state: { refreshAt: Date.now(), dastResult: res } });
        }
        return;
      }

      // ── CI/CD ───────────────────────────────────────────
      if (service === "cicd") {
        const { cicdAPI } = await import("../services/api");

        if (cicdMode === "repo") {
          await cicdAPI.scanRepo(gitUrl, branch);
        } else {
          await cicdAPI.submitResults(JSON.parse(pipelinePayload));
        }

        navigate("/cicd", { state: { refreshAt: Date.now() } });
        return;
      }
    } catch (e: any) {
      const msg = e?.message || "Erreur lors du scan";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
      setStatus("error");
    }
  }, [
    service,
    sastMode,
    sastFile,
    localPath,
    projectName,
    dastMode,
    dastTarget,
    customTargetUrl,
    uploadFile,
    cicdMode,
    gitUrl,
    branch,
    pipelinePayload,
    navigate,
  ]);

  // ── Auto-start SAST si on arrive depuis /sastscanner ─────
  useEffect(() => {
    const state = location.state as any;
    const shouldAutoStart = !!state?.autoStartSast;

    if (!shouldAutoStart || autoStartedRef.current) return;

    autoStartedRef.current = true;

    setService("sast");
    setSastMode("path");

    if (state?.projectName) setProjectName(state.projectName);
    if (state?.localPath) setLocalPath(state.localPath);

    const delayedStart = async () => {
      const hasUpload = state?.sastFile;
      const hasPath = typeof state?.localPath === "string" && state.localPath.trim().length > 2;

      if (hasUpload) {
        setSastMode("upload");
        setSastFile(state.sastFile);
        return;
      }

      if (hasPath) {
        setStatus("scanning");
        setError("");
        setResult(null);

        try {
          await sastAPI.scanSync(state.localPath, state.projectName || "scan");
          navigate("/sast");
        } catch (e: any) {
          const msg = e?.message || "Erreur lors du scan SAST automatique";
          setError(typeof msg === "string" ? msg : JSON.stringify(msg));
          setStatus("error");
        }
      }
    };

    delayedStart();
  }, [location.state, navigate]);

  // ── Résultat upload DAST ────────────────────────────────
  if (status === "done" && result?._type === "dast_upload") {
    const up = result.uploaded_project || {};
    const phases = result.phases || {};
    const isErr = !!result.error;
    const errMsg = safeStr(result.error);
    const totalVulns = Number(result.total_vulns ?? 0);

    return (
      <div className="p-6 max-w-2xl space-y-4">
        <button
          onClick={() => {
            setStatus("idle");
            resetResult();
          }}
          className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft size={14} /> Nouveau scan
        </button>

        <div
          className={cn(
            "flex items-center gap-3 p-4 rounded-xl border",
            isErr
              ? "border-red-500/30 bg-red-500/8 text-red-300"
              : "border-green-500/30 bg-green-500/8 text-green-300"
          )}
        >
          {isErr ? (
            <AlertTriangle size={18} className="shrink-0" />
          ) : (
            <CheckCircle2 size={18} className="shrink-0" />
          )}
          <div>
            <p className="text-sm font-semibold">
              {isErr
                ? `Erreur : ${errMsg}`
                : `Scan terminé — ${totalVulns} vulnérabilité${
                    totalVulns !== 1 ? "s" : ""
                  } détectée${totalVulns !== 1 ? "s" : ""}`}
            </p>
            {up.target_url && (
              <p className="text-xs opacity-70 mt-0.5 font-mono">{safeStr(up.target_url)}</p>
            )}
          </div>
        </div>

        {!isErr && (
          <Card className="bg-card/50 border-cyber-border">
            <CardContent className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Projet</p>
                  <p className="font-medium">{safeStr(up.filename)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Container</p>
                  <p className="font-mono text-xs text-blue-400">
                    {safeStr(up.container_name)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Image Docker</p>
                  <p className="font-mono text-xs text-violet-400">
                    {safeStr(up.image_name)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Vulnérabilités</p>
                  <p
                    className={cn(
                      "font-bold font-mono text-lg",
                      totalVulns > 0 ? "text-red-400" : "text-green-400"
                    )}
                  >
                    {totalVulns}
                  </p>
                </div>
              </div>

              {Object.keys(phases).length > 0 && (
                <div className="space-y-1 border-t border-cyber-border/30 pt-3">
                  <p className="text-xs text-muted-foreground mb-2">Phases d'exécution</p>
                  {Object.entries(phases).map(([key, phase]: [string, any]) => {
                    const success = phase?.success === true;
                    const label = key.replace(/_/g, " ");
                    const phaseErr = phase?.error ? safeStr(phase.error) : null;
                    const urlCount =
                      typeof phase?.urls_found === "number" ? phase.urls_found : null;
                    const vulnCount =
                      typeof phase?.vuln_count === "number" ? phase.vuln_count : null;

                    return (
                      <div
                        key={key}
                        className="flex items-center gap-2 text-xs py-1.5 border-b border-cyber-border/20 last:border-0"
                      >
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded-full text-[10px] font-medium shrink-0",
                            success
                              ? "bg-green-500/10 text-green-400 border border-green-500/30"
                              : "bg-red-500/10 text-red-400 border border-red-500/30"
                          )}
                        >
                          {success ? "✓" : "✗"}
                        </span>
                        <span className="text-muted-foreground capitalize flex-1">
                          {label}
                        </span>
                        {urlCount !== null && (
                          <span className="text-[10px] text-muted-foreground/60">
                            {urlCount} URLs
                          </span>
                        )}
                        {vulnCount !== null && (
                          <span className="text-[10px] text-amber-400">
                            {vulnCount} vulns
                          </span>
                        )}
                        {phaseErr && (
                          <span className="text-[10px] text-red-400/70 truncate max-w-[180px]">
                            {phaseErr}
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {result.pcap_path && (
                <div className="text-xs text-purple-400 font-mono pt-1">
                  PCAP : {safeStr(result.pcap_path).split("/").pop()}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        <div className="flex gap-3">
          <Button onClick={() => navigate("/dast")} variant="outline" size="sm">
            Voir les preuves DAST
          </Button>
          <Button
            onClick={() => {
              setStatus("idle");
              resetResult();
            }}
            variant="outline"
            size="sm"
          >
            Nouveau scan
          </Button>
        </div>
      </div>
    );
  }

  // ── Formulaire principal ────────────────────────────────
  return (
    <div className="max-w-5xl space-y-6 p-6">
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate("/")}
          className="rounded p-1 text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeft size={16} />
        </button>
        <div>
          <h1 className="text-xl font-bold">Scan Center</h1>
          <p className="text-sm text-muted-foreground">
            Sélectionnez un mode d'analyse puis remplissez le formulaire
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {SERVICES.map((svc) => {
          const Icon = svc.icon;
          const active = service === svc.id;

          return (
            <button
              key={svc.id}
              onClick={() => {
                setService(svc.id);
                setStatus("idle");
                resetResult();
              }}
              className={cn(
                "rounded-2xl border p-5 text-left transition-all",
                active ? svc.activeClass : svc.cardClass
              )}
            >
              <div className="mb-3 flex items-center justify-between">
                <div className={cn("rounded-lg p-2", active ? "bg-white/10" : "bg-black/10")}>
                  <Icon size={18} className={svc.iconClass} />
                </div>
                {active && <Badge variant="secondary">Sélectionné</Badge>}
              </div>
              <h3 className="text-sm font-semibold">{svc.title}</h3>
              <p className="mt-1 text-xs text-muted-foreground">{svc.subtitle}</p>
              <p className="mt-3 text-[11px] text-muted-foreground">{svc.desc}</p>
            </button>
          );
        })}
      </div>

      <Card className="border-cyber-border bg-card/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">
            {service === "sast" && "Configuration du scan statique"}
            {service === "cicd" && "Configuration du scan CI/CD"}
            {service === "dast" && "Configuration du scan dynamique"}
          </CardTitle>
        </CardHeader>

        <CardContent className="space-y-5">
          {service === "sast" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                {[
                  {
                    id: "path" as SastMode,
                    label: "Chemin serveur",
                    icon: <FolderOpen size={16} className="text-blue-400" />,
                    desc: "Dossier accessible côté backend",
                  },
                  {
                    id: "upload" as SastMode,
                    label: "Upload ZIP",
                    icon: <FileArchive size={16} className="text-blue-400" />,
                    desc: "Importer un projet depuis le navigateur",
                  },
                ].map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setSastMode(m.id)}
                    className={cn(
                      "rounded-xl border p-4 text-left transition-all",
                      sastMode === m.id
                        ? "border-blue-500 bg-blue-500/15"
                        : "border-blue-500/30 bg-blue-500/8 hover:bg-blue-500/12"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {m.icon}
                      <span className="text-sm font-semibold">{m.label}</span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{m.desc}</p>
                  </button>
                ))}
              </div>

              <div>
                <label className="mb-1.5 block text-xs text-muted-foreground">
                  Nom du projet
                </label>
                <input
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  placeholder="mon-projet"
                  className="w-full rounded-lg border border-cyber-border bg-card/30 px-3 py-2 text-sm focus:border-blue-500/50 focus:outline-none"
                />
              </div>

              {sastMode === "path" && (
                <div>
                  <label className="mb-1.5 block text-xs text-muted-foreground">
                    Dossier local à analyser
                  </label>
                  <div className="relative">
                    <FolderOpen
                      size={13}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                    />
                    <input
                      value={localPath}
                      onChange={(e) => setLocalPath(e.target.value)}
                      placeholder="/app/project"
                      className="w-full rounded-lg border border-cyber-border bg-card/30 py-2 pl-8 pr-3 text-sm font-mono focus:border-blue-500/50 focus:outline-none"
                    />
                  </div>
                  <p className="mt-1.5 text-xs text-muted-foreground">
                    Ce chemin doit exister côté backend FastAPI.
                  </p>
                </div>
              )}

              {sastMode === "upload" && (
                <div className="space-y-3">
                  <input
                    ref={sastFileInputRef}
                    type="file"
                    accept=".zip"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) setSastFile(f);
                    }}
                  />

                  <div
                    onClick={() => sastFileInputRef.current?.click()}
                    onDragOver={(e) => {
                      e.preventDefault();
                      setIsSastDragging(true);
                    }}
                    onDragLeave={() => setIsSastDragging(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setIsSastDragging(false);
                      const f = e.dataTransfer.files?.[0];
                      if (f) setSastFile(f);
                    }}
                    className={cn(
                      "cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-all",
                      isSastDragging
                        ? "border-blue-500/70 bg-blue-500/8"
                        : sastFile
                        ? "border-green-500/50 bg-green-500/5"
                        : "border-cyber-border/40 hover:border-blue-500/40"
                    )}
                  >
                    {sastFile ? (
                      <div className="flex items-center justify-center gap-3">
                        <CheckCircle2 size={18} className="text-green-400" />
                        <div className="text-left">
                          <p className="text-sm font-medium text-green-300">
                            {sastFile.name}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {(sastFile.size / 1024).toFixed(0)} KB
                          </p>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSastFile(null);
                            if (sastFileInputRef.current) {
                              sastFileInputRef.current.value = "";
                            }
                          }}
                          className="ml-2 text-muted-foreground hover:text-foreground"
                        >
                          <X size={14} />
                        </button>
                      </div>
                    ) : (
                      <>
                        <Upload size={22} className="mx-auto mb-3 text-blue-400/60" />
                        <p className="text-sm font-medium text-blue-300/80">
                          Glissez votre projet ZIP ici
                        </p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          ZIP uniquement · cliquez pour parcourir
                        </p>
                      </>
                    )}
                  </div>
                </div>
              )}
            </>
          )}

          {service === "cicd" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                {[
                  {
                    id: "repo" as CicdMode,
                    label: "Repo GitHub",
                    icon: <GitBranch size={16} className="text-teal-400" />,
                    desc: "Cloner et scanner un dépôt",
                  },
                  {
                    id: "results" as CicdMode,
                    label: "Résultats pipeline",
                    icon: <Upload size={16} className="text-teal-400" />,
                    desc: "Envoyer un JSON depuis un pipeline",
                  },
                ].map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setCicdMode(m.id)}
                    className={cn(
                      "rounded-xl border p-4 text-left transition-all",
                      cicdMode === m.id
                        ? "border-teal-500 bg-teal-500/15"
                        : "border-teal-500/30 bg-teal-500/8 hover:bg-teal-500/12"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {m.icon}
                      <span className="text-sm font-semibold">{m.label}</span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{m.desc}</p>
                  </button>
                ))}
              </div>

              {cicdMode === "repo" && (
                <>
                  <div>
                    <label className="mb-1.5 block text-xs text-muted-foreground">
                      URL GitHub
                    </label>
                    <div className="relative">
                      <GitBranch
                        size={13}
                        className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                      />
                      <input
                        value={gitUrl}
                        onChange={(e) => setGitUrl(e.target.value)}
                        placeholder="https://github.com/org/repo"
                        className="w-full rounded-lg border border-cyber-border bg-card/30 py-2 pl-8 pr-3 text-sm font-mono focus:border-teal-500/50 focus:outline-none"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="mb-1.5 block text-xs text-muted-foreground">
                      Branche
                    </label>
                    <input
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                      placeholder="main"
                      className="w-full rounded-lg border border-cyber-border bg-card/30 px-3 py-2 text-sm font-mono focus:border-teal-500/50 focus:outline-none"
                    />
                  </div>
                </>
              )}

              {cicdMode === "results" && (
                <div>
                  <label className="mb-1.5 block text-xs text-muted-foreground">
                    Payload JSON pipeline
                  </label>
                  <textarea
                    value={pipelinePayload}
                    onChange={(e) => setPipelinePayload(e.target.value)}
                    rows={12}
                    className="w-full rounded-lg border border-cyber-border bg-card/30 px-3 py-3 text-sm font-mono focus:border-teal-500/50 focus:outline-none"
                  />
                </div>
              )}
            </>
          )}

          {service === "dast" && (
            <>
              <div className="grid grid-cols-3 gap-3">
                {[
                  {
                    id: "preset" as DastMode,
                    label: "Cible prédéfinie",
                    icon: <Zap size={16} className="text-red-400" />,
                    desc: "WebGoat ou DVWA dans la sandbox",
                  },
                  {
                    id: "custom" as DastMode,
                    label: "Cible personnalisée",
                    icon: <Globe size={16} className="text-red-400" />,
                    desc: "URL d'une app déjà déployée",
                  },
                  {
                    id: "upload" as DastMode,
                    label: "Upload projet",
                    icon: <FileArchive size={16} className="text-red-400" />,
                    desc: "ZIP → build → scan → teardown",
                  },
                ].map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setDastMode(m.id)}
                    className={cn(
                      "rounded-xl border p-4 text-left transition-all",
                      dastMode === m.id
                        ? "border-red-500 bg-red-500/15"
                        : "border-red-500/30 bg-red-500/8 hover:bg-red-500/12"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {m.icon}
                      <span className="text-sm font-semibold">{m.label}</span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{m.desc}</p>
                  </button>
                ))}
              </div>

              {dastMode === "preset" && (
                <div className="grid grid-cols-2 gap-3">
                  {(["webgoat", "dvwa"] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setDastTarget(t)}
                      className={cn(
                        "rounded-xl border p-4 text-left transition-all",
                        dastTarget === t
                          ? "border-red-500 bg-red-500/15"
                          : "border-red-500/30 bg-red-500/8 hover:bg-red-500/12"
                      )}
                    >
                      <p className="text-sm font-semibold text-red-300">
                        {t === "webgoat" ? "WebGoat" : "DVWA"}
                      </p>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        {t === "webgoat"
                          ? "Application OWASP volontairement vulnérable"
                          : "Damn Vulnerable Web App"}
                      </p>
                    </button>
                  ))}
                </div>
              )}

              {dastMode === "custom" && (
                <div>
                  <label className="mb-1.5 block text-xs text-muted-foreground">
                    URL cible
                  </label>
                  <input
                    value={customTargetUrl}
                    onChange={(e) => setCustomTargetUrl(e.target.value)}
                    placeholder="http://cybersentinel_monapp:8080"
                    className="w-full rounded-lg border border-cyber-border bg-card/30 px-3 py-2 text-sm font-mono focus:border-red-500/50 focus:outline-none"
                  />
                  <p className="mt-1.5 text-xs text-muted-foreground">
                    Application déployée dans votre réseau sandbox.
                  </p>
                </div>
              )}

              {dastMode === "upload" && (
                <div className="space-y-3">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".zip"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) setUploadFile(f);
                    }}
                  />

                  <div
                    onClick={() => fileInputRef.current?.click()}
                    onDragOver={(e) => {
                      e.preventDefault();
                      setIsDragging(true);
                    }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setIsDragging(false);
                      const f = e.dataTransfer.files?.[0];
                      if (f) setUploadFile(f);
                    }}
                    className={cn(
                      "cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-all",
                      isDragging
                        ? "border-red-500/70 bg-red-500/8"
                        : uploadFile
                        ? "border-green-500/50 bg-green-500/5"
                        : "border-cyber-border/40 hover:border-red-500/40"
                    )}
                  >
                    {uploadFile ? (
                      <div className="flex items-center justify-center gap-3">
                        <CheckCircle2 size={18} className="text-green-400" />
                        <div className="text-left">
                          <p className="text-sm font-medium text-green-300">
                            {uploadFile.name}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {(uploadFile.size / 1024).toFixed(0)} KB
                          </p>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setUploadFile(null);
                            if (fileInputRef.current) fileInputRef.current.value = "";
                          }}
                          className="ml-2 text-muted-foreground hover:text-foreground"
                        >
                          <X size={14} />
                        </button>
                      </div>
                    ) : (
                      <>
                        <Upload size={22} className="mx-auto mb-3 text-red-400/60" />
                        <p className="text-sm font-medium text-red-300/80">
                          Glissez votre projet ZIP ici
                        </p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          ZIP uniquement · cliquez pour parcourir
                        </p>
                      </>
                    )}
                  </div>

                  <div className="rounded-lg border border-cyber-border bg-card/50 p-3">
                    <p className="mb-2 text-xs font-medium text-muted-foreground">
                      Stacks supportées (V1)
                    </p>
                    <div className="grid grid-cols-2 gap-1.5">
                      {[
                        { label: "Spring Boot", port: "8080" },
                        { label: "Node/Express", port: "3000" },
                        { label: "Python Flask/FastAPI", port: "8000" },
                        { label: "PHP Apache", port: "80" },
                      ].map((s) => (
                        <div
                          key={s.label}
                          className="flex items-center gap-2 text-xs text-muted-foreground"
                        >
                          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-green-500/60" />
                          <span>{s.label}</span>
                          <span className="font-mono text-[10px] opacity-60">
                            :{s.port}
                          </span>
                        </div>
                      ))}
                    </div>
                    <p className="mt-2 text-[10px] text-muted-foreground/60">
                      L'application doit démarrer seule sans dépendances externes.
                    </p>
                  </div>

                  <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-500/8 border border-amber-500/20 text-xs text-amber-400">
                    <AlertTriangle size={12} className="shrink-0" />
                    Build Docker + ZAP active scan — peut prendre 5 à 15 minutes
                  </div>
                </div>
              )}

              {dastMode !== "upload" && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-500/8 border border-amber-500/20 text-xs text-amber-400">
                  <AlertTriangle size={12} className="shrink-0" />
                  Sandbox isolée activée — contrainte C-05 (internal:true)
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {status === "error" && error && (
        <div className="flex items-center gap-3 rounded-xl border border-red-500/30 bg-red-500/8 p-4 text-red-300">
          <AlertTriangle size={16} className="shrink-0" />
          <p className="text-sm">{error}</p>
        </div>
      )}

      <Button
        onClick={handleScan}
        disabled={!canScan() || status === "scanning"}
        className={cn(
          "h-11 w-full gap-2 text-sm font-semibold text-white",
          currentService.buttonClass
        )}
      >
        {status === "scanning" ? (
          <>
            <Loader2 size={16} className="animate-spin" />
            {service === "dast" && dastMode === "upload"
              ? "Build + scan en cours... (5-15 min)"
              : service === "sast" && sastMode === "upload"
              ? "Upload + scan SAST en cours..."
              : "Scan en cours..."}
          </>
        ) : (
          <>
            <Play size={16} />
            Lancer {currentService.title}
          </>
        )}
      </Button>

      {status === "idle" && (
        <p className="text-center text-xs text-muted-foreground">
          {service === "sast" && "Semgrep + Trivy + Gitleaks · 1-5 min"}
          {service === "cicd" && "Clone + SAST + Quality Gate · asynchrone"}
          {service === "dast" &&
            dastMode === "preset" &&
            "OWASP ZAP · 6 phases · 10-20 min"}
          {service === "dast" &&
            dastMode === "custom" &&
            "OWASP ZAP sur votre app · 10-20 min"}
          {service === "dast" &&
            dastMode === "upload" &&
            "Upload → build Docker → ZAP → teardown · 5-15 min"}
        </p>
      )}
    </div>
  );
}

export default CodeScan;