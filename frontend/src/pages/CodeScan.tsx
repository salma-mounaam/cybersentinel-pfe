// ============================================================
// pages/CodeScan.tsx
// Sources : ZIP upload + Repo GitHub + Image Docker
// FIX : status reset propre, setStatus("idle") dans finally
// ============================================================
import { useState, useCallback, useRef, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  GitBranch,
  Shield,
  Zap,
  ArrowLeft,
  Loader2,
  AlertTriangle,
  Code2,
  Play,
  Upload,
  CheckCircle2,
  X,
  Container,
  BrainCircuit,
} from "lucide-react";
import { cn } from "../lib/utils";
import { sastAPI, dastAPI, cicdAPI } from "../services/api";

type SourceMode = "zip" | "git" | "image";
type ScanStatus = "idle" | "scanning" | "error";

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

export function CodeScan() {
  const navigate = useNavigate();
  const location = useLocation();
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [sourceMode, setSourceMode] = useState<SourceMode>("zip");
  const [projectName, setProjectName] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [gitUrl, setGitUrl] = useState("");
  const [gitBranch, setGitBranch] = useState("main");
  const [isDragging, setIsDragging] = useState(false);

  // ── Mode Image Docker ──────────────────────────────────────
  const [dockerImage,      setDockerImage]      = useState("");
  const [dockerPort,       setDockerPort]       = useState("3000");
  const [dockerHealthPath, setDockerHealthPath] = useState("/");

  const [sastOn, setSastOn] = useState(true);
  const [dastOn, setDastOn] = useState(false);
  const [cicdOn, setCicdOn] = useState(false);

  const [status, setStatus] = useState<ScanStatus>("idle");
  const [error, setError]   = useState("");

  const canScan = (): boolean => {
    if (status === "scanning") return false;
    if (!sastOn && !dastOn && !cicdOn) return false;

    if (sourceMode === "zip")   return !!zipFile && zipFile.name.toLowerCase().endsWith(".zip");
    if (sourceMode === "git")   return gitUrl.startsWith("https://github.com/");
    if (sourceMode === "image") return dockerImage.trim().length > 0;

    return false;
  };

  const handleScan = useCallback(async () => {
    setStatus("scanning");
    setError("");

    const _sastOn           = sastOn;
    const _dastOn           = dastOn;
    const _cicdOn           = cicdOn;
    const _sourceMode       = sourceMode;
    const _zipFile          = zipFile;
    const _projectName      = projectName;
    const _gitUrl           = gitUrl;
    const _gitBranch        = gitBranch;
    const _dockerImage      = dockerImage.trim();
    const _dockerPort       = parseInt(dockerPort) || 3000;
    const _dockerHealthPath = dockerHealthPath || "/";

    const goToResults = (dastResult?: any, sastScanId?: string | null) => {
      navigate("/scan-results", {
        state: {
          sastOn:      _sastOn,
          dastOn:      _dastOn,
          cicdOn:      _cicdOn,
          projectName: _projectName || _dockerImage,
          sourceMode:  _sourceMode,
          dastResult,
          sastScanId,
        },
      });
    };

    try {
      let sastScanId: string | null = null;

      // ── SAST : ZIP ou Git uniquement ──────────────────────
      if (_sastOn && _sourceMode !== "image") {
        let scanResult: any = null;

        if (_sourceMode === "zip" && _zipFile) {
          scanResult = await sastAPI.uploadScan(_zipFile, _projectName || "scan");
        } else if (_sourceMode === "git") {
          const repoName =
            _projectName ||
            _gitUrl.split("/").pop()?.replace(".git", "") ||
            "scan";

          const repoResult = await cicdAPI.scanRepo(_gitUrl, _gitBranch);

          scanResult =
            repoResult?.sast_scan ||
            repoResult?.sast_result ||
            null;

          if (!scanResult?.scan_id && !scanResult?.scanId && repoResult?.sast_scan_id) {
            scanResult = { scan_id: repoResult.sast_scan_id };
          }

          if (!scanResult?.scan_id && !scanResult?.scanId) {
            for (let i = 0; i < 60; i++) {
              const latest = await sastAPI.getLatestScan({ repo_name: repoName });
              if (latest?.scan_id) { scanResult = latest; break; }
              await new Promise((resolve) => setTimeout(resolve, 2000));
            }
          }
        }

        sastScanId = scanResult?.scan_id ?? scanResult?.scanId ?? null;
      }

      if (_cicdOn && !_sastOn && _sourceMode === "git") {
        await cicdAPI.scanRepo(_gitUrl, _gitBranch);
      }

      // ── DAST ──────────────────────────────────────────────
      if (_dastOn) {
        let dastRes: any = null;

        if (_sourceMode === "image") {
          dastRes = await dastAPI.startFromImage({
            image:            _dockerImage,
            port:             _dockerPort,
            healthcheck_path: _dockerHealthPath,
            scan_profile:     "baseline",
          });
        } else if (_sourceMode === "zip" && _zipFile) {
          dastRes = await uploadAndScanDast(_zipFile);
        } else if (_sourceMode === "git") {
          const repoName =
            _gitUrl.split("/").pop()?.replace(".git", "") || "target";

          dastRes = await dastAPI.startFromGit({
            repo_url:     _gitUrl.trim(),
            branch:       _gitBranch || "main",
            project_name: _projectName || repoName,
          });
        } else {
          throw new Error("Mode DAST non supporté");
        }

        goToResults(dastRes, sastScanId);
        return;
      }

      goToResults(undefined, sastScanId);
    } catch (e: any) {
      console.error("[CodeScan] ERREUR scan:", e);
      const msg = e?.message || "Erreur lors du scan";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
      setStatus("error");
    }
    // NOTE : pas de finally setStatus("idle") car navigate() démonte le composant.
    // Le status "scanning" est réinitialisé par le catch en cas d'erreur.
  }, [
    sastOn, dastOn, cicdOn,
    sourceMode, zipFile, projectName,
    gitUrl, gitBranch,
    dockerImage, dockerPort, dockerHealthPath,
    navigate,
  ]);

  useEffect(() => {
    const state = location.state as any;
    if (!state?.autoStartSast) return;
    console.warn("[CodeScan] autoStartSast ignoré : mode 'path' supprimé");
  }, [location.state]);

  // Reset status si on change de mode pendant un scan en erreur
  useEffect(() => {
    if (status === "error") {
      setStatus("idle");
      setError("");
    }
  }, [sourceMode]); // eslint-disable-line react-hooks/exhaustive-deps

  const activeModules = [
    sastOn && "SAST",
    dastOn && "DAST",
    cicdOn && "CI/CD",
  ].filter(Boolean) as string[];

  const launchLabel =
    activeModules.length > 0 ? "Lancer le scan" : "Choisir un module";

  const durationHint = [
    sastOn && sourceMode !== "image" && "Semgrep · Trivy · Gitleaks · 1–5 min",
    dastOn && sourceMode === "image" && "Trivy image + OWASP ZAP · 10–20 min",
    dastOn && sourceMode !== "image" && "OWASP ZAP · sandbox isolée · 10–20 min",
    cicdOn && "Quality Gate · blocage PR critiques",
  ]
    .filter(Boolean)
    .join("  ·  ");

  const sourceHints: Record<SourceMode, string> = {
    zip:   "ZIP uniquement · Spring Boot, Node, Flask, PHP supportés",
    git:   "Le repo sera cloné et analysé par le backend",
    image: "Image Docker pré-buildée · Trivy scan + OWASP ZAP · sandbox isolée",
  };

  const launchColorClass = canScan()
    ? sourceMode === "image"
      ? "bg-violet-600 hover:bg-violet-700 text-white"
      : dastOn && sastOn
      ? "bg-purple-600 hover:bg-purple-700 text-white"
      : dastOn
      ? "bg-red-600 hover:bg-red-700 text-white"
      : cicdOn && !sastOn
      ? "bg-teal-600 hover:bg-teal-700 text-white"
      : "bg-blue-600 hover:bg-blue-700 text-white"
    : "bg-card text-muted-foreground cursor-not-allowed";

  return (
    <div className="flex flex-col items-center w-full px-8 py-10">
      <div className="w-full max-w-5xl space-y-8">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate("/")}
            className="rounded p-1 text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft size={16} />
          </button>

          <div>
            <h1 className="text-2xl font-semibold">Scan Center</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Importez votre projet, lancez SAST/DAST, puis expliquez les vulnérabilités avec LLM
            </p>
          </div>
        </div>

        <div className="rounded-xl border border-cyber-border bg-card/50 overflow-hidden">
          <div className="flex items-stretch h-14 border-b border-cyber-border/60">

            {/* Sélecteur source */}
            <select
              value={sourceMode}
              onChange={(e) => {
                setSourceMode(e.target.value as SourceMode);
                setZipFile(null);
              }}
              className="h-full bg-card border-r border-cyber-border/60 px-4 text-sm text-foreground font-mono cursor-pointer outline-none focus:bg-card/80 shrink-0"
              style={{ minWidth: "180px" }}
            >
              <option value="zip">Upload ZIP</option>
              <option value="git">Repo GitHub</option>
              <option value="image">🐳 Image Docker</option>
            </select>

            {/* Zone saisie selon mode */}
            <div className="flex-1 flex items-center min-w-0">

              {/* Mode ZIP */}
              {sourceMode === "zip" && (
                <div className="flex-1 flex items-center gap-3 px-4">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".zip"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) setZipFile(f);
                    }}
                  />

                  {zipFile ? (
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      <CheckCircle2 size={15} className="text-green-400 shrink-0" />
                      <span className="text-sm font-mono text-green-300 truncate">
                        {zipFile.name}
                      </span>
                      <span className="text-xs text-muted-foreground shrink-0">
                        {(zipFile.size / 1024).toFixed(0)} KB
                      </span>
                      <button
                        onClick={() => {
                          setZipFile(null);
                          if (fileInputRef.current) fileInputRef.current.value = "";
                        }}
                        className="ml-auto text-muted-foreground hover:text-foreground shrink-0"
                      >
                        <X size={13} />
                      </button>
                    </div>
                  ) : (
                    <>
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="shrink-0 px-3 py-1.5 rounded border border-cyber-border text-xs text-muted-foreground hover:text-foreground hover:bg-card transition-colors"
                      >
                        Parcourir
                      </button>
                      <span className="text-sm text-muted-foreground/50 font-mono truncate">
                        Aucun fichier sélectionné
                      </span>
                    </>
                  )}
                </div>
              )}

              {/* Mode Git */}
              {sourceMode === "git" && (
                <div className="flex-1 flex items-center gap-3 px-4">
                  <GitBranch size={15} className="text-muted-foreground shrink-0" />
                  <input
                    value={gitUrl}
                    onChange={(e) => setGitUrl(e.target.value)}
                    placeholder="https://github.com/org/repo"
                    className="flex-1 bg-transparent text-sm font-mono outline-none placeholder:text-muted-foreground/50"
                  />

                  <div className="flex items-center gap-2 shrink-0 border-l border-cyber-border/40 pl-4">
                    <span className="text-xs text-muted-foreground">branche</span>
                    <input
                      value={gitBranch}
                      onChange={(e) => setGitBranch(e.target.value)}
                      className="w-20 bg-transparent text-sm font-mono outline-none text-foreground"
                    />
                  </div>
                </div>
              )}

              {/* Mode Image Docker */}
              {sourceMode === "image" && (
                <div className="flex-1 flex items-center gap-3 px-4">
                  <Container size={15} className="text-violet-400 shrink-0" />
                  <input
                    value={dockerImage}
                    onChange={(e) => setDockerImage(e.target.value)}
                    placeholder="cybersentinel-juiceshop:scan"
                    className="flex-1 bg-transparent text-sm font-mono outline-none placeholder:text-muted-foreground/50 text-violet-300"
                  />

                  <div className="flex items-center gap-2 shrink-0 border-l border-cyber-border/40 pl-4">
                    <span className="text-xs text-muted-foreground">port</span>
                    <input
                      value={dockerPort}
                      onChange={(e) => setDockerPort(e.target.value)}
                      type="number"
                      className="w-16 bg-transparent text-sm font-mono outline-none text-foreground"
                    />
                  </div>

                  <div className="flex items-center gap-2 shrink-0 border-l border-cyber-border/40 pl-4">
                    <span className="text-xs text-muted-foreground">healthcheck</span>
                    <input
                      value={dockerHealthPath}
                      onChange={(e) => setDockerHealthPath(e.target.value)}
                      className="w-16 bg-transparent text-sm font-mono outline-none text-foreground"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="w-px bg-cyber-border/60 self-stretch" />

            {/* Toggles modules */}
            <div className="flex items-center gap-2 px-4 shrink-0">
              {[
                {
                  key:         "sast",
                  on:          sastOn,
                  set:         setSastOn,
                  icon:        <Shield size={14} />,
                  label:       "SAST",
                  activeClass: "bg-blue-500/15 text-blue-400 border-blue-500/30",
                  disabled:    sourceMode === "image",
                },
                {
                  key:         "dast",
                  on:          dastOn,
                  set:         setDastOn,
                  icon:        <Zap size={14} />,
                  label:       "DAST",
                  activeClass: "bg-red-500/15 text-red-400 border-red-500/30",
                  disabled:    false,
                },
                {
                  key:         "cicd",
                  on:          cicdOn,
                  set:         setCicdOn,
                  icon:        <Code2 size={14} />,
                  label:       "CI/CD",
                  activeClass: "bg-teal-500/15 text-teal-400 border-teal-500/30",
                  disabled:    sourceMode === "image",
                },
              ].map(({ key, on, set, icon, label, activeClass, disabled }) => (
                <button
                  key={key}
                  onClick={() => !disabled && set(!on)}
                  disabled={disabled}
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all border",
                    disabled
                      ? "opacity-30 cursor-not-allowed text-muted-foreground border-transparent"
                      : on
                      ? activeClass
                      : "text-muted-foreground border-transparent hover:border-cyber-border hover:text-foreground"
                  )}
                >
                  {icon}
                  {label}
                </button>
              ))}
            </div>

            <div className="w-px bg-cyber-border/60 self-stretch" />

            {/* Bouton lancer */}
            <button
              onClick={handleScan}
              disabled={!canScan()}
              className={cn(
                "flex items-center gap-2 px-7 text-sm font-semibold transition-all shrink-0 h-full whitespace-nowrap",
                launchColorClass
              )}
            >
              {status === "scanning" ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <Play size={15} />
              )}
              {status === "scanning" ? "Scan en cours..." : launchLabel}
            </button>
          </div>

          {/* Hints bas de barre */}
          <div className="px-5 py-3 flex items-center justify-between gap-4">
            <p className="text-xs text-muted-foreground">{sourceHints[sourceMode]}</p>
            {durationHint && (
              <p className="text-xs text-muted-foreground shrink-0">{durationHint}</p>
            )}
          </div>

          {/* Avertissement DAST sandbox (mode Git ou ZIP) — sans WebGoat/DVWA */}
          {dastOn && sourceMode !== "image" && (
            <div className="px-5 pb-4 border-t border-cyber-border/40 pt-4 flex items-center gap-2 text-xs text-amber-400/80">
              <AlertTriangle size={12} />
              OWASP ZAP · Sandbox isolée · contrainte C-05
            </div>
          )}

          {/* Info mode Image Docker */}
          {sourceMode === "image" && (
            <div className="px-5 pb-4 border-t border-cyber-border/40 pt-4">
              <div className="flex items-start gap-2 text-xs text-violet-400/80">
                <Container size={13} className="shrink-0 mt-0.5" />
                <div>
                  <span className="font-medium">Mode Production — Image Docker pré-buildée</span>
                  <span className="text-muted-foreground ml-2">
                    Workflow : Trivy image scan → déploiement sandbox-net → OWASP ZAP → teardown
                  </span>
                  <div className="mt-1 font-mono text-muted-foreground/60 text-[10px]">
                    Commande : <code>docker build -t {dockerImage || "mon-app:scan"} .</code>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Zone drag & drop ZIP */}
          {sourceMode === "zip" && !zipFile && (
            <div
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                const f = e.dataTransfer.files?.[0];
                if (f) setZipFile(f);
              }}
              className={cn(
                "mx-5 mb-4 cursor-pointer rounded-lg border-2 border-dashed p-8 text-center transition-all",
                isDragging
                  ? "border-blue-500/60 bg-blue-500/8"
                  : "border-cyber-border/40 hover:border-cyber-border"
              )}
            >
              <Upload size={20} className="mx-auto mb-2 text-muted-foreground/40" />
              <p className="text-sm text-muted-foreground">
                Glissez votre projet ZIP ici
              </p>
              <p className="text-xs text-muted-foreground/60 mt-1">
                Spring Boot · Node · Flask/FastAPI · PHP Apache
              </p>
            </div>
          )}
        </div>

        {/* Nom du projet */}
        {(sastOn || dastOn) && sourceMode !== "image" && (
          <div className="flex items-center gap-3">
            <label className="text-sm text-muted-foreground shrink-0">
              Nom du projet
            </label>
            <input
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="mon-projet"
              className="w-56 rounded-lg border border-cyber-border bg-card/30 px-3 py-2 text-sm font-mono focus:border-blue-500/50 focus:outline-none"
            />
          </div>
        )}

        {/* Cartes modules actifs */}
        {activeModules.length > 0 && (
          <div
            className={cn(
              "grid gap-4",
              activeModules.length === 1
                ? "grid-cols-1 max-w-sm"
                : activeModules.length === 2
                ? "grid-cols-2"
                : "grid-cols-3"
            )}
          >
            {sastOn && sourceMode !== "image" && (
              <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Shield size={15} className="text-blue-400" />
                  <span className="text-sm font-medium text-blue-400">Scan statique</span>
                  <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/20">
                    M4
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">Semgrep · Trivy · Gitleaks</p>
                <p className="text-xs text-muted-foreground mt-1">SARIF · MITRE ATT&CK mapping</p>
              </div>
            )}

            {dastOn && sourceMode === "image" && (
              <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Container size={15} className="text-violet-400" />
                  <span className="text-sm font-medium text-violet-400">Scan image Docker</span>
                  <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/20">
                    M5
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">Trivy · OWASP ZAP · 6 phases</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Image : <span className="font-mono text-violet-400">{dockerImage || "—"}</span>
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  Port : <span className="font-mono">{dockerPort}</span>
                  {" "}· Healthcheck : <span className="font-mono">{dockerHealthPath}</span>
                </p>
              </div>
            )}

            {dastOn && sourceMode !== "image" && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Zap size={15} className="text-red-400" />
                  <span className="text-sm font-medium text-red-400">Scan dynamique</span>
                  <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">
                    M5
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">OWASP ZAP · 6 phases</p>
                <p className="text-xs text-muted-foreground mt-1">Proof-of-exploit · PCAP labelisé</p>
              </div>
            )}

            {cicdOn && (
              <div className="rounded-xl border border-teal-500/20 bg-teal-500/5 p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Code2 size={15} className="text-teal-400" />
                  <span className="text-sm font-medium text-teal-400">Pipeline CI/CD</span>
                  <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-teal-500/15 text-teal-400 border border-teal-500/20">
                    M8
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">GitHub Actions · Quality Gate</p>
                <p className="text-xs text-muted-foreground mt-1">Blocage automatique PR critiques</p>
              </div>
            )}
          </div>
        )}

        {(sastOn || dastOn) && (
          <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-5">
            <div className="flex items-center gap-2 mb-2">
              <BrainCircuit size={15} className="text-purple-400" />
              <span className="text-sm font-medium text-purple-400">Assistant LLM vulnérabilités</span>
              <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/20">
                SAST + DAST
              </span>
            </div>
            <p className="text-xs text-muted-foreground">
              Après le scan, chaque finding peut être expliqué : résumé simple, impact, preuve, priorité et correction recommandée.
            </p>
          </div>
        )}

        {/* Bandeau erreur */}
        {status === "error" && error && (
          <div className="flex items-center gap-3 rounded-xl border border-red-500/30 bg-red-500/8 p-4 text-red-300">
            <AlertTriangle size={16} className="shrink-0" />
            <p className="text-sm">{error}</p>
            <button
              onClick={() => { setError(""); setStatus("idle"); }}
              className="ml-auto text-red-300/60 hover:text-red-300"
            >
              <X size={14} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default CodeScan;