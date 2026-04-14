// ============================================================
// pages/DASTSandbox.tsx — Version corrigée (React #185 fix)
// M5 · OWASP ZAP · 6 phases · upload ZIP · sandbox-net
// ============================================================
import React, { useState, useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import { dastAPI } from "../services/api";
import { PageHeader, KPICard, SectionTitle } from "../components/common";

const PHASE_LABELS = [
  "1. Déploiement",
  "2. Spider",
  "3. Injection active",
  "4. Capture PCAP",
  "5. Preuves exploit",
  "6. Teardown",
];

const PHASE_KEYS = [
  "1_deploy",
  "2_spider",
  "3_inject",
  "4_capture",
  "5_proofs",
  "6_teardown",
];

type DastMode = "preset" | "custom" | "upload";

// ── Sécurise toute valeur pour affichage JSX ────────────────
function safeStr(v: any): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string")  return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

function safePcapName(pcap_path: any): string {
  const s = safeStr(pcap_path);
  if (s === "—") return "—";
  const parts = s.split("/");
  return parts[parts.length - 1] || s;
}

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
  try { payload = await res.json(); } catch { payload = null; }

  if (!res.ok) {
    const msg = payload?.detail || payload?.error || `Erreur HTTP ${res.status}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return payload;
}

export default function DASTSandbox() {
  const location = useLocation();
  const navState = location.state as { refreshAt?: number; dastResult?: any } | null;

  const [status,   setStatus]   = useState<any>(null);
  const [findings, setFindings] = useState<any>(null);
  const [isoCheck, setIsoCheck] = useState<any>(null);

  const [mode,            setMode]            = useState<DastMode>("preset");
  const [target,          setTarget]          = useState<"webgoat"|"dvwa">("webgoat");
  const [customTargetUrl, setCustomTargetUrl] = useState("");
  const [uploadFile,      setUploadFile]      = useState<File | null>(null);
  const [isDragging,      setIsDragging]      = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [running, setRunning] = useState(false);
  const [result,  setResult]  = useState<any>(navState?.dastResult || null);

  const refreshData = async () => {
    try {
      const [s, f] = await Promise.all([
        dastAPI.getStatus(),
        dastAPI.getFindings(20),
      ]);
      setStatus(s);
      setFindings(f);
    } catch (e) {
      console.error("Refresh DAST:", e);
    }
  };

  useEffect(() => { refreshData(); }, []);

  useEffect(() => {
    if (navState?.dastResult) setResult(navState.dastResult);
    refreshData();
  }, [location.key]);

  useEffect(() => {
    const id = setInterval(refreshData, 5000);
    return () => clearInterval(id);
  }, []);

  const checkIso = async () => {
    try {
      const r = await dastAPI.verifyIsolation();
      setIsoCheck(r);
    } catch (e: any) {
      setIsoCheck({
        ca09_passed: false,
        message: "Erreur pendant la vérification",
        error: String(e?.message || e),
      });
    }
  };

  const startScan = async () => {
    setRunning(true);
    setResult(null);
    try {
      let r: any = null;
      if (mode === "preset") {
        r = await dastAPI.startSync({ target, deploy_target: true });
      } else if (mode === "custom") {
        r = await dastAPI.startSync({ target_url: customTargetUrl.trim(), deploy_target: false });
      } else if (mode === "upload" && uploadFile) {
        r = await uploadAndScanDast(uploadFile);
      }
      setResult(r);
      await refreshData();
    } catch (e: any) {
      setResult({ error: String(e?.message || e) });
    } finally {
      setRunning(false);
    }
  };

  const canStart =
    !running && !status?.active && (
      mode === "preset" ||
      (mode === "custom" && (
        customTargetUrl.startsWith("http://") || customTargetUrl.startsWith("https://")
      )) ||
      (mode === "upload" && !!uploadFile && uploadFile.name.toLowerCase().endsWith(".zip"))
    );

  const uploadedProject = result?.uploaded_project || null;

  return (
    <div>
      <PageHeader
        title="DAST Sandbox"
        subtitle="M5 · OWASP ZAP · Docker sandbox-net internal:true · 6 phases"
      />

      {/* KPI Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: "10px", marginBottom: "18px" }}>
        <KPICard
          label="Statut session"
          value={status?.active ? "Active" : "Inactive"}
          color={status?.active ? "var(--cs-red)" : "var(--cs-green)"}
        />
        <KPICard label="Fichiers PCAP"    value={findings?.total_pcaps  || 0} color="var(--cs-purple)" />
        <KPICard label="Preuves exploit"  value={findings?.total_proofs || 0} color="var(--cs-amber)"  />
      </div>

      {/* Isolation check */}
      <div className="card" style={{ marginBottom: "14px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
          marginBottom: isoCheck ? "10px" : 0 }}>
          <SectionTitle>Vérification isolation sandbox (Contrainte C-05 / CA09)</SectionTitle>
          <button onClick={checkIso} style={{ fontSize: "11px" }}>
            Vérifier sandbox-net internal:true
          </button>
        </div>
        {isoCheck && (
          <div style={{
            padding: "10px 12px", borderRadius: "6px", fontSize: "12px",
            background: isoCheck.ca09_passed ? "rgba(34,197,94,.1)" : "rgba(239,68,68,.1)",
            border: `0.5px solid ${isoCheck.ca09_passed ? "rgba(34,197,94,.3)" : "rgba(239,68,68,.3)"}`,
            color: isoCheck.ca09_passed ? "var(--cs-green)" : "var(--cs-red)",
          }}>
            {safeStr(isoCheck.message)} — CA09 : {isoCheck.ca09_passed ? "✓ RESPECTÉ" : "✗ VIOLÉ"}
            {isoCheck.error && ` (${safeStr(isoCheck.error)})`}
          </div>
        )}
      </div>

      {/* Formulaire scan */}
      <div className="card" style={{ marginBottom: "14px" }}>
        <SectionTitle>Lancer une session DAST</SectionTitle>

        {/* Sélecteur mode */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: "8px", marginBottom: "12px" }}>
          {(["preset", "custom", "upload"] as DastMode[]).map(m => (
            <button
              key={m}
              onClick={() => setMode(m)}
              style={{
                fontSize: "12px", padding: "10px 12px", borderRadius: "6px",
                border: mode === m ? "0.5px solid rgba(239,68,68,.35)" : "0.5px solid var(--cs-border)",
                background: mode === m ? "rgba(239,68,68,.1)" : "var(--cs-surface2)",
                color: mode === m ? "var(--cs-red)" : "var(--cs-text2)",
              }}
            >
              {m === "preset" ? "Cible prédéfinie" : m === "custom" ? "Cible personnalisée" : "Upload projet ZIP"}
            </button>
          ))}
        </div>

        {/* Mode preset */}
        {mode === "preset" && (
          <>
            <div style={{ display: "flex", gap: "8px", marginBottom: "10px" }}>
              <select value={target}
                onChange={e => setTarget(e.target.value as "webgoat"|"dvwa")}
                style={{ fontSize: "12px" }}>
                <option value="webgoat">WebGoat (OWASP)</option>
                <option value="dvwa">DVWA</option>
              </select>
              <button onClick={startScan} disabled={!canStart} style={{
                background: !canStart ? "var(--cs-surface2)" : "var(--cs-red)",
                color: !canStart ? "var(--cs-text2)" : "#fff",
                border: "none", padding: "7px 16px", borderRadius: "6px", fontSize: "12px",
              }}>
                {running ? "Session en cours... (6 phases)" : "Lancer session DAST"}
              </button>
            </div>
            <div style={{ fontSize: "10px", color: "var(--cs-text3)" }}>Cibles prédéfinies : WebGoat et DVWA</div>
          </>
        )}

        {/* Mode custom */}
        {mode === "custom" && (
          <>
            <div style={{ display: "flex", gap: "8px", marginBottom: "10px" }}>
              <input value={customTargetUrl}
                onChange={e => setCustomTargetUrl(e.target.value)}
                placeholder="http://cybersentinel_monapp:8080"
                style={{
                  flex: 1, fontSize: "12px", padding: "7px 10px", borderRadius: "6px",
                  border: "0.5px solid var(--cs-border)", background: "var(--cs-surface2)", color: "var(--cs-text)",
                }} />
              <button onClick={startScan} disabled={!canStart} style={{
                background: !canStart ? "var(--cs-surface2)" : "var(--cs-red)",
                color: !canStart ? "var(--cs-text2)" : "#fff",
                border: "none", padding: "7px 16px", borderRadius: "6px", fontSize: "12px",
              }}>
                {running ? "Session en cours... (6 phases)" : "Lancer session DAST"}
              </button>
            </div>
            <div style={{ fontSize: "10px", color: "var(--cs-text3)" }}>
              URL d'une application déjà déployée dans votre environnement contrôlé.
            </div>
          </>
        )}

        {/* Mode upload */}
        {mode === "upload" && (
          <>
            <input ref={fileInputRef} type="file" accept=".zip"
              style={{ display: "none" }}
              onChange={e => { const f = e.target.files?.[0]; if (f) setUploadFile(f); }} />

            <div
              onClick={() => fileInputRef.current?.click()}
              onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={e => {
                e.preventDefault(); setIsDragging(false);
                const f = e.dataTransfer.files?.[0]; if (f) setUploadFile(f);
              }}
              style={{
                border: isDragging ? "2px dashed rgba(239,68,68,.65)"
                  : uploadFile ? "2px dashed rgba(34,197,94,.5)"
                  : "2px dashed var(--cs-border)",
                background: isDragging ? "rgba(239,68,68,.06)"
                  : uploadFile ? "rgba(34,197,94,.05)"
                  : "var(--cs-surface2)",
                borderRadius: "10px", padding: "28px",
                textAlign: "center", cursor: "pointer", marginBottom: "10px",
              }}
            >
              {uploadFile ? (
                <>
                  <div style={{ color: "var(--cs-green)", fontWeight: 500, marginBottom: "6px" }}>ZIP sélectionné</div>
                  <div style={{ fontSize: "12px", color: "var(--cs-text)" }}>{uploadFile.name}</div>
                  <div style={{ fontSize: "10px", color: "var(--cs-text3)", marginTop: "4px" }}>
                    {(uploadFile.size / 1024).toFixed(0)} KB
                  </div>
                  <button onClick={e => {
                    e.stopPropagation(); setUploadFile(null);
                    if (fileInputRef.current) fileInputRef.current.value = "";
                  }} style={{
                    marginTop: "10px", fontSize: "11px",
                    background: "rgba(239,68,68,.1)", color: "var(--cs-red)",
                    border: "0.5px solid rgba(239,68,68,.25)", borderRadius: "6px", padding: "5px 10px",
                  }}>Retirer le fichier</button>
                </>
              ) : (
                <>
                  <div style={{ fontSize: "13px", color: "var(--cs-text)", marginBottom: "6px" }}>
                    Glissez votre projet ZIP ici
                  </div>
                  <div style={{ fontSize: "10px", color: "var(--cs-text3)" }}>Cliquez pour parcourir · ZIP uniquement</div>
                </>
              )}
            </div>

            <div style={{ fontSize: "10px", color: "var(--cs-text3)", marginBottom: "10px" }}>
              Support V1 : Spring Boot · Node/Express · Python Flask/FastAPI · PHP Apache
            </div>

            <button onClick={startScan} disabled={!canStart} style={{
              background: !canStart ? "var(--cs-surface2)" : "var(--cs-red)",
              color: !canStart ? "var(--cs-text2)" : "#fff",
              border: "none", padding: "7px 16px", borderRadius: "6px", fontSize: "12px",
            }}>
              {running ? "Build + scan en cours..." : "Uploader et lancer le scan"}
            </button>
          </>
        )}

        {/* Avertissement */}
        <div style={{
          marginTop: "12px", padding: "10px 12px", borderRadius: "6px", fontSize: "12px",
          background: "rgba(245,158,11,.08)", border: "0.5px solid rgba(245,158,11,.2)",
          color: "var(--cs-amber)",
        }}>
          {mode === "upload"
            ? "Le projet ZIP sera buildé, déployé dans sandbox-net, scanné par ZAP puis détruit."
            : "Sandbox isolée activée — ciblez uniquement une application que vous contrôlez."}
        </div>

        {/* Résultats des 6 phases */}
        {result && (
          <div style={{ marginTop: "14px" }}>
            <div style={{ fontSize: "11px", color: "var(--cs-text2)", marginBottom: "8px", fontFamily: "monospace" }}>
              Résultats des 6 phases :
            </div>

            {PHASE_KEYS.map((key, i) => {
              const phase    = result.phases?.[key];
              const success  = phase?.success === true;
              // ── FIX #185 : toujours convertir en string ──
              const phaseErr = phase?.error
                ? safeStr(phase.error).slice(0, 120)
                : "Erreur";
              const urlCount  = typeof phase?.urls_found  === "number" ? phase.urls_found  : null;
              const vulnCount = typeof phase?.vuln_count  === "number" ? phase.vuln_count  : null;
              const pcapName  = phase?.pcap_path ? safePcapName(phase.pcap_path) : null;

              return (
                <div key={i} style={{
                  display: "flex", alignItems: "center", gap: "10px",
                  padding: "7px 0", borderBottom: "0.5px solid var(--cs-border)", fontSize: "12px",
                }}>
                  <span style={{ minWidth: "160px", color: "var(--cs-text2)" }}>{PHASE_LABELS[i]}</span>

                  <span style={{
                    fontSize: "10px", padding: "2px 8px", borderRadius: "20px",
                    background: !phase ? "var(--cs-surface2)"
                      : success ? "rgba(34,197,94,.1)" : "rgba(239,68,68,.1)",
                    color: !phase ? "var(--cs-text3)"
                      : success ? "var(--cs-green)" : "var(--cs-red)",
                    border: `0.5px solid ${!phase ? "var(--cs-border)"
                      : success ? "rgba(34,197,94,.3)" : "rgba(239,68,68,.3)"}`,
                  }}>
                    {!phase ? "—" : success ? "✓ OK" : `✗ ${phaseErr}`}
                  </span>

                  {urlCount  !== null && (
                    <span style={{ fontSize: "10px", color: "var(--cs-text3)" }}>{urlCount} URLs</span>
                  )}
                  {vulnCount !== null && (
                    <span style={{ fontSize: "10px", color: "var(--cs-amber)" }}>{vulnCount} vulnérabilités</span>
                  )}
                  {pcapName && (
                    <span className="font-mono" style={{ fontSize: "10px", color: "var(--cs-purple)" }}>
                      {pcapName}
                    </span>
                  )}
                </div>
              );
            })}

            {/* Infos projet uploadé */}
            {uploadedProject && (
              <div style={{
                marginTop: "10px", padding: "10px 12px",
                background: "rgba(59,130,246,.08)", borderRadius: "6px",
                fontSize: "12px", color: "var(--cs-blue)",
                border: "0.5px solid rgba(59,130,246,.2)",
              }}>
                Projet : {safeStr(uploadedProject.filename)}
                {uploadedProject.container_name && ` · Conteneur : ${safeStr(uploadedProject.container_name)}`}
                {uploadedProject.target_url     && ` · URL : ${safeStr(uploadedProject.target_url)}`}
              </div>
            )}

            {/* Résumé succès */}
            {result.total_vulns !== undefined && !result.error && (
              <div style={{
                marginTop: "10px", padding: "10px 12px",
                background: "rgba(34,197,94,.08)", borderRadius: "6px",
                fontSize: "12px", color: "var(--cs-green)",
                border: "0.5px solid rgba(34,197,94,.2)",
              }}>
                Session terminée — {Number(result.total_vulns)} vulnérabilités trouvées
                {result.pcap_path && ` · PCAP : ${safePcapName(result.pcap_path)}`}
              </div>
            )}

            {/* Erreur — FIX #185 : safeStr() obligatoire */}
            {result.error && (
              <div style={{
                marginTop: "10px", padding: "10px 12px",
                background: "rgba(239,68,68,.08)", borderRadius: "6px",
                fontSize: "12px", color: "var(--cs-red)",
                border: "0.5px solid rgba(239,68,68,.2)",
              }}>
                Erreur : {safeStr(result.error)}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Preuves collectées */}
      {findings?.findings?.length > 0 && (
        <div className="card" style={{ padding: 0 }}>
          <div style={{
            padding: "12px 16px", borderBottom: "0.5px solid var(--cs-border)",
            fontSize: "11px", fontFamily: "monospace",
            textTransform: "uppercase", letterSpacing: ".5px", color: "var(--cs-text2)",
          }}>
            Preuves d'exploit collectées ({findings.findings.length})
          </div>

          {findings.findings.map((f: any, i: number) => (
            <div key={i} style={{
              padding: "10px 16px", borderBottom: "0.5px solid var(--cs-border)", fontSize: "12px",
            }}>
              <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "4px" }}>
                <span style={{
                  fontSize: "10px", padding: "2px 8px", borderRadius: "20px",
                  background: f.risk === "High" ? "rgba(239,68,68,.1)" : "rgba(245,158,11,.1)",
                  color: f.risk === "High" ? "var(--cs-red)" : "var(--cs-amber)",
                  border: `0.5px solid ${f.risk === "High" ? "rgba(239,68,68,.3)" : "rgba(245,158,11,.3)"}`,
                }}>
                  {safeStr(f.risk)}
                </span>
                <span style={{ fontWeight: 500 }}>
                  {safeStr(f.alert_name || f.title)}
                </span>
              </div>
              <div style={{ fontSize: "10px", color: "var(--cs-text2)" }}>
                {safeStr(f.url)} · Payload :{" "}
                <code style={{
                  fontFamily: "monospace", color: "var(--cs-amber)",
                  background: "var(--cs-surface2)", padding: "0 4px", borderRadius: "3px",
                }}>
                  {safeStr(f.attack).slice(0, 80)}
                </code>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}