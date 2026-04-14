// ============================================================
// pages/Admin.tsx — Configuration + Simulateur Score R
// ============================================================
import React, { useState, useEffect } from "react";
import { scoringAPI, incidentsAPI, mlAPI } from "../services/api";
import { PageHeader, SectionTitle } from "../components/common";

export default function Admin() {
  const [weights, setWeights]   = useState<any>(null);
  const [sla,     setSLA]       = useState<any>(null);
  const [mlSt,    setMLSt]      = useState<any>(null);
  const [scoreA,  setScoreA]    = useState(7.5);
  const [scoreV,  setScoreV]    = useState(8.0);
  const [dastOk,  setDastOk]    = useState(false);
  const [scoreC,  setScoreC]    = useState(5.0);
  const [scoreR,  setScoreR]    = useState<any>(null);
  const [h4Data,  setH4Data]    = useState({ computed:"9.1,6.8,5.1,2.8", expert:"9.5,7.0,5.0,3.0" });
  const [h4Res,   setH4Res]     = useState<any>(null);

  useEffect(() => {
    scoringAPI.getWeights().then(setWeights).catch(console.error);
    scoringAPI.getSLA().then(setSLA).catch(console.error);
    mlAPI.getStatus().then(setMLSt).catch(console.error);
  }, []);

  const computeR = async () => {
    const r = await incidentsAPI.computeR({ anomaly_score:scoreA, cvss_score:scoreV,
      dast_confirmed:dastOk, asset_criticality:scoreC });
    setScoreR(r);
  };

  const validateH4 = async () => {
    try {
      const computed = h4Data.computed.split(",").map(Number);
      const expert   = h4Data.expert.split(",").map(Number);
      const r = await incidentsAPI.validateH4(computed, expert);
      setH4Res(r);
    } catch(e:any) { setH4Res({ error: e.message }); }
  };

  const R_COLOR = (r:number) => r>=8?"var(--cs-red)":r>=6?"var(--cs-amber)":r>=4?"var(--cs-blue)":"var(--cs-green)";
  const SEV_LBL = (r:number) => r>=8?"CRITIQUE":r>=6?"ÉLEVÉ":r>=4?"MOYEN":"FAIBLE";

  return (
    <div>
      <PageHeader title="Admin" subtitle="Configuration plateforme · Simulateur Score R · Validation H4" />

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"14px" }}>

        {/* Simulateur Score R */}
        <div className="card">
          <SectionTitle>Simulateur Score R</SectionTitle>
          <div style={{ fontSize:"10px", color:"var(--cs-text3)", marginBottom:"12px", fontFamily:"monospace" }}>
            R = 0.35×A + 0.30×V + 0.25×E + 0.10×C
          </div>
          {[
            { label:`A — Anomalie IDS (0-10)`, val:scoreA, set:setScoreA },
            { label:`V — CVSS Score (0-10)`,   val:scoreV, set:setScoreV },
            { label:`C — Criticité Asset`,     val:scoreC, set:setScoreC },
          ].map((s,i) => (
            <div key={i} style={{ marginBottom:"10px" }}>
              <div style={{ display:"flex", justifyContent:"space-between", fontSize:"11px",
                color:"var(--cs-text2)", marginBottom:"4px" }}>
                <span>{s.label}</span>
                <span className="font-mono" style={{ color:"var(--cs-text)" }}>{s.val.toFixed(1)}</span>
              </div>
              <input type="range" min={0} max={10} step={0.1} value={s.val}
                onChange={e => s.set(parseFloat(e.target.value))}
                style={{ width:"100%" }} />
            </div>
          ))}
          <div style={{ marginBottom:"12px", display:"flex", alignItems:"center", gap:"8px" }}>
            <input type="checkbox" checked={dastOk} onChange={e => setDastOk(e.target.checked)}
              id="dast-cb" />
            <label htmlFor="dast-cb" style={{ fontSize:"11px", cursor:"pointer" }}>
              E — Exploit DAST confirmé (0 ou 10)
            </label>
          </div>
          <button onClick={computeR}
            style={{ background:"var(--cs-purple)", color:"#fff", border:"none",
              padding:"7px 16px", borderRadius:"6px", fontSize:"12px", marginBottom:"10px" }}>
            Calculer Score R
          </button>
          {scoreR && (
            <div style={{ padding:"12px", borderRadius:"6px", background:"var(--cs-surface2)",
              border:`0.5px solid ${R_COLOR(scoreR.score_r)}40` }}>
              <div style={{ fontSize:"28px", fontWeight:500, fontFamily:"monospace",
                color: R_COLOR(scoreR.score_r || scoreR.score_r) }}>
                {scoreR.score_r?.toFixed(2)}
              </div>
              <div style={{ fontSize:"12px", fontWeight:500, color: R_COLOR(scoreR.score_r),
                marginBottom:"6px" }}>
                {(scoreR.severity?.value || SEV_LBL(scoreR.score_r))}
              </div>
              <div className="font-mono" style={{ fontSize:"10px", color:"var(--cs-text3)" }}>
                {scoreR.formula}
              </div>
            </div>
          )}
        </div>

        {/* Infos backend */}
        <div style={{ display:"flex", flexDirection:"column", gap:"12px" }}>
          {/* Poids Score R */}
          <div className="card">
            <SectionTitle>Pondérations Score R (backend)</SectionTitle>
            {weights ? (
              <div>
                <div className="font-mono" style={{ fontSize:"10px", color:"var(--cs-text3)", marginBottom:"8px" }}>
                  {weights.formula}
                </div>
                {[["w_a — Anomalie IDS",weights.w_a],["w_v — CVSS",weights.w_v],
                  ["w_e — Exploit DAST",weights.w_e],["w_c — Criticité",weights.w_c]].map(([l,v],i) => (
                  <div key={i} style={{ display:"flex", justifyContent:"space-between",
                    padding:"5px 0", borderBottom:"0.5px solid var(--cs-border)", fontSize:"11px" }}>
                    <span style={{ color:"var(--cs-text2)" }}>{l as string}</span>
                    <span className="font-mono">{v as number}</span>
                  </div>
                ))}
              </div>
            ) : <div style={{ fontSize:"11px", color:"var(--cs-text3)" }}>Chargement...</div>}
          </div>

          {/* SLA Config */}
          <div className="card">
            <SectionTitle>Configuration SLA par sévérité</SectionTitle>
            {sla ? Object.entries(sla).map(([sev, val]) => (
              <div key={sev} style={{ display:"flex", justifyContent:"space-between",
                padding:"6px 0", borderBottom:"0.5px solid var(--cs-border)", fontSize:"11px" }}>
                <span style={{ color: sev==="CRITIQUE"?"var(--cs-red)":sev==="ELEVE"?"var(--cs-amber)":
                  sev==="MOYEN"?"var(--cs-blue)":"var(--cs-green)", fontWeight:500 }}>{sev}</span>
                <span style={{ color:"var(--cs-text2)" }}>{val as string}</span>
              </div>
            )) : <div style={{ fontSize:"11px", color:"var(--cs-text3)" }}>Chargement...</div>}
          </div>
        </div>

        {/* Validation H4 */}
        <div className="card" style={{ gridColumn:"1 / -1" }}>
          <SectionTitle>Validation H4 — Corrélation Pearson r ≥ 0.80</SectionTitle>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"10px", marginBottom:"10px" }}>
            <div>
              <div style={{ fontSize:"10px", color:"var(--cs-text2)", marginBottom:"4px" }}>
                Scores R calculés (séparés par virgule)
              </div>
              <input value={h4Data.computed}
                onChange={e => setH4Data(p => ({...p, computed:e.target.value}))}
                style={{ width:"100%", fontSize:"11px", fontFamily:"monospace" }} />
            </div>
            <div>
              <div style={{ fontSize:"10px", color:"var(--cs-text2)", marginBottom:"4px" }}>
                Scores expert / évaluation réelle (séparés par virgule)
              </div>
              <input value={h4Data.expert}
                onChange={e => setH4Data(p => ({...p, expert:e.target.value}))}
                style={{ width:"100%", fontSize:"11px", fontFamily:"monospace" }} />
            </div>
          </div>
          <button onClick={validateH4}
            style={{ background:"var(--cs-teal)", color:"#fff", border:"none",
              padding:"7px 16px", borderRadius:"6px", fontSize:"12px" }}>
            Calculer Pearson r
          </button>
          {h4Res && !h4Res.error && (
            <div style={{ marginTop:"10px", padding:"12px", borderRadius:"6px",
              background: h4Res.h4_validated ? "rgba(34,197,94,.1)" : "rgba(245,158,11,.1)",
              border: `0.5px solid ${h4Res.h4_validated ? "rgba(34,197,94,.3)" : "rgba(245,158,11,.3)"}` }}>
              <span style={{ fontFamily:"monospace", fontSize:"16px", fontWeight:500,
                color: h4Res.h4_validated ? "var(--cs-green)" : "var(--cs-amber)" }}>
                r = {h4Res.pearson_r}
              </span>
              <span style={{ marginLeft:"10px", fontSize:"12px",
                color: h4Res.h4_validated ? "var(--cs-green)" : "var(--cs-amber)" }}>
                {h4Res.h4_validated ? "H4 VALIDÉE ✓" : "H4 non validée (< 0.80)"}
              </span>
              <div style={{ fontSize:"10px", color:"var(--cs-text2)", marginTop:"4px" }}>
                {h4Res.n_incidents} incidents · Moyenne calculée: {h4Res.mean_computed} · Moyenne expert: {h4Res.mean_expert}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}